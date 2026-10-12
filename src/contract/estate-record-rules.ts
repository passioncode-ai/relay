import { createHash } from "node:crypto";
import { rfc8785 } from "./canonical.js";
import { isSmallOrderKey } from "./ed25519.js";
import { type Finding, type JsonObject, isObject } from "./findings.js";
import { isValidP256Key } from "./p256.js";
import { type PackageTrust, packageDigest } from "./package-rules.js";
import { secretValue } from "./secret-shape.js";
import { type AssertionProblem, type PasskeyCredential, credentialKey, verifyAssertion } from "./webauthn.js";

// #region estate-record-rules — docs: docs/specification/estate-record.md#semantic-rules
/**
 * `estate-record/1` (DEC-0055): one revision of one person's estate — the passkeys that sign it, the machines with
 * their device keys and hub-key certificates, the packages placed per machine, secret placements by reference, share
 * grants and revocations. A revision names its parent's digest and is signed by a passkey assertion over a challenge
 * derived from its own digest.
 */
const list = (value: unknown): JsonObject[] => (Array.isArray(value) ? value.filter(isObject) : []);
const isString = (value: unknown): value is string => typeof value === "string";

export const ESTATE_RECORD_SCHEMA = "estate-record/1";
/** The challenge type an estate revision's passkey assertion covers (v4 §7, signing challenge types). */
export const ESTATE_CHALLENGE_TYPE = "estate-revision/1";
/** v4 §7, Freshness: the estate record is valid for 30 days. */
export const MAX_VALIDITY_SECONDS = 30 * 24 * 60 * 60;

const sha256 = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest();

/**
 * The record's digest (DEC-0055): `sha256:` and the hex SHA-256 of the UTF-8 RFC 8785 form (DEC-0043) of the record
 * without `digest` and `signature`. Throws a `TypeError` for a value RFC 8785 has no form for.
 */
export function estateRecordDigest(record: JsonObject): string {
  const { digest: _digest, signature: _signature, ...covered } = record;
  return `sha256:${sha256(Buffer.from(rfc8785(covered), "utf8")).toString("hex")}`;
}

/** The bytes the challenge hashes: the UTF-8 RFC 8785 form of `{type: "estate-revision/1", digest}`. */
export function estateChallengeInput(digest: string): Buffer {
  return Buffer.from(rfc8785({ type: ESTATE_CHALLENGE_TYPE, digest }), "utf8");
}

/** The WebAuthn challenge a signer passes to `navigator.credentials.get()`: SHA-256 of `estateChallengeInput`. */
export function estateChallenge(digest: string): Buffer {
  return sha256(estateChallengeInput(digest));
}

export type EstateRecordProblem =
  | "malformed"
  | "digest-mismatch"
  | "broken-chain"
  | "no-trusted-authority"
  | "unknown-authority"
  | "duplicate-authority"
  | AssertionProblem
  | "too-long-lived"
  | "not-yet-valid"
  | "expired"
  | "no-clock"
  | "revoked-authority"
  | "rule-violation";

export type EstateRecordVerdict =
  | { ok: true; digest: string; revision: number; signedBy: string; signCount: number }
  | { ok: false; problem: EstateRecordProblem; codes?: string[] };

export interface EstateRecordTrust {
  /** The record's verified parent: its authorities are the trusted ones, and the chain is checked against it. */
  parent?: unknown;
  /** Without a parent, the passkeys the machine pinned (revision 1: at enrollment, v4 Path 2 step 1). */
  authorities?: readonly unknown[];
  /** The verifier's clock. */
  at: Date;
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;
/**
 * An RFC 3339 date-time as milliseconds, or NaN: `T`, an offset and a day that exists in its month are required. This is
 * stricter than the schema's `date-time`, which also admits a space separator and a leap second `:60`; both are refused
 * here (ER-10). `Date.parse` alone reads 2026-02-30 as 2 March and a missing offset as local time.
 */
const time = (value: unknown): number => {
  const match = isString(value) ? RFC3339.exec(value) : null;
  if (!match) return Number.NaN;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  if (date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day || hour > 23 || minute > 59 || second > 59) return Number.NaN;
  return Date.parse(value as string);
};
/** A revocation's identity across revisions: its kind and its reference. */
const revocationKey = (entry: JsonObject) => `${String(entry.kind)} ${String(entry.ref)}`;

/**
 * The reference verifier (DEC-0055), in the order of estate-record.md's ER table: shape, digest, the chain to the
 * parent, the signing passkey among the trusted ones, the assertion (WebAuthn Level 3 §7.2, `verifyAssertion`), then
 * the validity window. The caller verified `parent` before; this function does not verify it again.
 */
export function verifyEstateRecord(record: unknown, trust: EstateRecordTrust): EstateRecordVerdict {
  // An unreadable clock would make every window comparison false and accept any record; it is refused first.
  const at = isObject(trust) && trust.at instanceof Date ? trust.at.getTime() : Number.NaN;
  if (!Number.isFinite(at)) return { ok: false, problem: "no-clock" };
  if (!isObject(record) || !isString(record.digest) || !Number.isSafeInteger(record.revision) || !isObject(record.signature)) return { ok: false, problem: "malformed" };
  const signature = record.signature;
  if (signature.format !== "webauthn-assertion" || !isString(signature.credentialId)) return { ok: false, problem: "malformed" };
  let digest: string;
  try {
    digest = estateRecordDigest(record);
  } catch {
    return { ok: false, problem: "malformed" };
  }
  if (digest !== record.digest) return { ok: false, problem: "digest-mismatch" };

  let trusted: readonly unknown[];
  let revoked = new Set<unknown>();
  if (trust.parent !== undefined) {
    const parent = trust.parent;
    if (!isObject(parent)) return { ok: false, problem: "broken-chain" };
    let parentDigest: string;
    try {
      parentDigest = estateRecordDigest(parent);
    } catch {
      return { ok: false, problem: "broken-chain" };
    }
    if (parent.estate !== record.estate || record.revision !== Number(parent.revision) + 1 || record.parent !== parentDigest) return { ok: false, problem: "broken-chain" };
    // FAC-SEM-072 holds here too, so a machine that only verifies still refuses a revision issued before its parent or
    // one that drops a revocation: a passkey cannot quietly un-revoke a stolen machine.
    if (time(record.issuedAt) < time(parent.issuedAt)) return { ok: false, problem: "broken-chain" };
    const kept = new Set(list(record.revocations).map(revocationKey));
    if (list(parent.revocations).some((entry) => !kept.has(revocationKey(entry)))) return { ok: false, problem: "broken-chain" };
    // A passkey the parent revokes signs nothing after it; a revision may still revoke its own signer (rotation).
    revoked = new Set(list(parent.revocations).filter((entry) => entry.kind === "authority").map((entry) => entry.ref));
    trusted = list(parent.authorities);
  } else {
    // Without a parent only revision 1 starts a chain; a later revision is checked against the one before it.
    if (record.revision !== 1 || record.parent !== undefined) return { ok: false, problem: "broken-chain" };
    trusted = Array.isArray(trust.authorities) ? trust.authorities : [];
  }
  if (trusted.length === 0) return { ok: false, problem: "no-trusted-authority" };
  const matches = trusted.filter((entry) => isObject(entry) && entry.credentialId === signature.credentialId) as JsonObject[];
  if (matches.length > 1) return { ok: false, problem: "duplicate-authority" };
  const authority = matches[0];
  if (!authority) return { ok: false, problem: "unknown-authority" };
  if (revoked.has(authority.credentialId)) return { ok: false, problem: "revoked-authority" };
  const credential: PasskeyCredential = {
    credentialId: String(authority.credentialId),
    alg: String(authority.alg),
    publicKey: isObject(authority.publicKey) ? authority.publicKey : {},
    rpId: String(authority.rpId),
    origins: Array.isArray(authority.origins) ? authority.origins.filter(isString) : []
  };
  const assertion = verifyAssertion(signature, credential, estateChallenge(digest));
  if (!assertion.ok) return { ok: false, problem: assertion.problem };

  const issuedAt = time(record.issuedAt);
  const validUntil = time(record.validUntil);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(validUntil) || validUntil <= issuedAt || validUntil - issuedAt > MAX_VALIDITY_SECONDS * 1000) return { ok: false, problem: "too-long-lived" };
  if (at < issuedAt) return { ok: false, problem: "not-yet-valid" };
  if (at > validUntil) return { ok: false, problem: "expired" };
  // The record's own rules (FAC-SEM-072…076) hold too, so passing this function is enough to apply a revision.
  const codes = [...new Set(recordFindings(record).map((finding) => finding.code))];
  if (codes.length > 0) return { ok: false, problem: "rule-violation", codes };
  return { ok: true, digest, revision: record.revision as number, signedBy: credential.credentialId, signCount: assertion.signCount };
}

/**
 * What `verifyPackage` (DEC-0051) trusts for a package placed on a machine: the publisher key the placement names, from
 * the record's `publisherKeys`. `undefined` when the record places no such agent on that machine.
 */
export function placementTrust(record: JsonObject, machineId: string, agentRef: string): PackageTrust | undefined {
  const machine = list(record.machines).find((entry) => entry.id === machineId);
  const placement = list(machine?.packages).find((entry) => entry.agentRef === agentRef);
  if (!placement) return undefined;
  return { publisher: list(record.publisherKeys).filter((key) => key.kid === placement.publisherKid) };
}

type Flag = (instancePath: string, message: string) => void;
const flagger = (findings: Finding[], code: string): Flag => (instancePath, message) => findings.push({ code, instancePath, message });

/** FAC-SEM-072 on one revision: its digest is its own, and its validity window is positive and at most 30 days. */
function revisionWhole(value: JsonObject, flag: Flag): void {
  try {
    const digest = estateRecordDigest(value);
    if (digest !== value.digest) flag("/digest", `the digest is ${digest}: the record changed after it was drafted, or was hashed over another form than RFC 8785`);
  } catch {
    flag("/digest", "the record has no RFC 8785 form, so it has no digest");
  }
  const issuedAt = time(value.issuedAt);
  const validUntil = time(value.validUntil);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(validUntil)) {
    flag(Number.isFinite(issuedAt) ? "/validUntil" : "/issuedAt", "issuedAt and validUntil are RFC 3339 date-times with an offset, on days that exist");
  } else if (validUntil <= issuedAt || validUntil - issuedAt > MAX_VALIDITY_SECONDS * 1000) {
    flag("/validUntil", "an estate record is valid after it is issued and for at most 30 days");
  }
}

/** FAC-SEM-072 across two revisions: `{parent, next}`. */
function revisionChain(value: JsonObject): Finding[] {
  const findings: Finding[] = [];
  const flag = flagger(findings, "FAC-SEM-072");
  const parent = isObject(value.parent) ? value.parent : {};
  const next = isObject(value.next) ? value.next : {};
  if (next.estate !== parent.estate) flag("/next/estate", "a revision continues its parent's estate");
  if (next.revision !== Number(parent.revision) + 1) flag("/next/revision", `the revision after ${String(parent.revision)} is ${Number(parent.revision) + 1}: a revision never skips or repeats one`);
  let parentDigest: string | undefined;
  try {
    parentDigest = estateRecordDigest(parent);
  } catch {
    parentDigest = undefined;
  }
  if (next.parent !== parentDigest) flag("/next/parent", "parent names the digest of the revision before it");
  if (time(next.issuedAt) < time(parent.issuedAt)) flag("/next/issuedAt", "a revision is never issued before its parent");
  const kept = new Set(list(next.revocations).map(revocationKey));
  list(parent.revocations).forEach((entry, index) => {
    if (!kept.has(revocationKey(entry))) flag(`/parent/revocations/${index}`, `the ${String(entry.kind)} revocation of ${String(entry.ref)} is dropped: a revision keeps every revocation before it`);
  });
  return findings;
}

/** Whether a raw device key is valid for its algorithm: Ed25519 of full order, or a P-256 point by SEC 1 §3.2.2. */
const validDeviceKey = (key: JsonObject) => {
  const raw = Buffer.from(String(key.publicKey ?? ""), "base64");
  return key.alg === "ed25519" ? raw.length === 32 && !isSmallOrderKey(raw) : isValidP256Key(raw);
};

/**
 * FAC-SEM-073: every key is usable — a machine has exactly one `<id>#sig` key and at most one `#kem` (DEC-0053), each
 * named by the machine and its role, valid for its algorithm and used in one role only; machine ids and hub kids are
 * unique, and a hub key is of full order; every passkey's public key is valid and named once.
 */
function keys(value: JsonObject, flag: Flag): void {
  const ids = new Set<unknown>();
  const hubKids = new Set<unknown>();
  const hubKeys = new Set<unknown>();
  list(value.machines).forEach((machine, m) => {
    const at = `/machines/${m}`;
    if (ids.has(machine.id)) flag(`${at}/id`, `machine ${String(machine.id)} is listed twice`);
    ids.add(machine.id);
    const deviceKeys = list(machine.deviceKeys);
    if (deviceKeys.filter((key) => key.use === "sig").length !== 1) flag(`${at}/deviceKeys`, "a machine has exactly one signing device key, <id>#sig");
    if (deviceKeys.filter((key) => key.use === "kem").length > 1) flag(`${at}/deviceKeys`, "a machine has at most one key-agreement device key, <id>#kem");
    const seen = new Set<unknown>();
    deviceKeys.forEach((key, k) => {
      if (key.kid !== `${String(machine.id)}#${String(key.use)}`) flag(`${at}/deviceKeys/${k}/kid`, "a device key is listed as <machine id>#sig or <machine id>#kem, by its role");
      if (!validDeviceKey(key)) flag(`${at}/deviceKeys/${k}/publicKey`, "an Ed25519 key is never of small order (DEC-0045) and a P-256 key is a valid point (SEC 1 §3.2.2)");
      if (seen.has(key.publicKey)) flag(`${at}/deviceKeys/${k}/publicKey`, "one key is never used for the other role");
      seen.add(key.publicKey);
    });
    if (isObject(machine.hubKey)) {
      const hub = machine.hubKey;
      if (hubKids.has(hub.kid)) flag(`${at}/hubKey/kid`, `hub key ${String(hub.kid)} is certified for two machines: one kid per machine`);
      hubKids.add(hub.kid);
      if (hubKeys.has(hub.x)) flag(`${at}/hubKey/x`, "one hub public key is certified for two machines under two kids: one key per machine");
      hubKeys.add(hub.x);
      const raw = Buffer.from(String(hub.x ?? ""), "base64url");
      if (isSmallOrderKey(raw)) flag(`${at}/hubKey/x`, "a hub key of small order verifies forged tokens and is never certified (DEC-0045)");
    }
  });
  const credentials = new Set<unknown>();
  list(value.authorities).forEach((authority, index) => {
    if (credentials.has(authority.credentialId)) flag(`/authorities/${index}/credentialId`, "a passkey is listed once");
    credentials.add(authority.credentialId);
    if ("problem" in credentialKey(authority.publicKey, String(authority.alg))) flag(`/authorities/${index}/publicKey`, "a passkey's public key is a valid P-256 point for ES256 or an Ed25519 key of full order for EdDSA");
  });
}

/**
 * FAC-SEM-074 on one record: a machine places an agent once, under a publisher key the record pins, named once.
 */
function placements(value: JsonObject, flag: Flag): void {
  const kids = new Set<unknown>();
  list(value.publisherKeys).forEach((key, index) => {
    if (kids.has(key.kid)) flag(`/publisherKeys/${index}/kid`, `publisher key ${String(key.kid)} is pinned twice`);
    kids.add(key.kid);
  });
  list(value.machines).forEach((machine, m) => {
    const agents = new Set<unknown>();
    list(machine.packages).forEach((placement, p) => {
      const at = `/machines/${m}/packages/${p}`;
      if (agents.has(placement.agentRef)) flag(`${at}/agentRef`, `${String(placement.agentRef)} is placed twice on one machine`);
      agents.add(placement.agentRef);
      if (!kids.has(placement.publisherKid)) flag(`${at}/publisherKid`, `publisher key ${String(placement.publisherKid)} is not in publisherKeys, so the machine pins no key to verify the package under`);
    });
  });
}

/**
 * FAC-SEM-075 on one record (DEC-0013): a secret placement is a reference — none of its strings is shaped like a
 * credential; it fills a slot of an agent placed on that machine, from a machine of this record, once.
 */
function secretReferences(value: JsonObject, flag: Flag): void {
  const machineIds = new Set(list(value.machines).map((machine) => machine.id));
  list(value.machines).forEach((machine, m) => {
    const placed = new Set(list(machine.packages).map((placement) => placement.agentRef));
    const slots = new Set<string>();
    list(machine.secrets).forEach((secret, s) => {
      const at = `/machines/${m}/secrets/${s}`;
      // The message never repeats the value.
      for (const field of ["slot", "from", "agentRef"] as const) {
        const text = secret[field];
        if (isString(text) && secretValue(text)) flag(`${at}/${field}`, "a secret placement names a slot, never a value: this looks like a credential");
      }
      if (!placed.has(secret.agentRef)) flag(`${at}/agentRef`, "a secret goes only where a placed package declares it (v4 Path 2): this agent is not placed on this machine");
      if (!machineIds.has(secret.from)) flag(`${at}/from`, "the slot is filled from a machine of this estate");
      const key = `${String(secret.agentRef)} ${String(secret.slot)}`;
      if (slots.has(key)) flag(`${at}/slot`, `slot ${String(secret.slot)} is placed twice for one agent on one machine`);
      slots.add(key);
    });
  });
}

/**
 * FAC-SEM-076: share grants and revocations — a share grant's principal is external and its id is named once; a
 * revocation is listed once; and the record lists nothing it revokes (revocation outranks addition, v4 §7).
 */
function grantsAndRevocations(value: JsonObject, flag: Flag): void {
  const grantIds = new Set<unknown>();
  list(value.shareGrants).forEach((grant, index) => {
    if (grant.principalKind !== "external") flag(`/shareGrants/${index}/principalKind`, "a share grant is to a principal outside the estate: principalKind external");
    const id = isObject(grant.meta) ? grant.meta.id : undefined;
    if (grantIds.has(id)) flag(`/shareGrants/${index}/meta/id`, `grant ${String(id)} is listed twice`);
    grantIds.add(id);
  });
  const machines = list(value.machines);
  // A Map, so a kind such as `constructor` or `__proto__` reads nothing from Object.prototype.
  const listed = new Map<string, Set<unknown>>(Object.entries({
    authority: new Set(list(value.authorities).map((entry) => entry.credentialId)),
    machine: new Set(machines.map((machine) => machine.id)),
    "device-key": new Set(machines.flatMap((machine) => list(machine.deviceKeys).map((key) => key.kid))),
    "hub-key": new Set(machines.flatMap((machine) => (isObject(machine.hubKey) ? [machine.hubKey.kid] : []))),
    "publisher-key": new Set(list(value.publisherKeys).map((key) => key.kid)),
    package: new Set(machines.flatMap((machine) => list(machine.packages).map((placement) => placement.digest))),
    grant: grantIds
  }));
  const seen = new Set<string>();
  list(value.revocations).forEach((revocation, index) => {
    const key = `${String(revocation.kind)} ${String(revocation.ref)}`;
    if (seen.has(key)) flag(`/revocations/${index}`, `the ${String(revocation.kind)} ${String(revocation.ref)} is revoked twice`);
    seen.add(key);
    if (listed.get(String(revocation.kind))?.has(revocation.ref)) flag(`/revocations/${index}/ref`, `the record still lists the ${String(revocation.kind)} it revokes: revocation outranks addition`);
  });
}

/** FAC-SEM-072…076 over one record. */
function recordFindings(value: JsonObject): Finding[] {
  const findings: Finding[] = [];
  revisionWhole(value, flagger(findings, "FAC-SEM-072"));
  keys(value, flagger(findings, "FAC-SEM-073"));
  placements(value, flagger(findings, "FAC-SEM-074"));
  secretReferences(value, flagger(findings, "FAC-SEM-075"));
  grantsAndRevocations(value, flagger(findings, "FAC-SEM-076"));
  return findings;
}

/**
 * FAC-SEM-074 and FAC-SEM-075 for one installation: `{record, machine, package}` — the package is the one placed on that
 * machine (its own digest, the placement's `agentRef` and digest), and every slot placed for it is one it declares.
 */
function installation(value: JsonObject): Finding[] {
  const findings: Finding[] = [];
  const record = isObject(value.record) ? value.record : {};
  const pkg = isObject(value.package) ? value.package : {};
  const machineIndex = list(record.machines).findIndex((entry) => entry.id === value.machine);
  const machine = list(record.machines)[machineIndex];
  let digest: string | undefined;
  try {
    digest = packageDigest(pkg);
  } catch {
    digest = undefined;
  }
  const flag074 = flagger(findings, "FAC-SEM-074");
  if (!machine) {
    flag074("/machine", `machine ${String(value.machine)} is not in the estate record`);
    return findings;
  }
  if (digest === undefined || digest !== pkg.digest) flag074("/package/digest", "the package is not the one its digest names: it changed after it was packed");
  const placement = list(machine.packages).find((entry) => entry.agentRef === pkg.agentRef);
  if (!placement) flag074("/package/agentRef", `the record places no ${String(pkg.agentRef)} on machine ${String(value.machine)}`);
  else if (placement.digest !== digest) flag074("/package", `the record places ${String(placement.digest)} of this agent on this machine, not this package`);
  const declared = new Set(list(pkg.secrets).map((slot) => slot.name));
  const flag075 = flagger(findings, "FAC-SEM-075");
  list(machine.secrets).forEach((secret, index) => {
    if (secret.agentRef === pkg.agentRef && !declared.has(secret.slot)) flag075(`/record/machines/${machineIndex}/secrets/${index}/slot`, `the package declares no slot ${String(secret.slot)}: a secret goes only where a placed package declares it`);
  });
  return findings;
}

export function estateRecordRules(kind: string, value: JsonObject): Finding[] | undefined {
  if (kind === "estate-record") return recordFindings(value);
  if (kind === "estate-record-revision") return revisionChain(value);
  if (kind === "estate-placement") return installation(value);
  return undefined;
}
// #endregion estate-record-rules
