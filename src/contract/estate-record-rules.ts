import { createHash } from "node:crypto";
import { rfc8785 } from "./canonical.js";
import { PERSONAL_CONTEXT, parseContext } from "./context-route.js";
import { grantContextFindings } from "./context-rules.js";
import { isSmallOrderKey } from "./ed25519.js";
import { type Finding, type JsonObject, isObject, show, toNumber } from "./findings.js";
import { normalIdentifier } from "./identifiers.js";
import { isValidP256Key } from "./p256.js";
import { type PackageTrust, packageDigest } from "./package-rules.js";
import { CLOCK_SKEW_SECONDS, strictTime } from "./rfc3339.js";
import { secretValue } from "./secret-shape.js";
import { signingCredentialFindings, verifySigningAssertion } from "./signing-challenges.js";
import { type AssertionProblem, type PasskeyCredential, credentialKey } from "./webauthn.js";

// #region estate-record-rules — docs: docs/specification/estate-record.md#semantic-rules
/**
 * `estate-record/1` (DEC-0055): one revision of one person's estate — the passkeys that sign it, the machines with
 * their device keys and hub-key certificates, the packages placed per machine, secret placements by reference, share
 * grants and revocations. A revision names its parent's digest and is signed by a passkey assertion over a challenge
 * derived from its own digest.
 */
const list = (value: unknown): JsonObject[] => (Array.isArray(value) ? value.filter(isObject) : []);
const isString = (value: unknown): value is string => typeof value === "string";
/**
 * The object items of an array with their index in the array as written, so an instancePath names the item it flags
 * even when a non-object precedes it.
 */
const indexed = (value: unknown): Array<[JsonObject, number]> => (Array.isArray(value) ? value.flatMap((item, index): Array<[JsonObject, number]> => (isObject(item) ? [[item, index]] : [])) : []);

export const ESTATE_RECORD_SCHEMA = "estate-record/1";
/** The challenge type an estate revision's passkey assertion covers: the first row of the register (DEC-0063). */
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

/** RFC 3339 read strictly (ER-10): `T`, an offset and a day that exists; NaN otherwise. */
const time = strictTime;
/** A revocation's identity across revisions: its kind and its reference. */
const revocationKey = (entry: JsonObject) => `${show(entry.kind)} ${show(entry.ref)}`;

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
    if (parent.estate !== record.estate || record.revision !== toNumber(parent.revision) + 1 || record.parent !== parentDigest) return { ok: false, problem: "broken-chain" };
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
    credentialId: show(authority.credentialId),
    alg: show(authority.alg),
    publicKey: isObject(authority.publicKey) ? authority.publicKey : {},
    rpId: show(authority.rpId),
    origins: Array.isArray(authority.origins) ? authority.origins.filter(isString) : []
  };
  // DEC-0063: the challenge is the register's `estate-revision/1`, and the passkey is a signing credential — an RP ID
  // that is not sign.<domain> is `wrong-rp`, an origin outside it is not pinned.
  const assertion = verifySigningAssertion(signature, credential, ESTATE_CHALLENGE_TYPE, { digest });
  if (!assertion.ok) return { ok: false, problem: assertion.problem };

  const issuedAt = time(record.issuedAt);
  const validUntil = time(record.validUntil);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(validUntil) || validUntil <= issuedAt || validUntil - issuedAt > MAX_VALIDITY_SECONDS * 1000) return { ok: false, problem: "too-long-lived" };
  // A revision issued a moment ahead of this clock is admitted within the skew every relay time allows (DEC-0066).
  if (at < issuedAt - CLOCK_SKEW_SECONDS * 1000) return { ok: false, problem: "not-yet-valid" };
  if (at > validUntil) return { ok: false, problem: "expired" };
  // The record's own rules (FAC-SEM-072…076) hold too, so passing this function is enough to apply a revision.
  const codes = [...new Set(recordFindings(record).map((finding) => finding.code))];
  if (codes.length > 0) return { ok: false, problem: "rule-violation", codes };
  return { ok: true, digest, revision: record.revision as number, signedBy: credential.credentialId, signCount: assertion.signCount };
}

/**
 * A placement's context (DEC-0082): its `context`, `personal` when absent. A placement and a secret placement are keyed
 * by it, compared as written.
 */
const contextOf = (entry: JsonObject): unknown => (entry.context === undefined ? PERSONAL_CONTEXT : entry.context);
/** A collision-free key over JSON values (a placement's agent and context, a slot's agent, slot and context). */
const keyOf = (...parts: unknown[]): string => JSON.stringify(parts);

/**
 * What `verifyPackage` (DEC-0051) trusts for a package placed on a machine in a context (DEC-0082; `personal` when not
 * given, so a caller written before contexts is unchanged): the publisher key the placement names, from the record's
 * `publisherKeys`. `undefined` when the record places no such agent on that machine in that context.
 */
export function placementTrust(record: JsonObject, machineId: string, agentRef: string, context: string = PERSONAL_CONTEXT): PackageTrust | undefined {
  const machine = list(record.machines).find((entry) => entry.id === machineId);
  const placement = list(machine?.packages).find((entry) => entry.agentRef === agentRef && contextOf(entry) === context);
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
  if (next.revision !== toNumber(parent.revision) + 1) flag("/next/revision", `the revision after ${show(parent.revision)} is ${toNumber(parent.revision) + 1}: a revision never skips or repeats one`);
  let parentDigest: string | undefined;
  try {
    parentDigest = estateRecordDigest(parent);
  } catch {
    parentDigest = undefined;
  }
  if (next.parent !== parentDigest) flag("/next/parent", "parent names the digest of the revision before it");
  if (time(next.issuedAt) < time(parent.issuedAt)) flag("/next/issuedAt", "a revision is never issued before its parent");
  const kept = new Set(list(next.revocations).map(revocationKey));
  indexed(parent.revocations).forEach(([entry, index]) => {
    if (!kept.has(revocationKey(entry))) flag(`/parent/revocations/${index}`, `the ${show(entry.kind)} revocation of ${show(entry.ref)} is dropped: a revision keeps every revocation before it`);
  });
  return findings;
}

/** Whether a raw device key is valid for its algorithm: Ed25519 of full order, or a P-256 point by SEC 1 §3.2.2. */
const validDeviceKey = (key: JsonObject) => {
  const raw = Buffer.from(show(key.publicKey ?? ""), "base64");
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
  indexed(value.machines).forEach(([machine, m]) => {
    const at = `/machines/${m}`;
    if (ids.has(machine.id)) flag(`${at}/id`, `machine ${show(machine.id)} is listed twice`);
    ids.add(machine.id);
    const deviceKeys = list(machine.deviceKeys);
    const deviceKeysAt = indexed(machine.deviceKeys);
    if (deviceKeys.filter((key) => key.use === "sig").length !== 1) flag(`${at}/deviceKeys`, "a machine has exactly one signing device key, <id>#sig");
    if (deviceKeys.filter((key) => key.use === "kem").length > 1) flag(`${at}/deviceKeys`, "a machine has at most one key-agreement device key, <id>#kem");
    const seen = new Set<unknown>();
    deviceKeysAt.forEach(([key, k]) => {
      if (key.kid !== `${show(machine.id)}#${show(key.use)}`) flag(`${at}/deviceKeys/${k}/kid`, "a device key is listed as <machine id>#sig or <machine id>#kem, by its role");
      if (!validDeviceKey(key)) flag(`${at}/deviceKeys/${k}/publicKey`, "an Ed25519 key is never of small order (DEC-0045) and a P-256 key is a valid point (SEC 1 §3.2.2)");
      if (seen.has(key.publicKey)) flag(`${at}/deviceKeys/${k}/publicKey`, "one key is never used for the other role");
      seen.add(key.publicKey);
    });
    if (isObject(machine.hubKey)) {
      const hub = machine.hubKey;
      if (hubKids.has(hub.kid)) flag(`${at}/hubKey/kid`, `hub key ${show(hub.kid)} is certified for two machines: one kid per machine`);
      hubKids.add(hub.kid);
      if (hubKeys.has(hub.x)) flag(`${at}/hubKey/x`, "one hub public key is certified for two machines under two kids: one key per machine");
      hubKeys.add(hub.x);
      const raw = Buffer.from(show(hub.x ?? ""), "base64url");
      if (isSmallOrderKey(raw)) flag(`${at}/hubKey/x`, "a hub key of small order verifies forged tokens and is never certified (DEC-0045)");
    }
  });
  const credentials = new Set<unknown>();
  indexed(value.authorities).forEach(([authority, index]) => {
    if (credentials.has(authority.credentialId)) flag(`/authorities/${index}/credentialId`, "a passkey is listed once");
    credentials.add(authority.credentialId);
    if ("problem" in credentialKey(authority.publicKey, show(authority.alg))) flag(`/authorities/${index}/publicKey`, "a passkey's public key is a valid P-256 point for ES256 or an Ed25519 key of full order for EdDSA");
  });
}

/**
 * FAC-SEM-074 on one record: a machine places an agent once per context (DEC-0082; absent is `personal`), under a
 * publisher key the record pins, named once.
 */
function placements(value: JsonObject, flag: Flag): void {
  const kids = new Set<unknown>();
  indexed(value.publisherKeys).forEach(([key, index]) => {
    if (kids.has(key.kid)) flag(`/publisherKeys/${index}/kid`, `publisher key ${show(key.kid)} is pinned twice`);
    kids.add(key.kid);
  });
  indexed(value.machines).forEach(([machine, m]) => {
    const agents = new Set<string>();
    indexed(machine.packages).forEach(([placement, p]) => {
      const at = `/machines/${m}/packages/${p}`;
      const key = keyOf(placement.agentRef, contextOf(placement));
      if (agents.has(key)) flag(`${at}/agentRef`, `${show(placement.agentRef)} is placed twice on one machine in the context ${show(contextOf(placement))}`);
      agents.add(key);
      if (!kids.has(placement.publisherKid)) flag(`${at}/publisherKid`, `publisher key ${show(placement.publisherKid)} is not in publisherKeys, so the machine pins no key to verify the package under`);
    });
  });
}

/**
 * FAC-SEM-075 on one record (DEC-0013): a secret placement is a reference — none of its strings is shaped like a
 * credential; it fills a slot of an agent placed on that machine in its context (DEC-0082; absent is `personal`), from a
 * machine of this record — for an organization's instance, this machine itself — once per agent, slot and context.
 */
function secretReferences(value: JsonObject, flag: Flag): void {
  const machineIds = new Set(list(value.machines).map((machine) => machine.id));
  indexed(value.machines).forEach(([machine, m]) => {
    const placed = new Set(list(machine.packages).map((placement) => keyOf(placement.agentRef, contextOf(placement))));
    const slots = new Set<string>();
    indexed(machine.secrets).forEach(([secret, s]) => {
      const at = `/machines/${m}/secrets/${s}`;
      // The message never repeats the value, and no message of this rule repeats a secret placement's context.
      for (const field of ["slot", "from", "agentRef", "context"] as const) {
        const text = secret[field];
        if (isString(text) && secretValue(text)) flag(`${at}/${field}`, "a secret placement names a slot, never a value: this looks like a credential");
      }
      if (!placed.has(keyOf(secret.agentRef, contextOf(secret)))) flag(`${at}/agentRef`, "a secret goes only where a placed package declares it (v4 Path 2): this agent is not placed on this machine in the secret's context");
      if (!machineIds.has(secret.from)) flag(`${at}/from`, "the slot is filled from a machine of this estate");
      // An envelope names no context (DEC-0082), so an organization's instance fills its slot on its own machine.
      else if (contextOf(secret) !== PERSONAL_CONTEXT && secret.from !== machine.id) flag(`${at}/from`, "an organization's instance fills its slot from its own machine's vault, never by an envelope from another machine");
      const key = keyOf(secret.agentRef, secret.slot, contextOf(secret));
      if (slots.has(key)) flag(`${at}/slot`, `slot ${show(secret.slot)} is placed twice for one agent in one context on one machine`);
      slots.add(key);
    });
  });
}

/**
 * FAC-SEM-111 (DEC-0082) for one placement: an instance placed in an organization's context runs under a share grant of
 * the same record — the placement names it in `grant`, matched by the normal form of the grant's id (DEC-0076); the
 * grant's `context` is the placement's, compared as written; the record does not revoke it. A personal placement (no
 * `context`, or `personal`) names no grant. Any other value needs a grant, and a grant matches only an
 * `org:<orgId>` context (`parseContext`), so a malformed one such as `Personal` fails closed. Answers the problems as `[instancePath suffix, message]` pairs.
 */
function placementGrantProblems(record: JsonObject, placement: JsonObject): Array<[string, string]> {
  const context = contextOf(placement);
  if (context === PERSONAL_CONTEXT) {
    return placement.grant === undefined ? [] : [["/grant", "a personal instance runs under no share grant: only a placement in an organization's context names one"]];
  }
  if (typeof placement.grant !== "string") return [["/grant", `an instance placed in the context ${show(context)} names the share grant it runs under, by its id`]];
  const id = normalIdentifier(placement.grant);
  const grants = list(record.shareGrants).filter((grant) => isObject(grant.meta) && typeof grant.meta.id === "string" && normalIdentifier(grant.meta.id) === id);
  const problems: Array<[string, string]> = [];
  if (grants.length === 0) problems.push(["/grant", `the record has no share grant ${placement.grant}`]);
  else if (parseContext(context)?.kind !== "org") problems.push(["/context", `${show(context)} is not an organization's context id (org:<orgId>), so no share grant matches it`]);
  else if (!grants.some((grant) => grant.context === context)) problems.push(["/grant", `the share grant ${placement.grant} is not for the context ${show(context)}: its context must be the placement's, as written`]);
  if (list(record.revocations).some((entry) => entry.kind === "grant" && typeof entry.ref === "string" && normalIdentifier(entry.ref) === id)) problems.push(["/grant", `the record revokes the share grant ${placement.grant}, so no instance runs under it`]);
  return problems;
}

/** FAC-SEM-111 on one record: every placement's grant, as `placementGrantProblems` says. */
function placementGrants(value: JsonObject, flag: Flag): void {
  indexed(value.machines).forEach(([machine, m]) => {
    indexed(machine.packages).forEach(([placement, p]) => {
      for (const [suffix, message] of placementGrantProblems(value, placement)) flag(`/machines/${m}/packages/${p}${suffix}`, message);
    });
  });
}

/**
 * FAC-SEM-076: share grants and revocations — a share grant's principal is external and its id is named once; a
 * revocation is listed once; and the record lists nothing it revokes (revocation outranks addition, v4 §7). A grant's id
 * is a URI, so grants and their revocations are keyed by its normal form (DEC-0076): another spelling of one grant is
 * that grant, listed twice or still listed after its revocation.
 */
function grantsAndRevocations(value: JsonObject, flag: Flag): void {
  const grantKey = (id: unknown): unknown => (typeof id === "string" ? normalIdentifier(id) : id);
  const grantIds = new Set<unknown>();
  indexed(value.shareGrants).forEach(([grant, index]) => {
    if (grant.principalKind !== "external") flag(`/shareGrants/${index}/principalKind`, "a share grant is to a principal outside the estate: principalKind external");
    const id = isObject(grant.meta) ? grant.meta.id : undefined;
    if (grantIds.has(grantKey(id))) flag(`/shareGrants/${index}/meta/id`, `grant ${show(id)} is listed twice`);
    grantIds.add(grantKey(id));
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
  indexed(value.revocations).forEach(([revocation, index]) => {
    const ref = revocation.kind === "grant" ? grantKey(revocation.ref) : revocation.ref;
    const key = `${show(revocation.kind)} ${show(ref)}`;
    if (seen.has(key)) flag(`/revocations/${index}`, `the ${show(revocation.kind)} ${show(revocation.ref)} is revoked twice`);
    seen.add(key);
    if (listed.get(show(revocation.kind))?.has(ref)) flag(`/revocations/${index}/ref`, `the record still lists the ${show(revocation.kind)} it revokes: revocation outranks addition`);
  });
}

/**
 * FAC-SEM-072…076 over one record, FAC-SEM-092 (DEC-0063) on each passkey it lists, FAC-SEM-110 on each share grant and
 * FAC-SEM-111 on each placement (DEC-0082).
 */
function recordFindings(value: JsonObject): Finding[] {
  const findings: Finding[] = [];
  revisionWhole(value, flagger(findings, "FAC-SEM-072"));
  keys(value, flagger(findings, "FAC-SEM-073"));
  placements(value, flagger(findings, "FAC-SEM-074"));
  secretReferences(value, flagger(findings, "FAC-SEM-075"));
  grantsAndRevocations(value, flagger(findings, "FAC-SEM-076"));
  indexed(value.shareGrants).forEach(([grant, index]) => findings.push(...grantContextFindings(grant, `/shareGrants/${index}`)));
  placementGrants(value, flagger(findings, "FAC-SEM-111"));
  indexed(value.authorities).forEach(([authority, index]) => findings.push(...signingCredentialFindings(authority, `/authorities/${index}`)));
  return findings;
}

/**
 * FAC-SEM-074, FAC-SEM-075 and FAC-SEM-111 for one installation: `{record, machine, package, context?}` — the package is
 * the one placed on that machine in that context (DEC-0082; `personal` when absent): its own digest, the placement's
 * `agentRef` and digest; every slot placed for that instance is one it declares; and an instance in an organization's
 * context names a share grant of the record for that context that the record does not revoke.
 */
function installation(value: JsonObject): Finding[] {
  const findings: Finding[] = [];
  const record = isObject(value.record) ? value.record : {};
  const pkg = isObject(value.package) ? value.package : {};
  const [machine, machineIndex] = indexed(record.machines).find(([entry]) => entry.id === value.machine) ?? [undefined, -1];
  let digest: string | undefined;
  try {
    digest = packageDigest(pkg);
  } catch {
    digest = undefined;
  }
  const flag074 = flagger(findings, "FAC-SEM-074");
  if (!machine) {
    flag074("/machine", `machine ${show(value.machine)} is not in the estate record`);
    return findings;
  }
  if (digest === undefined || digest !== pkg.digest) flag074("/package/digest", "the package is not the one its digest names: it changed after it was packed");
  const context = contextOf(value);
  const [placement, placementIndex] = indexed(machine.packages).find(([entry]) => entry.agentRef === pkg.agentRef && contextOf(entry) === context) ?? [undefined, -1];
  if (!placement) flag074("/package/agentRef", `the record places no ${show(pkg.agentRef)} on machine ${show(value.machine)} in the context ${show(context)}`);
  else if (placement.digest !== digest) flag074("/package", `the record places ${show(placement.digest)} of this agent on this machine in this context, not this package`);
  const declared = new Set(list(pkg.secrets).map((slot) => slot.name));
  const flag075 = flagger(findings, "FAC-SEM-075");
  indexed(machine.secrets).forEach(([secret, index]) => {
    if (secret.agentRef === pkg.agentRef && contextOf(secret) === context && !declared.has(secret.slot)) flag075(`/record/machines/${machineIndex}/secrets/${index}/slot`, `the package declares no slot ${show(secret.slot)}: a secret goes only where a placed package declares it`);
  });
  if (placement) {
    const flag111 = flagger(findings, "FAC-SEM-111");
    for (const [suffix, message] of placementGrantProblems(record, placement)) flag111(`/record/machines/${machineIndex}/packages/${placementIndex}${suffix}`, message);
  }
  return findings;
}

export function estateRecordRules(kind: string, value: JsonObject): Finding[] | undefined {
  if (kind === "estate-record") return recordFindings(value);
  if (kind === "estate-record-revision") return revisionChain(value);
  if (kind === "estate-placement") return installation(value);
  return undefined;
}
// #endregion estate-record-rules
