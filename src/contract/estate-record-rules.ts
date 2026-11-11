import { createHash } from "node:crypto";
import { rfc8785 } from "./canonical.js";
import { PERSONAL_CONTEXT, parseContext } from "./context-route.js";
import { grantContextFindings } from "./context-rules.js";
import { isSmallOrderKey } from "./ed25519.js";
import { type Finding, type JsonObject, indexed, isObject, show, toNumber } from "./findings.js";
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

/** Standard base64 with its padding, the one form DEC-0053 records a device key's octets in. */
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * A device key's fingerprint (DEC-0084): `sha256:` and the hex SHA-256 of the key's octets, its `publicKey` decoded
 * from base64. `undefined` when `publicKey` is not a non-empty string in canonical padded base64, so two readers never
 * disagree on which key a fingerprint names. A device key's kid is `<machine id>#sig` or `#kem` and outlives the key
 * (DEC-0053), so the fingerprint is what tells two keys of one machine and one role apart.
 */
export function deviceKeyFingerprint(key: unknown): string | undefined {
  const text = isObject(key) ? key.publicKey : undefined;
  if (!isString(text) || text.length === 0 || !BASE64.test(text)) return undefined;
  const raw = Buffer.from(text, "base64");
  if (raw.toString("base64") !== text) return undefined;
  return `sha256:${sha256(raw).toString("hex")}`;
}

/**
 * The one form of a key reference (DEC-0084): a kid of the device-key schema, `@sha256:`, 64 lower-case hex digits. A
 * `device-key` revocation whose `ref` holds `@` and is not this is malformed (`FAC-SEM-076`); a relay reports such a
 * delta entry rather than ignoring it (`relayAdmissionSet`'s `unread`).
 */
export const KEY_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:~-]{0,127}#(sig|kem)@sha256:[a-f0-9]{64}$/;

/**
 * The `device-key` revocation reference of one key (DEC-0084): `<kid>@<fingerprint>`. A `device-key` revocation names
 * either a kid, which revokes every key ever listed under it, or one key in this form, which revokes that key alone and
 * leaves the next key under the same kid usable: the form a key replacement revokes the old key by. `@` never occurs in
 * a kid (`device-enrollment.schema.json#/$defs/deviceKey`), so the two forms never collide. `undefined` when the key has
 * no string kid or no fingerprint.
 */
export function deviceKeyRef(key: unknown): string | undefined {
  const fingerprint = deviceKeyFingerprint(key);
  const kid = isObject(key) ? key.kid : undefined;
  return fingerprint !== undefined && isString(kid) ? `${kid}@${fingerprint}` : undefined;
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
  // With a parent, what the revision drops it revokes (FAC-SEM-114, DEC-0084): a removed machine, a replaced key.
  const dropped = isObject(trust.parent) ? [...droppedFindings(trust.parent, record), ...anchorFindings(trust.parent, record)] : [];
  const codes = [...new Set([...recordFindings(record), ...dropped].map((finding) => finding.code))];
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
  // DEC-0090: a partner's key is trusted only in the contexts its scope names.
  if (!scopeAdmits(record, placement.publisherKid, context)) return { publisher: [] };
  return { publisher: list(record.publisherKeys).filter((key) => key.kid === placement.publisherKid) };
}

/** The `publisherScopes[]` entries naming `kid` (DEC-0090): a partner's publisher key and the contexts it is trusted in. */
const scopesOf = (record: JsonObject, kid: unknown) => list(record.publisherScopes).filter((scope) => scope.kid === kid);
/** Whether a placement in `context` under `kid` may use that key: an unscoped key anywhere, a scoped one only in its contexts. */
function scopeAdmits(record: JsonObject, kid: unknown, context: unknown): boolean {
  const scopes = scopesOf(record, kid);
  return scopes.length === 0 || scopes.some((scope) => Array.isArray(scope.contexts) && scope.contexts.includes(context));
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
export const validDeviceKey = (key: JsonObject): boolean => {
  // Read only after deviceKeyFingerprint accepted the key (FAC-SEM-073, machineOfKeys), so publicKey is canonical base64.
  const raw = Buffer.from(show(key.publicKey), "base64");
  return key.alg === "ed25519" ? raw.length === 32 && !isSmallOrderKey(raw) : isValidP256Key(raw);
};

/**
 * FAC-SEM-073: every key is usable — a machine has exactly one `<id>#sig` key and at most one `#kem` (DEC-0053), each
 * named by the machine and its role, valid for its algorithm and used in one role only; machine ids and hub kids are
 * unique, and a hub key is of full order; every passkey's public key is valid and named once. A context hub key (DEC-0128)
 * is unique among every hub key of the record, of full order, once per context on its machine, in a pinned context, and
 * held only by a machine that holds the personal hub key.
 */
function keys(value: JsonObject, flag: Flag): void {
  const pinned = new Set<unknown>(list(value.organizations).map((pin) => pin.org));
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
      // A key with no canonical fingerprint could be read as two keys by two readers, and no key reference names it (DEC-0084).
      if (deviceKeyFingerprint(key) === undefined) flag(`${at}/deviceKeys/${k}/publicKey`, "a device key's octets are written in canonical padded base64, the one form a key reference can name (DEC-0084)");
      else if (!validDeviceKey(key)) flag(`${at}/deviceKeys/${k}/publicKey`, "an Ed25519 key is never of small order (DEC-0045) and a P-256 key is a valid point (SEC 1 §3.2.2)");
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
    // DEC-0128: a context's hub key is as unique as the personal one, across every hub key of the record, and belongs to a
    // pinned organization, so a token in that context verifies only under its own context's key.
    const contexts = new Set<unknown>();
    // A context's key lives with the personal hub key, so a hub move carries every context's key with it (DL-15).
    if (list(machine.contextHubKeys).length > 0 && !isObject(machine.hubKey)) flag(`${at}/contextHubKeys`, "a context's hub key is held only by the machine that holds the personal hub key (DEC-0128)");
    indexed(machine.contextHubKeys).forEach(([entry, c]) => {
      const keyAt = `${at}/contextHubKeys/${c}`;
      if (contexts.has(entry.context)) flag(`${keyAt}/context`, `context ${show(entry.context)} has two hub keys on one machine`);
      contexts.add(entry.context);
      if (!pinned.has(entry.context)) flag(`${keyAt}/context`, `context ${show(entry.context)} is not an organization the record pins (DEC-0127)`);
      // A key that is not an object is the schema's to refuse; nothing here reads it.
      if (!isObject(entry.key)) return;
      const key = entry.key;
      if (hubKids.has(key.kid)) flag(`${keyAt}/key/kid`, `hub key ${show(key.kid)} is certified twice: one kid per hub key, personal or per context`);
      hubKids.add(key.kid);
      if (hubKeys.has(key.x)) flag(`${keyAt}/key/x`, "one public key is certified as two hub keys: a context key is its own key");
      hubKeys.add(key.x);
      if (isSmallOrderKey(Buffer.from(show(key.x ?? ""), "base64url"))) flag(`${keyAt}/key/x`, "a hub key of small order verifies forged tokens and is never certified (DEC-0045)");
    });
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
 * FAC-SEM-122 on one record (DEC-0090): a partner's publisher key is scoped once, to a key the record pins, and a
 * placement under it is in one of the organization contexts its scope names, never `personal` or another.
 */
function partnerScopes(value: JsonObject, flag: Flag): void {
  const pinned = new Set(list(value.publisherKeys).map((key) => key.kid));
  const scoped = new Set<unknown>();
  indexed(value.publisherScopes).forEach(([scope, index]) => {
    if (scoped.has(scope.kid)) flag(`/publisherScopes/${index}/kid`, `publisher key ${show(scope.kid)} is scoped twice`);
    scoped.add(scope.kid);
    if (!pinned.has(scope.kid)) flag(`/publisherScopes/${index}/kid`, `publisher key ${show(scope.kid)} is not in publisherKeys, so the scope limits no key`);
  });
  indexed(value.machines).forEach(([machine, m]) => {
    indexed(machine.packages).forEach(([placement, p]) => {
      if (!scopeAdmits(value, placement.publisherKid, contextOf(placement))) {
        flag(`/machines/${m}/packages/${p}/publisherKid`, `publisher key ${show(placement.publisherKid)} is a partner's, trusted only in the contexts its scope names, not in ${show(contextOf(placement))}`);
      }
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
      else if (contextOf(secret) !== PERSONAL_CONTEXT && secret.from !== machine.id) flag(`${at}/from`, "an organization's instance fills its slot from its own machine's vault, never by a secret envelope from another machine");
      const key = keyOf(secret.agentRef, secret.slot, contextOf(secret));
      if (slots.has(key)) flag(`${at}/slot`, `slot ${show(secret.slot)} is placed twice for one agent in one context on one machine`);
      slots.add(key);
    });
  });
}

/** DEC-0106: what a machine of the estate may be. Absent is `full`, and a writer omits `full`. */
export const MACHINE_PROFILES = ["full", "member", "view"] as const;
export type MachineProfile = (typeof MACHINE_PROFILES)[number];
const isProfile = (value: unknown): value is MachineProfile => typeof value === "string" && (MACHINE_PROFILES as readonly string[]).includes(value);

/**
 * A machine's profile in a record (DEC-0106): `full` when the machine is listed once with no `profile`, its value when
 * that is one of the three, `undefined` otherwise (not listed, listed twice, an unreadable record or id, an unknown
 * value). It never throws.
 */
export function machineProfile(record: unknown, machineId: unknown): MachineProfile | undefined {
  if (!isObject(record) || !isString(machineId)) return undefined;
  const found = list(record.machines).filter((machine) => machine.id === machineId);
  if (found.length !== 1) return undefined;
  const profile = (found[0] as JsonObject).profile;
  if (profile === undefined) return "full";
  return isProfile(profile) ? profile : undefined;
}

/**
 * FAC-SEM-134 (DEC-0106): a profile, when present, is `full`, `member` or `view`; only a `full` machine carries a
 * `hubKey`; a `view` machine has no placement and no secret placement, and no secret placement names it as `from`.
 */
function machineProfiles(value: JsonObject, flag: Flag): void {
  const views = new Set<unknown>();
  indexed(value.machines).forEach(([machine, m]) => {
    if (machine.profile === undefined) return;
    if (!isProfile(machine.profile)) {
      flag(`/machines/${m}/profile`, `profile ${show(machine.profile)} is none of full, member, view`);
      return;
    }
    if (machine.profile !== "full" && machine.hubKey !== undefined) flag(`/machines/${m}/hubKey`, `a ${machine.profile} machine is never the hub's: only a full machine carries a hub key`);
    if (machine.profile !== "full" && list(machine.contextHubKeys).length > 0) flag(`/machines/${m}/contextHubKeys`, `a ${machine.profile} machine is never the hub's: only a full machine carries a context's hub key (DEC-0128)`);
    if (machine.profile === "view") {
      views.add(machine.id);
      if (list(machine.packages).length > 0) flag(`/machines/${m}/packages`, "a view machine runs no agent: it has no placement");
      if (list(machine.secrets).length > 0) flag(`/machines/${m}/secrets`, "a view machine holds none of the estate's secrets");
    }
  });
  indexed(value.machines).forEach(([machine, m]) => {
    indexed(machine.secrets).forEach(([secret, s]) => {
      if (views.has(secret.from)) flag(`/machines/${m}/secrets/${s}/from`, `machine ${show(secret.from)} is a view machine: it is the source of no secret`);
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
    // A kid, and each listed key's own reference (`deviceKeyRef`, DEC-0084): revoking either while listing it is refused.
    "device-key": new Set(machines.flatMap((machine) => list(machine.deviceKeys).flatMap((key) => [key.kid, deviceKeyRef(key)].filter((ref) => ref !== undefined)))),
    "hub-key": new Set(machines.flatMap((machine) => [
      ...(isObject(machine.hubKey) ? [machine.hubKey.kid] : []),
      ...list(machine.contextHubKeys).map((entry) => (isObject(entry.key) ? entry.key.kid : undefined))
    ])),
    "publisher-key": new Set(list(value.publisherKeys).map((key) => key.kid)),
    package: new Set(machines.flatMap((machine) => list(machine.packages).map((placement) => placement.digest))),
    grant: grantIds
  }));
  const seen = new Set<string>();
  indexed(value.revocations).forEach(([revocation, index]) => {
    const ref = revocation.kind === "grant" ? grantKey(revocation.ref) : revocation.ref;
    const key = `${show(revocation.kind)} ${show(ref)}`;
    if (seen.has(key)) flag(`/revocations/${index}`, `the ${show(revocation.kind)} ${show(revocation.ref)} is revoked twice`);
    // A `device-key` ref is a kid or a key reference; one with `@` that is neither revokes nothing a reader can name.
    if (revocation.kind === "device-key" && typeof revocation.ref === "string" && revocation.ref.includes("@") && !KEY_REFERENCE.test(revocation.ref)) {
      flag(`/revocations/${index}/ref`, "a device-key revocation names a kid or a key reference <kid>@sha256:<64 lower-case hex digits> (DEC-0084)");
    }
    seen.add(key);
    if (listed.get(show(revocation.kind))?.has(ref)) flag(`/revocations/${index}/ref`, `the record still lists the ${show(revocation.kind)} it revokes: revocation outranks addition`);
  });
}

/** A machine's context hub keys that are objects, with their indexes, each with the context it is certified for. */
const contextKeys = (machine: JsonObject): Array<[JsonObject, number, unknown]> =>
  indexed(machine.contextHubKeys).filter(([entry]) => isObject(entry.key)).map(([entry, c]) => [entry.key as JsonObject, c, entry.context]);

/**
 * FAC-SEM-114 across two revisions (DEC-0084): what a revision drops, it revokes in the same revision.
 * - A machine of the parent that `next` does not list is revoked as `machine <id>`, and its hub key, when it had one, as
 *   `hub-key <kid>`: the "remove a machine" ceremony.
 * - A device key of a machine both list, which `next` no longer lists under that machine (by `deviceKeyRef`), is revoked
 *   as `device-key` by its own reference or by its kid: the "replace a machine's key" ceremony. FAC-SEM-076 refuses a kid
 *   revoked while the new key is listed under it, so a kept machine revokes the old key by its reference.
 * - A hub key of a machine both list, which `next` no longer certifies with the same kid and key, is revoked as
 *   `hub-key <old kid>`; FAC-SEM-076 then refuses that kid on any later key, so a re-certified hub key has a new kid.
 * Revocations are matched exactly, as `isRevoked` matches every kind but `grant`.
 */
function droppedFindings(parent: JsonObject, next: JsonObject): Finding[] {
  const findings: Finding[] = [];
  const flag = flagger(findings, "FAC-SEM-114");
  const revoked = (kind: string, ...refs: unknown[]) => list(next.revocations).some((entry) => entry.kind === kind && refs.some((ref) => ref !== undefined && entry.ref === ref));
  const nextMachines = new Map<unknown, JsonObject>();
  for (const machine of list(next.machines)) if (!nextMachines.has(machine.id)) nextMachines.set(machine.id, machine);
  indexed(parent.machines).forEach(([machine, m]) => {
    const at = `/parent/machines/${m}`;
    const hub = isObject(machine.hubKey) ? machine.hubKey : undefined;
    const kept = nextMachines.get(machine.id);
    if (!kept) {
      if (!revoked("machine", machine.id)) flag(`${at}/id`, `machine ${show(machine.id)} is removed without its revocation: a revision that drops a machine lists machine ${show(machine.id)} in revocations`);
      if (hub && !revoked("hub-key", hub.kid)) flag(`${at}/hubKey/kid`, `the hub key ${show(hub.kid)} of a removed machine is revoked in the same revision`);
      contextKeys(machine).forEach(([key, c]) => {
        if (!revoked("hub-key", key.kid)) flag(`${at}/contextHubKeys/${c}/key/kid`, `the context hub key ${show(key.kid)} of a removed machine is revoked in the same revision (DEC-0128)`);
      });
      return;
    }
    const listed = new Set(list(kept.deviceKeys).map(deviceKeyRef).filter((ref) => ref !== undefined));
    indexed(machine.deviceKeys).forEach(([key, k]) => {
      const ref = deviceKeyRef(key);
      if (ref === undefined || listed.has(ref)) return;
      if (!revoked("device-key", ref, key.kid)) flag(`${at}/deviceKeys/${k}`, `the device key ${show(key.kid)} is replaced or dropped without its revocation: the same revision lists device-key ${ref}`);
    });
    const nextHub = isObject(kept.hubKey) ? kept.hubKey : undefined;
    if (hub && !(nextHub && nextHub.kid === hub.kid && nextHub.x === hub.x) && !revoked("hub-key", hub.kid)) {
      flag(`${at}/hubKey/kid`, `the hub key ${show(hub.kid)} is no longer certified as it was: the same revision revokes hub-key ${show(hub.kid)}, and a re-certified hub key takes a new kid`);
    }
    // DEC-0128: a context's hub key dropped (its context unpinned, OM-5, or the key replaced) is revoked the same way.
    // A key is kept only in its own context: one moved to another organization is a key that organization must not inherit.
    const keptContext = new Set(contextKeys(kept).map(([key, , context]) => `${show(context)} ${show(key.kid)} ${show(key.x)}`));
    contextKeys(machine).forEach(([key, c, context]) => {
      if (!keptContext.has(`${show(context)} ${show(key.kid)} ${show(key.x)}`) && !revoked("hub-key", key.kid)) {
        flag(`${at}/contextHubKeys/${c}/key/kid`, `the context hub key ${show(key.kid)} is no longer certified as it was: the same revision revokes hub-key ${show(key.kid)} (DEC-0128)`);
      }
    });
  });
  return findings;
}

/**
 * FAC-SEM-147: the organizations the person admitted (DEC-0127 OM-2), each once by its context, and no root of small
 * order (DEC-0045), since the root's key sets are what every attestation of that organization verifies under; each
 * context issuer once and never containing the estate id (DEC-0128).
 */
function organizationPins(value: JsonObject, flag: (instancePath: string, message: string) => void): void {
  const seen = new Set<string>();
  const issuers = new Set<unknown>();
  for (const [pin, index] of indexed(value.organizations)) {
    const at = `/organizations/${index}`;
    const org = show(pin.org);
    if (seen.has(org)) flag(`${at}/org`, `organization ${org} is pinned twice`);
    seen.add(org);
    // DEC-0128: a context's issuer is its own and names no estate, so two organizations' tokens share nothing.
    if (typeof pin.iss === "string") {
      if (issuers.has(pin.iss)) flag(`${at}/iss`, `context issuer ${show(pin.iss)} is used by two organizations`);
      issuers.add(pin.iss);
    }
    // Only the opaque part is the pin's own: the fixed prefix would match a short estate id by chance.
    const opaquePart = typeof pin.iss === "string" ? pin.iss.replace(/^urn:fabric:context:/, "").toLowerCase() : "";
    // An estate id shorter than eight characters appears inside any random id by chance; the issuer's duty covers it.
    if (typeof value.estate === "string" && value.estate.length >= 8 && opaquePart.includes(value.estate.toLowerCase())) {
      flag(`${at}/iss`, "a context issuer never contains the estate id (DEC-0128)");
    }
    const x = isObject(pin.root) ? pin.root.x : undefined;
    if (typeof x === "string" && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(x) && isSmallOrderKey(Buffer.from(x, "base64url"))) {
      flag(`${at}/root/x`, "a root of small order lets anyone forge the organization's key sets (DEC-0045)");
    }
  }
}

/**
 * FAC-SEM-072…076 over one record, FAC-SEM-092 (DEC-0063) on each passkey it lists, FAC-SEM-110 on each share grant,
 * FAC-SEM-111 on each placement (DEC-0082), FAC-SEM-134 on each machine's profile (DEC-0106) and FAC-SEM-147 on the
 * organizations it pins (DEC-0127).
 */
function recordFindings(value: JsonObject): Finding[] {
  const findings: Finding[] = [];
  revisionWhole(value, flagger(findings, "FAC-SEM-072"));
  keys(value, flagger(findings, "FAC-SEM-073"));
  placements(value, flagger(findings, "FAC-SEM-074"));
  partnerScopes(value, flagger(findings, "FAC-SEM-122"));
  secretReferences(value, flagger(findings, "FAC-SEM-075"));
  grantsAndRevocations(value, flagger(findings, "FAC-SEM-076"));
  indexed(value.shareGrants).forEach(([grant, index]) => findings.push(...grantContextFindings(grant, `/shareGrants/${index}`)));
  placementGrants(value, flagger(findings, "FAC-SEM-111"));
  machineProfiles(value, flagger(findings, "FAC-SEM-134"));
  organizationPins(value, flagger(findings, "FAC-SEM-147"));
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
  if (placement && !scopeAdmits(record, placement.publisherKid, context)) {
    flagger(findings, "FAC-SEM-122")(`/record/machines/${machineIndex}/packages/${placementIndex}/publisherKid`, `publisher key ${show(placement.publisherKid)} is a partner's, not trusted in ${show(context)}`);
  }
  if (placement) {
    const flag111 = flagger(findings, "FAC-SEM-111");
    for (const [suffix, message] of placementGrantProblems(record, placement)) flag111(`/record/machines/${machineIndex}/packages/${placementIndex}${suffix}`, message);
  }
  return findings;
}

/** The anchor a record vouches for, or undefined when it names none or its shape is not the schema's. */
export function deltaAnchorOf(record: unknown): { sequence: number; sha256: string } | undefined {
  if (!isObject(record) || !isObject(record.deltaAnchor)) return undefined;
  const { sequence, sha256 } = record.deltaAnchor;
  return Number.isSafeInteger(sequence) && (sequence as number) >= 1 && isString(sha256) && /^[a-f0-9]{64}$/.test(sha256) ? { sequence: sequence as number, sha256 } : undefined;
}

/**
 * FAC-SEM-137 across two revisions (DEC-0107): the delta anchor never moves back. A revision whose parent anchors the
 * delta anchors it too, at the parent's sequence or later, with the parent's hash at the same sequence.
 */
function anchorFindings(parent: JsonObject, next: JsonObject): Finding[] {
  const findings: Finding[] = [];
  const flag = flagger(findings, "FAC-SEM-137");
  const before = deltaAnchorOf(parent);
  if (before === undefined) return findings;
  const after = deltaAnchorOf(next);
  if (after === undefined) flag("/next/deltaAnchor", `the parent anchors the delta at ${before.sequence}: a revision keeps an anchor once one is set`);
  else if (after.sequence < before.sequence) flag("/next/deltaAnchor/sequence", `the anchor moves back from ${before.sequence} to ${after.sequence}`);
  else if (after.sequence === before.sequence && after.sha256 !== before.sha256) flag("/next/deltaAnchor/sha256", `another hash at sequence ${after.sequence}: two delta histories`);
  return findings;
}

export function estateRecordRules(kind: string, value: JsonObject): Finding[] | undefined {
  if (kind === "estate-record") return recordFindings(value);
  if (kind === "estate-record-revision") {
    const parent = isObject(value.parent) ? value.parent : {};
    const next = isObject(value.next) ? value.next : {};
    return [...revisionChain(value), ...droppedFindings(parent, next), ...anchorFindings(parent, next)];
  }
  if (kind === "estate-placement") return installation(value);
  return undefined;
}
// #endregion estate-record-rules
