import { createHash, createPublicKey, verify } from "node:crypto";
import { CLOCK_SKEW_SECONDS, strictTime } from "./rfc3339.js";
import { rfc8785 } from "./canonical.js";
import { isSmallOrderKey } from "./ed25519.js";
import { type JsonObject, isObject, show } from "./findings.js";
import { sameIdentifier } from "./identifiers.js";

// #region revocation-delta — docs: docs/specification/revocation-delta.md#the-verifier
/**
 * The revocation delta and the timestamp heartbeat (DEC-0054). The delta is an append-only chain of signed entries,
 * one revocation each; entry n names the hash of the head before it, so the head is `{sequence, sha256}` — the shape a
 * device check-in reports (`records.revocationDelta`, DEC-0053) and a relay's `welcome.deltaHead` carries (DEC-0047).
 * The heartbeat is a signed timestamp that commits to the delta's head and to the estate revision. Both are signed by
 * an estate key: a hub key the highest estate-record revision the machine verified and applied certifies (DEC-0055
 * `hubKey`), not revoked there or by an entry applied before. A machine whose heartbeat is more than 72 hours old, or
 * that has not applied up to the heartbeat's head and revision, or that saw two signed histories, refuses what arrives
 * from other machines and keeps the person's own work running.
 *
 * Every function here answers and never throws: malformed input is a verdict.
 */

export const DELTA_TYPE = "revocation-delta/1";
export const HEARTBEAT_TYPE = "heartbeat/1";
/** The estate key's algorithm until Fabric records D2; ES256 joins additively then (DEC-0055 item 9). */
export const DELTA_ALG = "EdDSA";
/** The revocation kinds an entry may carry: the estate record's, without `authority` (a passkey is revoked only by a revision a passkey signs). */
export const DELTA_KINDS: readonly string[] = ["machine", "device-key", "hub-key", "publisher-key", "package", "grant"];
/** v4 §7: without a heartbeat for 72 hours, calls from other machines fail closed. */
export const HEARTBEAT_STALE_SECONDS = 72 * 60 * 60;
/** v4 §7 "daily": the longest a running hub lets pass between two heartbeats. */
export const HEARTBEAT_MAX_INTERVAL_SECONDS = 24 * 60 * 60;
/** The interval a running hub SHOULD keep, beside a heartbeat after every entry and every revision. */
export const HEARTBEAT_INTERVAL_SECONDS = 60 * 60;
/** How far ahead of the verifier's clock a signed time may be: the relay's skew (DEC-0047 item 2). */
export const MAX_FUTURE_SECONDS = CLOCK_SKEW_SECONDS; // the relay family's and the estate record's skew (DEC-0066)
/** The most entries one page carries, so a relay frame stays under 1 MiB (DEC-0047 item 3). */
export const MAX_PAGE_ENTRIES = 256;

const HEX64 = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIG = /^[A-Za-z0-9_-]{86}$/;
const isString = (value: unknown): value is string => typeof value === "string";
const isCount = (value: unknown, min: number): value is number => Number.isSafeInteger(value) && (value as number) >= min;
const list = (value: unknown): JsonObject[] => (Array.isArray(value) ? value.filter(isObject) : []);
const sha256hex = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

/** The shared strict RFC 3339 reader (DEC-0055 ER-10, `src/rfc3339.ts`): an unreadable time is refused before any
 * comparison, since a comparison with NaN is always false and would let anything through. */
export const deltaTime = (value: unknown): number => strictTime(value);

/** The clock a verifier is given, as milliseconds, or NaN when it is not a readable `Date`. */
const clock = (trust: unknown): number => (isObject(trust) && trust.at instanceof Date ? trust.at.getTime() : Number.NaN);

/** The bytes an entry's or a heartbeat's signature covers: the UTF-8 RFC 8785 form of the document without `sig`. Throws for a value RFC 8785 has no form for. */
export function signingInput(document: JsonObject): Buffer {
  const { sig: _sig, ...covered } = document;
  return Buffer.from(rfc8785(covered), "utf8");
}

/** The head hash after an entry: the hex SHA-256 of its signing input. The signature stays outside, as an estate record's does. */
export function deltaEntryHash(entry: JsonObject): string {
  return sha256hex(signingInput(entry));
}

/** The head before entry 1: the hex SHA-256 of the RFC 8785 form of `{type: "revocation-delta/1", estate, sequence: 0}`, so no estate's chain splices onto another's. */
export function deltaGenesis(estate: string): string {
  return sha256hex(Buffer.from(rfc8785({ type: DELTA_TYPE, estate, sequence: 0 }), "utf8"));
}

/** What a machine holds of one estate's delta. `entries[n - 1]` is entry n; `forked` keeps signed entries that conflict with the chain, for their revocations and as evidence. */
export interface DeltaState {
  estate: string;
  entries: readonly JsonObject[];
  heartbeat?: JsonObject;
  broken?: boolean;
  forked?: readonly JsonObject[];
}

/** A machine that has applied no entry yet. */
export const emptyDeltaState = (estate: string): DeltaState => ({ estate, entries: [] });

/** The hash of the head at `sequence` in the chain a state holds: the genesis at 0; "" (never a hash) for what the state does not hold. */
const headAt = (state: DeltaState, sequence: number): string => {
  try {
    if (sequence === 0) return deltaGenesis(state.estate);
    const entry = state.entries[sequence - 1];
    return isObject(entry) ? deltaEntryHash(entry) : "";
  } catch {
    return "";
  }
};

/** Whether a state is one this module could have produced: an estate id and a list of entries. */
const usable = (state: unknown): state is DeltaState => isObject(state) && isString(state.estate) && Array.isArray(state.entries);

/** The head a machine has applied, in the check-in's `records.revocationDelta` shape. */
export function deltaHead(state: DeltaState): { sequence: number; sha256: string } {
  const sequence = state.entries.length;
  return { sequence, sha256: headAt(state, sequence) };
}

/**
 * The revocations the delta holds in force on a machine, in the estate record's revocation form (`{kind, ref,
 * revokedAt}`): the applied entries', then those of signed entries that forked. They are what a check that reads the
 * estate record's revocations applies on top of `record.revocations` — DL-14's `hubKeyCertified(..., {extraRevocations})`
 * among them (DEC-0054).
 */
export function deltaRevocations(state: DeltaState | undefined): JsonObject[] {
  const held: JsonObject = isObject(state) ? (state as unknown as JsonObject) : {};
  return [...list(held.entries), ...list(held.forked)].map((entry) => entry.revocation).filter(isObject);
}

/** Every revocation in force on a machine: the applied revision's, then the delta's (`deltaRevocations`). */
export function effectiveRevocations(record: unknown, state: DeltaState | undefined): JsonObject[] {
  return [...list(isObject(record) ? record.revocations : undefined), ...deltaRevocations(state)];
}

/**
 * Whether `revocations` revoke `ref` of `kind`, matched exactly: `kind` and `ref` are compared as the strings they are,
 * never through `show()`, as DL-14's `hubKeyCertified` matches them (a number 5 never revokes the machine "5"). A
 * `grant` ref is a grant's URI id, so it matches by normal form (DEC-0076): another spelling of a revoked grant is
 * revoked, never let through.
 */
export function isRevoked(revocations: readonly unknown[], kind: string, ref: unknown): boolean {
  const same = (other: unknown) => (kind === "grant" ? sameIdentifier(other, ref) : other === ref);
  return isString(ref) && revocations.some((revocation) => isObject(revocation) && revocation.kind === kind && same(revocation.ref));
}

export type SignerProblem = "unknown-signer" | "revoked-signer" | "unusable-key" | "small-order-key";

/**
 * The estate key a delta entry or a heartbeat is verified under: the `hubKey` of the machine of `record` whose kid is
 * `kid` (compared exactly), certified once, EdDSA, Ed25519 of full order (DEC-0045), and neither that kid (`hub-key`)
 * nor its machine (`machine`) revoked by `revocations` (`isRevoked`, exact matching).
 */
export function estateSigner(record: unknown, kid: unknown, revocations: readonly unknown[]): { key: ReturnType<typeof createPublicKey> } | { problem: SignerProblem } {
  const machines = list(isObject(record) ? record.machines : undefined).filter((machine) => isObject(machine.hubKey) && machine.hubKey.kid === kid);
  if (!isString(kid) || machines.length !== 1) return { problem: "unknown-signer" };
  const machine = machines[0] as JsonObject;
  const jwk = machine.hubKey as JsonObject;
  if (isRevoked(revocations, "hub-key", kid) || isRevoked(revocations, "machine", machine.id)) return { problem: "revoked-signer" };
  if (jwk.alg !== DELTA_ALG || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !isString(jwk.x) || jwk.d !== undefined) return { problem: "unusable-key" };
  const raw = Buffer.from(jwk.x, "base64url");
  if (raw.length !== 32 || raw.toString("base64url") !== jwk.x) return { problem: "unusable-key" };
  if (isSmallOrderKey(raw)) return { problem: "small-order-key" };
  try {
    return { key: createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" }) };
  } catch {
    return { problem: "unusable-key" };
  }
}

/** Whether `sig` (base64url, 64 bytes) verifies over `bytes` under `key`. */
const verifies = (bytes: Buffer, sig: string, key: ReturnType<typeof createPublicKey>): boolean => {
  try {
    return verify(null, bytes, key, Buffer.from(sig, "base64url"));
  } catch {
    return false;
  }
};

/** An entry's shape, beyond the schema only where a rule needs it: the answer is the first thing wrong, or undefined. */
function entryShape(entry: unknown): string | undefined {
  if (!isObject(entry)) return "an entry is an object";
  if (entry.type !== DELTA_TYPE) return `an entry's type is ${DELTA_TYPE}`;
  if (!isString(entry.estate) || !isString(entry.kid) || !isString(entry.alg)) return "estate, kid and alg are strings";
  if (!isCount(entry.sequence, 1)) return "sequence is an integer from 1 to 2^53 - 1";
  if (!isString(entry.prev) || !HEX64.test(entry.prev)) return "prev is 64 lower-case hex";
  if (!isString(entry.sig) || !SIG.test(entry.sig)) return "sig is 64 bytes in base64url";
  const revocation = entry.revocation;
  if (!isObject(revocation) || !isString(revocation.kind) || !isString(revocation.ref)) return "revocation names its kind and ref";
  const at = deltaTime(entry.at);
  const revokedAt = deltaTime(revocation.revokedAt);
  if (Number.isNaN(at) || Number.isNaN(revokedAt)) return "at and revokedAt are RFC 3339 date-times with an offset, on days that exist";
  if (revokedAt > at) return "a revocation is never dated after the entry that carries it";
  try {
    signingInput(entry);
  } catch {
    return "the entry has no RFC 8785 form";
  }
  return undefined;
}

export type DeltaProblem =
  | "no-clock"
  | "malformed"
  | "wrong-estate"
  | "unsupported-alg"
  | "not-revocable"
  | "not-yet-valid"
  | SignerProblem
  | "bad-signature"
  | "gap"
  | "broken-chain"
  | "fork";

export type DeltaVerdict =
  | { ok: true; state: DeltaState; applied: number }
  | { ok: false; problem: DeltaProblem; index: number; state: DeltaState; reason: string };

export interface DeltaTrust {
  /** The highest estate-record revision the machine verified (`verifyEstateRecord`) and applied. */
  record: unknown;
  /** The verifier's clock. */
  at: Date;
}

/**
 * Apply a page of entries (`{head, entries}`, the relay's `delta` frame and the check-in response's
 * `records.revocationDelta`) to what a machine holds, in order. Each entry is checked — shape, estate, `EdDSA`, an
 * admitted kind, not more than 60 s ahead, an estate key the record certifies and nothing revokes, the signature —
 * and only then placed: an entry already held is skipped; one past the next sequence is a `gap` (ask with
 * `delta-query`); a signed entry whose `prev` is not the held head, or that differs from the entry held at its
 * sequence, is a second signed history (`broken-chain`, `fork`), and the state becomes `broken`, keeping that entry's
 * revocation in force. The page's `head` is the relay's hint and binds nothing; a heartbeat's head does. On a refusal,
 * the entries before the refused one stay applied.
 */
export function applyDelta(state: DeltaState, page: unknown, trust: DeltaTrust): DeltaVerdict {
  const fail = (problem: DeltaProblem, index: number, current: DeltaState, reason: string): DeltaVerdict => ({ ok: false, problem, index, state: current, reason });
  const now = clock(trust);
  if (!Number.isFinite(now)) return fail("no-clock", -1, state, "the verifier's clock is not a readable time");
  if (!usable(state)) return fail("malformed", -1, state, "the held state names its estate and lists its entries");
  if (!isObject(page) || !Array.isArray(page.entries)) return fail("malformed", -1, state, "a page is {head, entries}");
  // A readable clock means `trust` is an object.
  const record: unknown = (trust as DeltaTrust).record;
  if (!isObject(record) || record.estate !== state.estate) return fail("wrong-estate", -1, state, "the trusted revision is not this estate's");
  let current = state;
  let applied = 0;
  const entries: unknown[] = page.entries;
  for (const [index, entry] of entries.entries()) {
    const shape = entryShape(entry);
    if (shape !== undefined) return fail("malformed", index, current, shape);
    const e = entry as JsonObject;
    const revocation = e.revocation as JsonObject;
    if (e.estate !== current.estate) return fail("wrong-estate", index, current, `the entry is estate ${show(e.estate)}'s`);
    if (e.alg !== DELTA_ALG) return fail("unsupported-alg", index, current, `an estate key signs with ${DELTA_ALG}`);
    if (!DELTA_KINDS.includes(revocation.kind as string)) return fail("not-revocable", index, current, `the delta does not carry a ${show(revocation.kind)} revocation: a passkey is revoked only by a revision`);
    if (deltaTime(e.at) > now + MAX_FUTURE_SECONDS * 1000) return fail("not-yet-valid", index, current, "the entry is dated more than 60 s ahead of the verifier's clock");
    const signer = estateSigner(record, e.kid, effectiveRevocations(record, current));
    if ("problem" in signer) return fail(signer.problem, index, current, `no estate key the trusted revision certifies signs as ${show(e.kid)}`);
    if (!verifies(signingInput(e), e.sig as string, signer.key)) return fail("bad-signature", index, current, "the signature does not verify");
    const sequence = e.sequence as number;
    const held = current.entries.length;
    if (sequence <= held) {
      if (headAt(current, sequence) === deltaEntryHash(e)) continue;
      return fail("fork", index, { ...current, broken: true, forked: [...(current.forked ?? []), e] }, `two signed entries carry sequence ${sequence}`);
    }
    if (sequence > held + 1) return fail("gap", index, current, `the next entry is ${held + 1}; ask from it with delta-query`);
    if (e.prev !== headAt(current, held)) return fail("broken-chain", index, { ...current, broken: true, forked: [...(current.forked ?? []), e] }, "prev is not the head this machine holds: a second signed history");
    current = { ...current, entries: [...current.entries, e] };
    applied += 1;
  }
  return { ok: true, state: current, applied };
}

export type HeartbeatProblem =
  | "no-clock"
  | "malformed"
  | "wrong-estate"
  | "unsupported-alg"
  | "not-yet-valid"
  | SignerProblem
  | "bad-signature"
  | "not-newer"
  | "regressed"
  | "fork";

export type HeartbeatVerdict =
  | { ok: true; state: DeltaState; newer: boolean }
  | { ok: false; problem: HeartbeatProblem; state: DeltaState; reason: string };

/** A heartbeat's shape: the first thing wrong, or undefined. */
function heartbeatShape(heartbeat: unknown): string | undefined {
  if (!isObject(heartbeat)) return "a heartbeat is an object";
  if (heartbeat.type !== HEARTBEAT_TYPE) return `a heartbeat's type is ${HEARTBEAT_TYPE}`;
  if (!isString(heartbeat.estate) || !isString(heartbeat.kid) || !isString(heartbeat.alg)) return "estate, kid and alg are strings";
  if (!isCount(heartbeat.sequence, 0)) return "sequence is an integer from 0 to 2^53 - 1";
  if (Number.isNaN(deltaTime(heartbeat.at))) return "at is an RFC 3339 date-time with an offset, on a day that exists";
  const head = heartbeat.deltaHead;
  if (!isObject(head) || !isCount(head.sequence, 0) || !isString(head.sha256) || !HEX64.test(head.sha256)) return "deltaHead is {sequence, sha256}, sha256 64 lower-case hex";
  const revision = heartbeat.estateRecord;
  if (!isObject(revision) || !isCount(revision.revision, 1) || !isString(revision.digest) || !DIGEST.test(revision.digest)) return "estateRecord is {revision, digest}, digest sha256: and 64 hex";
  if (!isString(heartbeat.sig) || !SIG.test(heartbeat.sig)) return "sig is 64 bytes in base64url";
  try {
    signingInput(heartbeat);
  } catch {
    return "the heartbeat has no RFC 8785 form";
  }
  return undefined;
}

/**
 * Accept a heartbeat: shape, estate, `EdDSA`, not more than 60 s ahead, an estate key, the signature; then against
 * what the machine holds — an older sequence is `not-newer` and changes nothing, the same sequence with other bytes or
 * a head or revision that contradicts the machine's own chain or revision is a `fork` (the state becomes `broken`), and
 * a newer sequence that moves `at`, the head or the revision back is `regressed`. A heartbeat whose head or revision is
 * ahead of the machine's is accepted: the machine is then behind (`deltaFreshness`) until it catches up.
 */
export function acceptHeartbeat(state: DeltaState, heartbeat: unknown, trust: DeltaTrust): HeartbeatVerdict {
  const fail = (problem: HeartbeatProblem, current: DeltaState, reason: string): HeartbeatVerdict => ({ ok: false, problem, state: current, reason });
  const now = clock(trust);
  if (!Number.isFinite(now)) return fail("no-clock", state, "the verifier's clock is not a readable time");
  if (!usable(state)) return fail("malformed", state, "the held state names its estate and lists its entries");
  const shape = heartbeatShape(heartbeat);
  if (shape !== undefined) return fail("malformed", state, shape);
  const h = heartbeat as JsonObject;
  // A readable clock means `trust` is an object.
  const record: unknown = (trust as DeltaTrust).record;
  if (h.estate !== state.estate || !isObject(record) || record.estate !== state.estate) return fail("wrong-estate", state, `the heartbeat is estate ${show(h.estate)}'s`);
  if (h.alg !== DELTA_ALG) return fail("unsupported-alg", state, `an estate key signs with ${DELTA_ALG}`);
  const at = deltaTime(h.at);
  if (at > now + MAX_FUTURE_SECONDS * 1000) return fail("not-yet-valid", state, "the heartbeat is dated more than 60 s ahead of the verifier's clock");
  const signer = estateSigner(record, h.kid, effectiveRevocations(record, state));
  if ("problem" in signer) return fail(signer.problem, state, `no estate key the trusted revision certifies signs as ${show(h.kid)}`);
  if (!verifies(signingInput(h), h.sig as string, signer.key)) return fail("bad-signature", state, "the signature does not verify");
  const head = h.deltaHead as JsonObject;
  const revision = h.estateRecord as JsonObject;
  const broken = (reason: string) => fail("fork", { ...state, broken: true }, reason);
  // A held heartbeat is one this function accepted; a corrupt held state never reads as "nothing newer is held".
  if (state.heartbeat !== undefined && heartbeatShape(state.heartbeat) !== undefined) return fail("malformed", state, "the heartbeat held is not one the machine could have accepted");
  // Past the check above, a held heartbeat is a well-formed one, or none.
  const held = state.heartbeat as JsonObject | undefined;
  if (held !== undefined) {
    if ((h.sequence as number) < (held.sequence as number)) return fail("not-newer", state, "the machine holds a newer heartbeat");
    if (h.sequence === held.sequence) {
      if (sameBytes(h, held)) return { ok: true, state, newer: false };
      return broken(`two signed heartbeats carry sequence ${show(h.sequence)}`);
    }
    const heldHead = held.deltaHead as JsonObject;
    const heldRevision = held.estateRecord as JsonObject;
    if (at < deltaTime(held.at) || (head.sequence as number) < (heldHead.sequence as number) || (revision.revision as number) < (heldRevision.revision as number)) {
      return fail("regressed", state, "a newer heartbeat never moves its time, the head or the revision back");
    }
  }
  const sequence = head.sequence as number;
  if (sequence <= state.entries.length && headAt(state, sequence) !== head.sha256) return broken(`the heartbeat's head at ${sequence} is not the entry this machine holds there`);
  if (revision.revision === record.revision && revision.digest !== record.digest) return broken(`the heartbeat names another revision ${show(revision.revision)} than the one this machine applied`);
  return { ok: true, state: { ...state, heartbeat: h }, newer: true };
}

/** Whether two signed documents cover the same bytes; a held document with no RFC 8785 form matches nothing. */
const sameBytes = (a: JsonObject, b: JsonObject): boolean => {
  try {
    return signingInput(a).equals(signingInput(b));
  } catch {
    return false;
  }
};

export type Freshness = "current" | "behind" | "stale" | "broken";

/**
 * The 72-hour rule as a pure function of what a machine holds, for a port and for the rule FAC-SEM-083: `broken` once two
 * signed histories were seen; `stale` with no readable clock, no heartbeat, an unreadable heartbeat time, or one more
 * than 72 hours old; `behind` when the heartbeat's head or revision is ahead of what the machine applied; else
 * `current`. Only `current` accepts what arrives from other machines.
 */
export function freshnessAnswer(input: { at: number; applied: { sequence: unknown; revision: unknown }; heartbeat?: unknown; broken?: boolean }): { answer: Freshness; reason: string } {
  if (input.broken === true) return { answer: "broken", reason: "two signed histories were seen; the person's own work continues" };
  if (!Number.isFinite(input.at)) return { answer: "stale", reason: "the machine's clock is not readable" };
  const heartbeat = input.heartbeat;
  if (!isObject(heartbeat)) return { answer: "stale", reason: "no heartbeat is held" };
  const at = deltaTime(heartbeat.at);
  const head = isObject(heartbeat.deltaHead) ? heartbeat.deltaHead.sequence : undefined;
  const revision = isObject(heartbeat.estateRecord) ? heartbeat.estateRecord.revision : undefined;
  if (Number.isNaN(at) || !isCount(head, 0) || !isCount(revision, 1)) return { answer: "stale", reason: "the heartbeat held is not readable" };
  if (input.at - at > HEARTBEAT_STALE_SECONDS * 1000) return { answer: "stale", reason: "the heartbeat is more than 72 hours old" };
  // An applied count that is not a count is behind everything: it never reads as caught up.
  const sequence = isCount(input.applied.sequence, 0) ? input.applied.sequence : -1;
  const applied = isCount(input.applied.revision, 1) ? input.applied.revision : 0;
  if (sequence < head) return { answer: "behind", reason: `the delta is applied to ${sequence}, the heartbeat's head is ${head}` };
  if (applied < revision) return { answer: "behind", reason: `revision ${applied} is applied, the heartbeat names ${revision}` };
  return { answer: "current", reason: "a heartbeat of at most 72 hours, and the delta and the record applied up to it" };
}

/** `freshnessAnswer` over a machine's state and trust. */
export function deltaFreshness(state: DeltaState, trust: DeltaTrust): { answer: Freshness; reason: string; remote: "accept" | "refuse" } {
  const record = isObject(trust) && isObject(trust.record) ? trust.record : {};
  const ok = usable(state);
  const verdict = freshnessAnswer({
    at: clock(trust),
    applied: { sequence: ok ? state.entries.length : undefined, revision: record.revision },
    heartbeat: ok ? state.heartbeat : undefined,
    broken: ok && state.broken === true
  });
  return { ...verdict, remote: verdict.answer === "current" ? "accept" : "refuse" };
}

/**
 * Reconciliation (DEC-0054): a revision issued at or after an entry's `at` lists that entry's revocation (kind and
 * ref). Returns the entries it leaves out; a machine refuses such a revision and keeps the one it holds. An unreadable
 * `issuedAt` or entry time is reported, never compared.
 */
export function unreconciled(revision: unknown, entries: readonly unknown[]): { missing: Array<{ index: number; kind: string; ref: string }>; unreadable: boolean } {
  const issuedAt = deltaTime(isObject(revision) ? revision.issuedAt : undefined);
  const listed = list(isObject(revision) ? revision.revocations : undefined);
  const missing: Array<{ index: number; kind: string; ref: string }> = [];
  let unreadable = Number.isNaN(issuedAt);
  entries.forEach((entry, index) => {
    const revocation = isObject(entry) && isObject(entry.revocation) ? entry.revocation : undefined;
    const at = deltaTime(isObject(entry) ? entry.at : undefined);
    if (!revocation || !isString(revocation.kind) || !isString(revocation.ref) || Number.isNaN(at)) {
      unreadable = true;
      return;
    }
    if (!unreadable && at <= issuedAt && !isRevoked(listed, revocation.kind as string, revocation.ref)) missing.push({ index, kind: show(revocation.kind), ref: show(revocation.ref) });
  });
  return { missing, unreadable };
}

/** Whether a machine holding `state` may apply `revision` (already schema-valid and accepted by `verifyEstateRecord`). */
export function reconcileRevision(state: DeltaState, revision: unknown): { ok: true } | { ok: false; problem: "malformed" | "unreconciled"; missing: Array<{ index: number; kind: string; ref: string }> } {
  if (!usable(state)) return { ok: false, problem: "malformed", missing: [] };
  const result = unreconciled(revision, state.entries);
  if (result.unreadable) return { ok: false, problem: "malformed", missing: [] };
  if (result.missing.length > 0) return { ok: false, problem: "unreconciled", missing: result.missing };
  return { ok: true };
}
// #endregion revocation-delta
