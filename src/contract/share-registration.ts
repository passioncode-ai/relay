import { createHash } from "node:crypto";
import { rfc8785 } from "./canonical.js";
import { type Finding, type JsonObject, indexed, isObject, jsonEqual, show } from "./findings.js";
import { sameIdentifier } from "./identifiers.js";
import { type SchemaUnsupported, acceptedRevisions, negotiateRevision } from "./protocol-revisions.js";
import { strictTime } from "./rfc3339.js";

// #region share-registration, docs: docs/specification/share-registration.md
/**
 * Share registrations (DEC-0086): how an organization server learns which agent a share grant into it runs, so it can
 * join a `grant.usage` to that agent. The sharer's enrolled node derives one registration per share grant whose context
 * is the enrollment's organization (`deriveShareRegistrations`) from the estate revision and the delta entries it
 * applied, and sends it over the device transport (devices.md, the DEC-0056 signature). The receiver decides it
 * (`decideShareRegistration`), keyed by (the user bound to the certificate's epoch, `grantId`), and joins usage to it
 * (`joinGrantUsage`). Every function here answers and never throws: malformed input is an answer.
 */
export const SHARE_REGISTRATION_TYPE = "share-registration/1";
export const SHARE_REGISTRATION_RECEIPT_TYPE = "share-registration-receipt/1";
/**
 * A node re-sends each active registration at least this often (SHOULD), so a receiver that lost it learns it again;
 * never one a typed refusal answered, which waits for the record to change.
 */
export const RESEND_SECONDS = 7 * 24 * 60 * 60;
/** The longest refusal message. */
export const MAX_MESSAGE = 200;
/** The refusal codes of `share-registration.schema.json#/$defs/refusal`, in the order of the SR table. */
export const SHARE_REFUSAL_CODES: readonly string[] = ["malformed", "wrong-organization", "unassigned-device", "already-withdrawn", "agent-mismatch", "stale-revision", "revision-conflict", "purpose-not-collected"];
/** DEC-0056's codes (devices.md, transport steps 1 to 8), which SR-1 answers as they come: 401, or 410 for `organization-closed` (DEC-0103). */
export const TRANSPORT_REFUSALS: readonly string[] = ["signature-missing", "digest-mismatch", "signature-stale", "certificate-unknown", "organization-closed", "certificate-revoked", "certificate-expired", "signature-invalid", "signature-replayed"];
/** DEC-0056 step 0: a receiver whose own context is unusable accepts nothing, and the fault is its own. */
export const RECEIVER_FAULTS: readonly string[] = ["context-invalid", "clock-unreadable", "base-url-invalid"];

/** `common#/$defs/shareGrantId`: no `m` flag, so `$` is the end of the text and a trailing newline is refused. */
const SHARE_GRANT_ID = /^urn:fabric:share:(?!0{32}$)[0-9a-f]{32}$/;
/** `common#/$defs/orgContextId`. */
const ORG_CONTEXT = /^org:[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
/** `fabric-package#/$defs/agentRef`. */
const AGENT_REF = /^urn:fabric:agent:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
/**
 * `share-registration#/$defs/instant`: an offset, seconds 00 to 59 (no leap second, which JSON Schema's `date-time` admits),
 * and at most three fraction digits (DEC-0085's millisecond rule).
 */
const INSTANT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-5][0-9](?:\.[0-9]{1,3})?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})$/;
/** A time whose fraction has more than three digits, which a registration cannot carry as written. */
const SUB_MILLISECOND = /:[0-9]{2}\.[0-9]{4,}/;
const DAY_MS = 24 * 60 * 60 * 1000;
/** `activity-common#/$defs/day`. */
const DAY = /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;

const isString = (value: unknown): value is string => typeof value === "string";
const list = (value: unknown): JsonObject[] => (Array.isArray(value) ? value.filter(isObject) : []);
const positive = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 1;
const agentRefOk = (value: unknown): value is string => isString(value) && value.length <= 146 && AGENT_REF.test(value);
/** An instant as milliseconds, or NaN: the schema's pattern and a day that exists (`strictTime`). */
const time = (value: unknown): number => (isString(value) && INSTANT.test(value) ? strictTime(value) : Number.NaN);
const readable = (value: unknown): value is string => Number.isFinite(time(value));
/** The midnight UTC, in milliseconds, of the day an instant falls on: days compare as numbers, so a year past 9999 compares too. */
const dayStart = (ms: number) => Math.floor(ms / DAY_MS) * DAY_MS;

/**
 * A grant's or a revocation's time as a registration carries it (DEC-0086, the fix round): a time with at most three
 * fraction digits as written, already a millisecond instant; one with more, rounded to milliseconds (`up` for a window's
 * start, down otherwise, so a registered window is never wider than the grant's and a withdrawal ends early, never late).
 * Rounding down cuts the fraction to three digits and keeps the offset, so every readable time can be carried; rounding a
 * start up by one millisecond writes it as `Date#toISOString` does, in UTC. Undefined for a time `strictTime` cannot read.
 */
function carried(value: unknown, up = false): string | undefined {
  if (!isString(value) || !Number.isFinite(strictTime(value))) return undefined;
  if (!SUB_MILLISECOND.test(value)) return value;
  // Cutting the fraction to three digits floors the instant; a non-zero digit cut away moves a start up by 1 ms.
  let extra = false;
  const cut = value.replace(/(\.[0-9]{3})([0-9]+)/, (_, kept: string, rest: string) => {
    extra = up && /[1-9]/.test(rest);
    return kept;
  });
  return extra ? new Date(strictTime(cut) + 1).toISOString() : cut;
}
/** A grant's or a revocation's time as milliseconds, any number of fraction digits floored, or NaN. */
const instant = (value: unknown): number => {
  const text = carried(value);
  return text === undefined ? Number.NaN : strictTime(text);
};
/** An object's own member, never one read through its prototype (`constructor`, `__proto__`). */
const own = (value: unknown, key: string): unknown => (isObject(value) && Object.hasOwn(value, key) ? value[key] : undefined);
const exactly = (value: JsonObject, names: readonly string[]) => Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));

/** Whether `value` is a share grant's id: `urn:fabric:share:` and 32 lower-case hex digits, not all zeros, as written. */
export function isShareGrantId(value: unknown): value is string {
  return isString(value) && SHARE_GRANT_ID.test(value);
}

/** Whether `value` is an organization's context id, `org:<orgId>`, as written. */
export function isOrgContext(value: unknown): value is string {
  return isString(value) && ORG_CONTEXT.test(value);
}

/** `sha256:` and the hex SHA-256 of the UTF-8 RFC 8785 form of `registration`; undefined when it has no RFC 8785 form. */
export function shareRegistrationDigest(registration: unknown): string | undefined {
  try {
    return `sha256:${createHash("sha256").update(Buffer.from(rfc8785(registration), "utf8")).digest("hex")}`;
  } catch {
    return undefined;
  }
}

const ACTIVE_MEMBERS = ["type", "grantId", "context", "state", "grantRevision", "agentRef", "startsAt", "expiresAt"] as const;
const WITHDRAWN_MEMBERS = ["type", "grantId", "context", "state", "withdrawnAt"] as const;

/**
 * Whether a registration has the schema's shape and `FAC-SEM-118`'s document clauses: exactly its state's members, every
 * instant readable (a day that exists), and an active window that ends after it starts.
 */
export function registrationWellFormed(doc: unknown): doc is JsonObject {
  if (!isObject(doc) || doc.type !== SHARE_REGISTRATION_TYPE || !isShareGrantId(doc.grantId) || !isOrgContext(doc.context)) return false;
  if (doc.state === "active") {
    return exactly(doc, ACTIVE_MEMBERS) && positive(doc.grantRevision) && agentRefOk(doc.agentRef) && time(doc.startsAt) < time(doc.expiresAt);
  }
  return doc.state === "withdrawn" && exactly(doc, WITHDRAWN_MEMBERS) && readable(doc.withdrawnAt);
}

// ---- Derivation (the node) ---------------------------------------------------------------------------------------

/** Why a share grant into the organization registers nothing: a reason the node reports as degraded. */
export type DerivationDegraded = "share-grant-id" | "share-grant-agents" | "share-grant-unreadable";
export interface ShareRegistrationDerivation {
  registrations: JsonObject[];
  degraded: Array<{ grantId: string; code: DerivationDegraded }>;
}

/**
 * Whether `grant` revocations name `id` by normal form, and the earliest `revokedAt` among them as a registration carries
 * it (`carried`, floored): compared at millisecond precision after the floor, the first listed among equals; undefined
 * when none is readable.
 */
function revokedAt(revocations: readonly JsonObject[], id: string): { revoked: boolean; at: string | undefined } {
  const matching = revocations.filter((revocation) => sameIdentifier(revocation.ref, id));
  const times = matching.map((revocation) => revocation.revokedAt).filter((value) => Number.isFinite(instant(value)));
  // The first earliest in order: two revocations at one instant give one answer.
  const at = times.reduce<unknown>((best, candidate) => (best === undefined || instant(candidate) < instant(best) ? candidate : best), undefined);
  return { revoked: matching.length > 0, at: carried(at) };
}

/**
 * The registrations a node sends toward its enrollment in `orgId` (DEC-0086 item 3), from the estate revision it applied
 * (`record`), the revocation-delta entries it applied (`appliedEntries`, each `{revocation: {kind, ref, revokedAt}}`)
 * and the grant ids it registered active toward that enrollment before (`previouslyRegistered`). For each share grant
 * of the revision whose `context` is `org:<orgId>` as written, in the record's order and each id once:
 *
 * - a `meta.id` that is no share grant id registers nothing (`share-grant-id`);
 * - a grant revoked by the record or an applied entry (a `grant` revocation, its ref matched by normal form) is
 *   withdrawn at the earliest `revokedAt`;
 * - otherwise the placements of the revision in that context naming the grant by normal form decide: none, nothing yet;
 *   two `agentRef`s (or one that is no agentRef), nothing (`share-grant-agents`); one, an active registration with the
 *   grant's `meta.revision` and its window as `carried` writes it.
 *
 * Then each grant id registered before that the revision no longer lists in that context is withdrawn: at the earliest
 * `revokedAt` when it is revoked, else at the revision's `issuedAt`. Times are carried at millisecond precision
 * (`carried`): a withdrawal time floored, a window rounded inward, so a revoked share is withdrawn whatever the number of
 * fraction digits. A time `strictTime` cannot read, a revision below 1, or a window that is empty once rounded registers
 * nothing (`share-grant-unreadable`). Personal, context-less and
 * other organizations' grants never register. Total: malformed input answers no registration.
 */
export function deriveShareRegistrations(record: unknown, appliedEntries: unknown, orgId: unknown, previouslyRegistered: unknown): ShareRegistrationDerivation {
  const answer: ShareRegistrationDerivation = { registrations: [], degraded: [] };
  const context = `org:${show(orgId)}`;
  if (!isObject(record) || !isString(orgId) || !isOrgContext(context)) return answer;
  const revocations = [...list(record.revocations), ...list(appliedEntries).map((entry) => entry.revocation)]
    .filter(isObject)
    .filter((revocation) => revocation.kind === "grant");
  const placements = list(record.machines).flatMap((machine) => list(machine.packages)).filter((placement) => placement.context === context);
  const emit = (registration: JsonObject, id: string) => {
    if (registrationWellFormed(registration)) answer.registrations.push(registration);
    else answer.degraded.push({ grantId: id, code: "share-grant-unreadable" });
  };
  const withdrawal = (id: string, withdrawnAt: unknown) => emit({ type: SHARE_REGISTRATION_TYPE, grantId: id, context, state: "withdrawn", withdrawnAt }, id);

  const listed = new Set<string>();
  for (const grant of list(record.shareGrants)) {
    if (grant.context !== context) continue;
    const meta = isObject(grant.meta) ? grant.meta : {};
    if (!isShareGrantId(meta.id)) {
      answer.degraded.push({ grantId: show(meta.id), code: "share-grant-id" });
      continue;
    }
    const id = meta.id;
    if (listed.has(id)) continue;
    listed.add(id);
    const revocation = revokedAt(revocations, id);
    if (revocation.revoked) {
      withdrawal(id, revocation.at);
      continue;
    }
    const refs = [...new Set(placements.filter((placement) => sameIdentifier(placement.grant, id)).map((placement) => placement.agentRef))];
    if (refs.length === 0) continue;
    const agentRef = refs[0];
    if (refs.length > 1 || !agentRefOk(agentRef)) {
      answer.degraded.push({ grantId: id, code: "share-grant-agents" });
      continue;
    }
    // The window is carried rounded inward to milliseconds, never wider than the grant's.
    emit({ type: SHARE_REGISTRATION_TYPE, grantId: id, context, state: "active", grantRevision: meta.revision, agentRef, startsAt: carried(grant.startsAt, true), expiresAt: carried(grant.expiresAt) }, id);
  }

  const earlier = Array.isArray(previouslyRegistered) ? previouslyRegistered.filter(isShareGrantId) : [];
  for (const id of new Set(earlier)) {
    if (listed.has(id)) continue;
    const revocation = revokedAt(revocations, id);
    withdrawal(id, revocation.revoked ? revocation.at : carried(record.issuedAt));
  }
  return answer;
}

// ---- Intake (the receiver) ---------------------------------------------------------------------------------------

/**
 * What a receiver holds per (user, grantId) (DEC-0086 item 5). A receiver keeps one held list per organization: an entry
 * carries no organization, because the user and the grant id are keys inside the organization whose certificate bound the
 * user, and a user id of one organization says nothing in another. So `decideShareRegistration` and `joinGrantUsage` are
 * given the list of the organization the request's certificate binds, never a list shared across organizations.
 * The entry holds: the state, the active registration's members (kept on a
 * withdrawal so usage before it still joins; absent on a tombstone, a withdrawal that arrived with nothing held), the
 * withdrawal time, and the digest of the registration it keeps.
 */
export interface HeldShareRegistration {
  user: string;
  grantId: string;
  state: "active" | "withdrawn";
  grantRevision?: number;
  agentRef?: string;
  startsAt?: string;
  expiresAt?: string;
  withdrawnAt?: string;
  digest: string;
}

/** The certificate's binding as recorded for its epoch, and the transport's verdict on the request (DEC-0056). */
export interface ShareRegistrationBinding {
  transport: { ok: true } | { ok: false; code: string };
  org: { id: string };
  device?: { id: string };
  user?: { id: string };
}

export type ShareRegistrationRefusal = { error: { code: string; message: string } };
export type ShareRegistrationReceipt = { type: typeof SHARE_REGISTRATION_RECEIPT_TYPE; grantId: string; state: "registered" | "unchanged" | "withdrawn"; digest: string };

/**
 * The receiver's answer. The 401 and 410 answers carry no body: the receiver writes the HTTP body itself, for the 410
 * `device-organization-closed` (`{error: {code, message}, closedAt}`, DEC-0103).
 */
export type ShareRegistrationAnswer =
  | { status: 200; receipt: ShareRegistrationReceipt; held: HeldShareRegistration }
  | { status: 400 | 403 | 409; body: ShareRegistrationRefusal | SchemaUnsupported }
  | { status: 401; code: string }
  | { status: 410; code: "organization-closed"; closedAt: string }
  | { fault: string };

const ACTIVE_HELD = ["grantRevision", "agentRef", "startsAt", "expiresAt"] as const;

/** Whether one held entry is one this module could have produced. */
function heldEntryOk(entry: unknown): entry is HeldShareRegistration {
  if (!isObject(entry) || !isString(entry.user) || entry.user === "" || !isShareGrantId(entry.grantId) || !isString(entry.digest) || !SHA256.test(entry.digest)) return false;
  const active = positive(entry.grantRevision) && agentRefOk(entry.agentRef) && time(entry.startsAt) < time(entry.expiresAt);
  const none = ACTIVE_HELD.every((name) => !Object.hasOwn(entry, name));
  if (entry.state === "active") return active && !Object.hasOwn(entry, "withdrawnAt");
  // A withdrawal keeps the active registration's members, or none at all (a tombstone).
  return entry.state === "withdrawn" && readable(entry.withdrawnAt) && (active || none);
}

/** Whether a held list is usable: well-formed entries, one per (user, grantId). */
function heldListOk(held: unknown): held is HeldShareRegistration[] {
  if (!Array.isArray(held) || !held.every(heldEntryOk)) return false;
  const keys = held.map((entry) => JSON.stringify([entry.user, entry.grantId]));
  return new Set(keys).size === keys.length;
}

/** The bound user's id, `undefined` when the epoch has none, or `null` when the binding's `user` is not `{id}`. */
function boundUser(binding: JsonObject): string | undefined | null {
  const user = own(binding, "user");
  if (user === undefined) return undefined;
  const id = own(user, "id");
  return isString(id) && id !== "" ? id : null;
}

/** Whether a binding is usable: an object with the organization's id and a well-formed or absent user. */
function bindingOk(binding: unknown): binding is JsonObject {
  const admitted = own(binding, "purposeAdmitted");
  return isObject(binding) && isString(own(own(binding, "org"), "id")) && boundUser(binding) !== null && (admitted === undefined || typeof admitted === "boolean");
}

const MESSAGES: Readonly<Record<string, string>> = {
  malformed: "the registration does not have share-registration/1's shape, or its window does not end after it starts",
  "wrong-organization": "the registration's context is not this certificate's organization",
  "unassigned-device": "no user is bound to this device's epoch, so no registrant",
  "already-withdrawn": "this grant is already withdrawn for this user; a withdrawal is final",
  "agent-mismatch": "this grant is held for another agentRef",
  "stale-revision": "a higher revision of this grant is held",
  "revision-conflict": "this revision of the grant is held with other bytes",
  "purpose-not-collected": "the notice this person acknowledged does not name the purposes a share registration serves; send it again when the notice changes or the person acknowledges it, and at the weekly resend"
};

const refuse = (status: 400 | 403 | 409, code: string): ShareRegistrationAnswer => ({ status, body: { error: { code, message: MESSAGES[code] as string } } });
const receipt = (held: HeldShareRegistration, state: ShareRegistrationReceipt["state"]): ShareRegistrationAnswer => ({
  status: 200,
  receipt: { type: SHARE_REGISTRATION_RECEIPT_TYPE, grantId: held.grantId, state, digest: held.digest },
  held
});

/**
 * The receiver's decision on one registration (DEC-0086 item 4), in the order of share-registration.md's SR table.
 * `held` is the list the receiver keeps for the organization of the certificate's `org.id` (see `HeldShareRegistration`):
 *
 * - SR-0: its own context unusable (`held` not a list of well-formed entries one per (user, grantId), a binding that is
 *   not `{transport, org: {id}, user?: {id}}`): `{fault: "context-invalid"}`; a transport verdict naming DEC-0056 step
 *   0's fault answers that fault;
 * - SR-1: the transport refused the request (DEC-0056 steps 1 to 8): 401 and its code, or 410 `organization-closed` with
 *   `closedAt` (DEC-0103; a verdict without a readable `closedAt` is SR-0's `context-invalid`);
 * - SR-2: an object whose `type` is a string other than `share-registration/1`: 400 `schema-unsupported` (DEC-0067);
 * - SR-3: not the schema's shape or `FAC-SEM-118`'s clauses: 400 `malformed`;
 * - SR-4: `context` is not `org:` and the certificate's `org.id` as written: 403 `wrong-organization`;
 * - SR-5: no user bound to the epoch: 403 `unassigned-device`;
 * - SR-5a (DEC-0100): an active registration while `binding.purposeAdmitted` is false, the bound user's acknowledged
 *   notice does not name the purposes a share registration serves: 403 `purpose-not-collected` (a withdrawal passes,
 *   DEC-0102);
 * - SR-6…SR-9: an active registration over what is held for (user, grantId): withdrawn, 409 `already-withdrawn`;
 *   another `agentRef`, `agent-mismatch`; a lower `grantRevision`, `stale-revision`; the same revision with another
 *   digest, `revision-conflict`;
 * - SR-10: the same digest, or a second withdrawal (the earliest `withdrawnAt` kept): 200 `unchanged`;
 * - SR-11: otherwise 200 `registered` or `withdrawn`, with the entry to hold.
 *
 * It never throws.
 */
export function decideShareRegistration(held: unknown, registration: unknown, binding: unknown): ShareRegistrationAnswer {
  if (!heldListOk(held) || !bindingOk(binding)) return { fault: "context-invalid" };
  const transport = own(binding, "transport");
  if (own(transport, "ok") !== true) {
    const code = own(transport, "ok") === false ? own(transport, "code") : undefined;
    const closedAt = own(transport, "closedAt");
    if (code === "organization-closed") return isString(closedAt) && !Number.isNaN(strictTime(closedAt)) ? { status: 410, code, closedAt } : { fault: "context-invalid" };
    if (isString(code) && TRANSPORT_REFUSALS.includes(code)) return { status: 401, code };
    return { fault: isString(code) && RECEIVER_FAULTS.includes(code) ? code : "context-invalid" };
  }
  if (isObject(registration) && isString(registration.type) && registration.type !== SHARE_REGISTRATION_TYPE) {
    // The register lists share-registration/1 and the type is another string, so the answer is the refusal.
    return { status: 400, body: negotiateRevision(registration.type, acceptedRevisions("share-registration")) as SchemaUnsupported };
  }
  if (!registrationWellFormed(registration)) return refuse(400, "malformed");
  const org = own(own(binding, "org"), "id") as string;
  if (registration.context !== `org:${org}`) return refuse(403, "wrong-organization");
  // bindingOk refused a user that is not {id}, so the user is a string or absent.
  const user = boundUser(binding) as string | undefined;
  if (user === undefined) return refuse(403, "unassigned-device");
  // SR-5a (DEC-0100): the receiver's own fact that the bound user's acknowledged notice does not name the purposes a
  // share registration serves (agent calls, usage and cost). The node holds the sums and sends again after the notice.
  // DEC-0102: a withdrawal reduces processing and is never held back by SR-5a.
  if (own(binding, "purposeAdmitted") === false && registration.state === "active") return refuse(403, "purpose-not-collected");

  const digest = shareRegistrationDigest(registration) as string;
  const grantId = registration.grantId as string;
  const entry = held.find((candidate) => candidate.user === user && candidate.grantId === grantId);
  if (registration.state === "active") {
    if (entry?.state === "withdrawn") return refuse(409, "already-withdrawn");
    if (entry && entry.agentRef !== registration.agentRef) return refuse(409, "agent-mismatch");
    if (entry && (registration.grantRevision as number) < (entry.grantRevision as number)) return refuse(409, "stale-revision");
    if (entry && registration.grantRevision === entry.grantRevision && digest !== entry.digest) return refuse(409, "revision-conflict");
    if (entry && digest === entry.digest) return receipt(entry, "unchanged");
    // Nothing held, or a higher revision of the same agent, which replaces what is held (and may extend expiresAt).
    const { grantRevision, agentRef, startsAt, expiresAt } = registration as { grantRevision: number; agentRef: string; startsAt: string; expiresAt: string };
    return receipt({ user, grantId, state: "active", grantRevision, agentRef, startsAt, expiresAt, digest }, "registered");
  }
  const withdrawnAt = registration.withdrawnAt as string;
  if (entry?.state === "withdrawn") {
    // Of two withdrawals the earliest is kept: a later one changes nothing, an earlier one moves the end back.
    return receipt(time(withdrawnAt) < time(entry.withdrawnAt) ? { ...entry, withdrawnAt, digest } : entry, "unchanged");
  }
  return receipt({ ...(entry ?? { user, grantId }), state: "withdrawn", withdrawnAt, digest }, "withdrawn");
}

// ---- The join ----------------------------------------------------------------------------------------------------

export type GrantUsageJoin =
  | { outcome: "rejected"; reason: "schema" | "attribution" }
  | { outcome: "stored"; joined: false; reason: "unassigned-device" | "unregistered" | "before-start" | "after-end" }
  | { outcome: "stored"; joined: true; agentRef: string }
  | { fault: "context-invalid" };

/**
 * The receiver's join of one `grant.usage` (DEC-0086 item 6), in the order of share-registration.md's GJ table, given
 * the binding recorded for the event's epoch (`{org: {id}, user?: {id}}`, FAC-SEM-045) and the registrations it holds for
 * that binding's organization (one list per organization, `HeldShareRegistration`). Days compare as midnight UTC in
 * milliseconds, so a window ending past year 9999 still compares:
 *
 * - GJ-0: its own context unusable, `{fault: "context-invalid"}`; an event that is not a `grant.usage` whose `data`
 *   carries a day that exists, a share grant id and an organization's context: rejected `schema`;
 * - GJ-1: `data.context` is not `org:` and the certificate's `org.id` as written: rejected `attribution`;
 * - GJ-2: no user bound to the epoch: stored, not joined, `unassigned-device`;
 * - GJ-3: no registration held for (bound user, `grantId`) with an `agentRef` (a tombstone has none): `unregistered`,
 *   recomputed when one arrives;
 * - GJ-4: `day` before the UTC day of `startsAt`: `before-start`;
 * - GJ-5: `day` after the UTC day of the end, the earlier of `expiresAt` and `withdrawnAt`: `after-end`;
 * - GJ-6: joined to the registration's `agentRef`.
 *
 * It never throws.
 */
export function joinGrantUsage(event: unknown, binding: unknown, registrations: unknown): GrantUsageJoin {
  if (!heldListOk(registrations) || !isObject(binding) || !isString(own(own(binding, "org"), "id")) || boundUser(binding) === null) return { fault: "context-invalid" };
  const data = own(event, "data");
  const day = own(data, "day");
  const grantId = own(data, "grantId");
  const context = own(data, "context");
  const dayOk = isString(day) && DAY.test(day) && Number.isFinite(strictTime(`${day}T00:00:00Z`));
  if (own(event, "kind") !== "grant.usage" || !dayOk || !isShareGrantId(grantId) || !isOrgContext(context)) return { outcome: "rejected", reason: "schema" };
  if (context !== `org:${own(own(binding, "org"), "id") as string}`) return { outcome: "rejected", reason: "attribution" };
  const user = boundUser(binding) as string | undefined;
  if (user === undefined) return { outcome: "stored", joined: false, reason: "unassigned-device" };
  const entry = registrations.find((candidate) => candidate.user === user && candidate.grantId === grantId && candidate.agentRef !== undefined);
  if (!entry) return { outcome: "stored", joined: false, reason: "unregistered" };
  const dayMs = strictTime(`${day}T00:00:00Z`);
  if (dayMs < dayStart(time(entry.startsAt))) return { outcome: "stored", joined: false, reason: "before-start" };
  const end = Math.min(time(entry.expiresAt), entry.withdrawnAt === undefined ? Number.POSITIVE_INFINITY : time(entry.withdrawnAt));
  if (dayMs > dayStart(end)) return { outcome: "stored", joined: false, reason: "after-end" };
  return { outcome: "stored", joined: true, agentRef: entry.agentRef as string };
}

// ---- The sender gate (the collector) ----------------------------------------------------------------------------

export type GateAnswer = "send" | "hold" | "hold-degraded" | "hold-notice" | "stop";

/** Refusals after which the grant's usage may be sent, with their status: the receiver holds a registration (or a final withdrawal). */
const SEND_AFTER: ReadonlyMap<string, number> = new Map([["stale-revision", 409], ["already-withdrawn", 409]]);
/** Typed refusals that sending the same registration again does not clear, with their status: the node holds back and reports degraded. */
const DEGRADED_AFTER: ReadonlyMap<string, number> = new Map([
  ["revision-conflict", 409], ["agent-mismatch", 409], ["wrong-organization", 403], ["unassigned-device", 403], ["malformed", 400], ["schema-unsupported", 400]
]);

/**
 * The sender gate (DEC-0086 item 6): whether a collector may emit `grant.usage` for a grant toward one enrollment, given
 * that enrollment's latest answer to the grant's registration, in the shape `decideShareRegistration` answers
 * (`{status: 200, receipt}`, `{status, body: {error: {code}}}`, `{status: 401, code}`, `{status: 410, code, closedAt}`,
 * `{fault}`), or `undefined`
 * before any answer:
 *
 * - `send`: a status 200 receipt, whatever its state, or a 409 `stale-revision` or `already-withdrawn`;
 * - `hold-degraded`: a typed refusal of the SR table that sending the same registration again does not clear (409
 *   `revision-conflict` or `agent-mismatch`, 403 `wrong-organization` or `unassigned-device`, 400 `malformed` or
 *   `schema-unsupported`): the node keeps the sums, reports itself degraded and sends again only when the record changes;
 * - `hold-notice` (DEC-0100): 403 `purpose-not-collected`: the node keeps the sums, is not degraded, and sends the
 *   registration again when its policy names a later `noticeVersion` or a check-in response a new
 *   `acknowledgedNoticeVersion` (DEC-0102), and at the seven-day resend;
 * - `stop` (DEC-0103): 410 `organization-closed`: the organization ended; the node keeps nothing for it and sends it
 *   nothing again;
 * - `hold`: no answer yet, a transport refusal (401), a receiver's fault, a code whose status is not its own, or anything
 *   else: the node keeps the sums and sends the registration again with backoff.
 *
 * It never throws.
 */
export function gateGrantUsage(answer: unknown): GateAnswer {
  if (own(answer, "status") === 200 && own(own(answer, "receipt"), "type") === SHARE_REGISTRATION_RECEIPT_TYPE) return "send";
  // DEC-0103: the organization closed; the node keeps nothing for it and sends it nothing again.
  // The reference's shape and the wire's nested body alike (`device-organization-closed`).
  if (own(answer, "status") === 410 && (own(answer, "code") === "organization-closed" || own(own(own(answer, "body"), "error"), "code") === "organization-closed")) return "stop";
  const code = own(own(own(answer, "body"), "error"), "code");
  const status = own(answer, "status");
  if (!isString(code)) return "hold";
  if (SEND_AFTER.get(code) === status) return "send";
  if (code === "purpose-not-collected" && status === 403) return "hold-notice";
  return DEGRADED_AFTER.get(code) === status ? "hold-degraded" : "hold";
}

// ---- Rules -------------------------------------------------------------------------------------------------------

/**
 * FAC-SEM-117 on one grant: a grant whose `context` is an organization's has a share grant id as its `meta.id`, and its
 * `startsAt` and `expiresAt` carry at most three fraction digits. Called
 * by kind `grant` (`src/context-rules.ts`) and by kind `org-share-grants` for each share grant of a record.
 */
export function shareGrantIdFindings(grant: unknown, at: string): Finding[] {
  if (!isObject(grant) || !isString(grant.context) || !grant.context.startsWith("org:")) return [];
  const findings: Finding[] = [];
  const id = isObject(grant.meta) ? grant.meta.id : undefined;
  if (!isShareGrantId(id)) findings.push({ code: "FAC-SEM-117", instancePath: `${at}/meta/id`, message: "a share grant into an organization is named urn:fabric:share: and 32 lower-case hex digits from a CSPRNG, never a name, an address or an estate id" });
  // The writer's millisecond rule (the fix round): the window a registration carries is the grant's, as written.
  for (const name of ["startsAt", "expiresAt"]) {
    if (isString(grant[name]) && SUB_MILLISECOND.test(grant[name] as string)) findings.push({ code: "FAC-SEM-117", instancePath: `${at}/${name}`, message: "a share grant into an organization carries its window with at most three fraction digits" });
  }
  return findings;
}

/** The agentRefs the placements of `record` in `context` run under the grant `id` (by normal form). */
function agentsUnder(record: JsonObject, context: unknown, id: unknown): Set<string> {
  const placements = list(record.machines).flatMap((machine) => list(machine.packages));
  return new Set(placements.filter((placement) => placement.context === context && isString(id) && sameIdentifier(placement.grant, id)).map((placement) => show(placement.agentRef)));
}

/**
 * FAC-SEM-117 on a record (`{record, parent?}`): each organization share grant's id and window form, one agentRef among
 * the placements naming it, and, against `parent` (the latest earlier revision that placed the grant in its context,
 * so that a move in two steps is caught), the same agentRef as that revision's placements ran under
 * the same grant (DEC-0086, the fix round: moving a share to another agent revokes the grant and mints a new id).
 */
function orgShareGrants(value: JsonObject): Finding[] {
  const record = isObject(value.record) ? value.record : {};
  const parent = isObject(value.parent) ? value.parent : undefined;
  const findings: Finding[] = [];
  for (const [grant, index] of indexed(record.shareGrants)) {
    const at = `/record/shareGrants/${index}`;
    findings.push(...shareGrantIdFindings(grant, at));
    if (!isString(grant.context) || !grant.context.startsWith("org:")) continue;
    const id = isObject(grant.meta) ? grant.meta.id : undefined;
    const refs = agentsUnder(record, grant.context, id);
    if (refs.size > 1) findings.push({ code: "FAC-SEM-117", instancePath: at, message: `the placements naming this grant run ${refs.size} agents: a share grant into an organization runs one agentRef` });
    if (!parent) continue;
    const before = list(parent.shareGrants).find((old) => old.context === grant.context && isObject(old.meta) && isString(id) && sameIdentifier(old.meta.id, id));
    const earlier = before ? agentsUnder(parent, before.context, id) : new Set<string>();
    if (earlier.size > 0 && [...refs].some((ref) => !earlier.has(ref))) {
      findings.push({ code: "FAC-SEM-117", instancePath: at, message: "this grant ran another agent in the earlier revision given as parent: a share grant into an organization keeps its agentRef; move the share by revoking it and minting a new id" });
    }
  }
  return findings;
}

/** FAC-SEM-118 on one document: a registration's instants are readable and an active window ends after it starts. */
function registrationDocument(value: JsonObject): Finding[] {
  if (value.type !== SHARE_REGISTRATION_TYPE) return [];
  const findings: Finding[] = [];
  const flag = (instancePath: string, message: string) => findings.push({ code: "FAC-SEM-118", instancePath, message });
  const names = value.state === "active" ? ["startsAt", "expiresAt"] : ["withdrawnAt"];
  const unreadable = names.filter((name) => !readable(value[name]));
  for (const name of unreadable) flag(`/${name}`, "an instant is an RFC 3339 date-time with an offset, on a day that exists, with at most three fraction digits");
  if (value.state === "active" && !unreadable.length && time(value.startsAt) >= time(value.expiresAt)) flag("/expiresAt", "an active registration's window ends after it starts");
  return findings;
}

/** FAC-SEM-118 on an implementation's answer: it is the reference's, member for member. */
function sameAnswer(answer: unknown, expected: unknown, what: string): Finding[] {
  if (jsonEqual(answer, expected)) return [];
  return [{ code: "FAC-SEM-118", instancePath: "/answer", message: `${what} is not the reference's: ${show(JSON.stringify(expected))}` }];
}

export function shareRegistrationRules(kind: string, value: JsonObject): Finding[] | undefined {
  if (kind === "org-share-grants") return orgShareGrants(value);
  if (kind === "share-registration") return registrationDocument(value);
  if (kind === "share-registration-derive") return sameAnswer(value.answer, deriveShareRegistrations(value.record, value.entries, value.orgId, value.previouslyRegistered), "the derivation");
  if (kind === "share-registration-intake") return sameAnswer(value.answer, decideShareRegistration(value.held, value.registration, value.binding), "the decision");
  if (kind === "grant-usage-join") return sameAnswer(value.answer, joinGrantUsage(value.event, value.binding, value.registrations), "the join");
  return undefined;
}
// #endregion share-registration
