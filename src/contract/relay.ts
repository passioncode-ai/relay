// #region relay — docs: docs/specification/relay.md
/**
 * The relay protocol (`fabric-relay/0.1`, DEC-0047): what a relay and a machine sign and check. The relay is a router
 * with a mailbox and holds no authority — every decision a node relies on is carried by a signature the relay cannot
 * make. This module is the reference for the two signatures the relay itself verifies: the machine's proof of its
 * device key inside the WebSocket (`relay-auth/1`) and a blob request (`relay-blob/1`); and for the message body a
 * recipient verifies end to end (`fabric-relay-message/1`).
 *
 * All three sign RFC 8785 bytes (DEC-0043 register) with ES256, raw `r ‖ s`, base64url, and name the algorithm in a
 * signed `alg` field. A relay participant's `#sig` is ES256 only: an Ed25519 key or another `alg` is `unsupported-alg`.
 * Every key passes SEC 1 validation first (`p256KeyRefusal`), in either form DEC-0053 and this decision use (SEC 1
 * octets or a JWK). Times are RFC 3339 UTC; one that does not parse to a finite instant is refused, never compared.
 */
import { verify as nodeVerify } from "node:crypto";
import { rfc8785 } from "./canonical.js";
import { P256_CURVE, isEd25519Key, isLowS, p256KeyRefusal, type P256Key } from "./p256.js";
import { CLOCK_SKEW_SECONDS, strictTime } from "./rfc3339.js";
import { verifyEstateRecord, type EstateRecordProblem } from "./estate-record-rules.js";
import { isObject, type JsonObject } from "./findings.js";

export const RELAY_PROTOCOL = "fabric-relay/0.1";
export const RELAY_SUBPROTOCOL = "fabric-relay.v1";
export const RELAY_PATH = "/v1/connect";
export const RELAY_ALG = "ES256";
export const MAX_FRAME_BYTES = 1_048_576;
/**
 * The decoded body limit (765 KiB): its base64url (1 044 480 characters) plus the largest rest of a `send` or `deliver`
 * frame — every string member at its schema maximum, each character JSON-escaped to six bytes — stays within
 * MAX_FRAME_BYTES. 768 KiB was exactly 1 MiB of base64 and left no room for the frame around it.
 */
export const MAX_BODY_BYTES = 783_360;
export const MAX_MESSAGE_TTL_SECONDS = 604_800;
export const AUTH_WINDOW_SECONDS = 60;
/** How far ahead of the verifier's clock a signed `iat` may be before it is `not-yet-valid` (shared with the estate record). */
export { CLOCK_SKEW_SECONDS };
export const AUTH_DEADLINE_SECONDS = 10;
export const IDLE_CLOSE_SECONDS = 90;

export const FRAME_TYPES = [
  "hello", "auth", "welcome", "send", "accepted", "deliver", "ack", "presence", "presence-query", "presence-result",
  "delta", "heartbeat", "delta-query", "ping", "pong", "error"
] as const;
export type FrameType = (typeof FRAME_TYPES)[number];

/**
 * Every code a relay `error` frame or blob refusal may carry. `bad-key` is **reserved** since DEC-0066: no relay emits
 * it any more (an unusable admitted key is left out of the admission set and the request is `unauthenticated`); it stays
 * in the list, the frame schema and `closeCodeFor` so that a frame from a relay built before DEC-0066 still validates.
 */
export const RELAY_ERROR_CODES = [
  "protocol-unsupported", "unauthenticated", "not-admitted", "bad-key", "unsupported-alg", "not-yet-valid", "replay",
  "unknown-type", "unknown-recipient", "too-large", "rate-limited", "mailbox-full", "expired", "digest-mismatch", "internal",
  "malformed", "recipients-mismatch"
] as const;
export type RelayErrorCode = (typeof RELAY_ERROR_CODES)[number];

/** WebSocket close codes the relay uses (DEC-0047 item 3, DEC-0066). */
export const CLOSE_CODES = { unauthenticated: 4401, notAdmitted: 4403, tooLarge: 1009, binary: 1003, idle: 1001, policy: 1008, internal: 1011 } as const;

const CLOSE_FOR: Partial<Record<RelayErrorCode, number>> = {
  "protocol-unsupported": CLOSE_CODES.unauthenticated, unauthenticated: CLOSE_CODES.unauthenticated, "unsupported-alg": CLOSE_CODES.unauthenticated,
  "not-yet-valid": CLOSE_CODES.unauthenticated, replay: CLOSE_CODES.unauthenticated, "bad-key": CLOSE_CODES.unauthenticated,
  "not-admitted": CLOSE_CODES.notAdmitted, expired: CLOSE_CODES.notAdmitted,
  "too-large": CLOSE_CODES.tooLarge, "rate-limited": CLOSE_CODES.policy, internal: CLOSE_CODES.internal
};

/**
 * The close code that follows an `error` of this code when the relay closes the connection for it, or undefined when
 * that error leaves the connection open (DEC-0066's table): 4401 for every refusal of `auth` and for the auth deadline
 * — before the signer is proven there is one answer; 4403 only for a proven session whose kid left the admission set
 * (`not-admitted`) or whose held record expired (`expired`); 1009 for a frame over 1 MiB; 1008 for a node that keeps
 * sending after `rate-limited`; 1011 after `internal`. A binary frame closes 1003, and 90 s of silence or a relay
 * shutting down 1001, with no error frame.
 */
export function closeCodeFor(code: RelayErrorCode): number | undefined {
  return CLOSE_FOR[code];
}

export interface AuthFrame { v: 1; type: "auth"; id: string; protocol: string; alg: string; estate: string; kid: string; iat: string; sig: string }
export interface AuthContext {
  relay: string; // this relay's origin, e.g. "https://relay.example"
  // The `estate` of the record this context admits from (its held record), or undefined when it holds none. `admit`
  // compares the signed estate with it and nowhere else: it is never an identifier or a key a connection can see
  // (DEC-0066; a relay keeps sessions, mailboxes, presence and blobs under its own per-context key).
  estate: string | undefined;
  nonce: string; // the nonce this relay sent in `hello` on this connection
  nonceUsed: boolean; // whether that nonce has already admitted a machine
  admittedKey: (kid: string) => P256Key | undefined; // the admission set (DEC-0047 item 3)
  now: Date;
}

/** The bytes a machine signs to prove its device key: `relay-auth/1` over RFC 8785. */
export function relayAuthSigningInput(fields: { relay: string; nonce: string; estate: string; kid: string; iat: string }): string {
  return rfc8785({ type: "relay-auth/1", alg: RELAY_ALG, relay: fields.relay, nonce: fields.nonce, estate: fields.estate, kid: fields.kid, iat: fields.iat });
}

/** The bytes a sender signs for a blob request: `relay-blob/1` over RFC 8785. */
export function relayBlobSigningInput(fields: { relay: string; method: "PUT" | "GET"; digest: string; recipients: string[]; iat: string }): string {
  return rfc8785({ type: "relay-blob/1", alg: RELAY_ALG, relay: fields.relay, method: fields.method, digest: fields.digest, recipients: fields.recipients, iat: fields.iat });
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;

/**
 * The instant of an RFC 3339 UTC string, or undefined (DEC-0066). The relay's pattern is the syntax gate — `Z` only,
 * an upper-case `T`, at most nine fraction digits — and `strictTime` then refuses a day its month does not have, hour
 * 24 and a leap second, which `Date.parse` alone rolls forward ("2026-02-30" would be 2 March).
 */
export function instant(value: unknown): number | undefined {
  if (typeof value !== "string" || !RFC3339.test(value)) return undefined;
  const t = strictTime(value);
  return Number.isNaN(t) ? undefined : t;
}

/**
 * ES256 (raw r ‖ s) under a validated P-256 key in either form: `unsupported-alg` for an Ed25519 key, `bad-key` when the
 * key fails SEC 1, `false` when the signature is not 64 canonical bytes, is not low-S (s > n/2, DEC-0066) or does not
 * verify. Low-S means nobody but the signer can make a second valid encoding of a signature; a signer normalises with
 * `toLowS` or signs with `signEs256`.
 */
export function verifyEs256(key: P256Key, bytes: string, sig: unknown): boolean | "bad-key" | "unsupported-alg" {
  if (isEd25519Key(key)) return "unsupported-alg";
  if (p256KeyRefusal(key) !== null) return "bad-key";
  return proveEs256(key, bytes, sig);
}

const bytes32 = (value: bigint) => Buffer.from(value.toString(16).padStart(64, "0"), "hex");
/**
 * A valid P-256 key nothing signs under (the base point G), in the SEC 1 octet form the admission set holds: the key a
 * pre-proof check validates and verifies under when it has none.
 */
const DUMMY_KEY = new Uint8Array(Buffer.concat([Buffer.from([0x04]), bytes32(P256_CURVE.gx), bytes32(P256_CURVE.gy)]));

/** The JWK of a key SEC 1 already accepted, without validating it again (so every path validates exactly once). */
function jwkOf(key: P256Key): { kty: "EC"; crv: "P-256"; x: string; y: string } {
  if (key instanceof Uint8Array) {
    const octets = Buffer.from(key);
    return { kty: "EC", crv: "P-256", x: octets.subarray(1, 33).toString("base64url"), y: octets.subarray(33).toString("base64url") };
  }
  return { kty: "EC", crv: "P-256", x: key.x as string, y: key.y as string };
}
/** 64 bytes that are no signature, verified in place of a signature that is not 64 canonical bytes. */
const DUMMY_SIG = Buffer.alloc(64, 0x5a);

/**
 * One ES256 verification of equal cost whatever the inputs (DEC-0066): a key that is missing or unusable is replaced by
 * DUMMY_KEY and a signature that is not 64 canonical bytes by DUMMY_SIG, the verification runs once either way, and the
 * low-S rule is applied after it. The answer is true only for a usable key, 64 canonical low-S bytes and a signature
 * that verifies. `admit` and `verifyBlobRequest` call this for every request past its own bytes, so neither the answer
 * nor the work tells an unproven caller whether the relay holds its kid, its estate or a record at all.
 */
function proveEs256(key: P256Key | undefined, bytes: string | undefined, sig: unknown): boolean {
  // One key validation, one verification and one low-S check on every path, combined without short-circuiting.
  const ed = isEd25519Key(key);
  const candidate = key === undefined || ed ? DUMMY_KEY : key;
  const valid = p256KeyRefusal(candidate) === null;
  const usable = key !== undefined && !ed && valid && bytes !== undefined;
  const jwk = jwkOf(valid ? candidate : DUMMY_KEY);
  const raw = typeof sig === "string" ? Buffer.from(sig, "base64url") : DUMMY_SIG;
  const canonical = typeof sig === "string" && raw.length === 64 && raw.toString("base64url") === sig;
  const signature = canonical ? raw : DUMMY_SIG;
  const verified = nodeVerify("sha256", Buffer.from(bytes ?? "", "utf8"), { key: jwk, format: "jwk", dsaEncoding: "ieee-p1363" }, signature);
  const low = isLowS(signature);
  return (Number(usable) & Number(canonical) & Number(verified) & Number(low)) === 1;
}

/** RFC 8785 of a signing input, or undefined when a field has no canonical form (a lone surrogate): it cannot be signed. */
function signable(build: () => string): string | undefined {
  try {
    return build();
  } catch {
    return undefined;
  }
}

/**
 * Every code `admit` refuses with; the shared vectors carry each (DEC-0066). There is no `not-admitted` and no `bad-key`:
 * until the signer is proven, nothing the relay holds may change the answer, so an unknown kid, an unusable admitted
 * key and a bad signature are one `unauthenticated` (DEC-0066, CON-001).
 */
export const ADMIT_REFUSALS = ["protocol-unsupported", "unsupported-alg", "unauthenticated", "not-yet-valid", "replay"] as const;

/**
 * Admits a machine on its `auth` frame (DEC-0047 item 4, DEC-0066), or names why not. The checks that depend only on
 * the frame's own bytes come first (protocol, `alg`, the times); then the nonce; then, as one step with one answer,
 * the kid's key in the admission set and the signature under it. The relay attributes every later frame on the
 * connection to the returned kid and to nothing a frame claims.
 */
export function admit(frame: AuthFrame, ctx: AuthContext): { ok: true; kid: string } | { ok: false; code: RelayErrorCode } {
  if (frame.protocol !== RELAY_PROTOCOL) return { ok: false, code: "protocol-unsupported" };
  if (frame.alg !== RELAY_ALG) return { ok: false, code: "unsupported-alg" };
  const iat = instant(frame.iat);
  if (iat === undefined) return { ok: false, code: "unauthenticated" };
  if (iat - ctx.now.getTime() > CLOCK_SKEW_SECONDS * 1000) return { ok: false, code: "not-yet-valid" };
  if (ctx.now.getTime() - iat > AUTH_WINDOW_SECONDS * 1000) return { ok: false, code: "unauthenticated" };
  if (ctx.nonceUsed) return { ok: false, code: "replay" };
  // The signed estate must be the held record's; a mismatch is the same answer, and the same work — the lookup included,
  // its result discarded — as a bad signature. A kid or estate with no canonical form cannot be signed: the same answer.
  const found = ctx.admittedKey(frame.kid);
  const key = ctx.estate !== undefined && frame.estate === ctx.estate ? found : undefined;
  const input = signable(() => relayAuthSigningInput({ relay: ctx.relay, nonce: ctx.nonce, estate: frame.estate, kid: frame.kid, iat: frame.iat }));
  const proven = proveEs256(key, input, frame.sig);
  return proven ? { ok: true, kid: frame.kid } : { ok: false, code: "unauthenticated" };
}

/**
 * The signed payload of a message body (`fabric-relay-message/1`). `exp` is signed: the recipient judges a message's
 * life by it, never by the `ttl` of the frame, which the relay could change and which only bounds its mailbox.
 */
export interface RelayMessagePayload { type: "fabric-relay-message/1"; from: string; to: string; msgId: string; iat: string; exp: string; payload: unknown }

/** Every refusal `verifyMessageBody` names, in the order it checks; the shared vectors carry each (DEC-0066). */
export const MESSAGE_REFUSALS = [
  "malformed", "unsupported-alg", "unknown-sender", "bad-key", "bad-signature", "mismatch", "not-yet-valid", "lifetime-too-long", "expired",
  "replay"
] as const;
export type MessageRefusal = (typeof MESSAGE_REFUSALS)[number];

/** Whether `bytes` are exactly the RFC 8785 form of `value`; a value that has none (a lone surrogate) is not. */
function isCanonical(value: unknown, bytes: Buffer): boolean {
  try {
    return Buffer.from(rfc8785(value), "utf8").equals(bytes);
  } catch {
    return false;
  }
}

/** The members a message body's payload carries, exactly (DEC-0066). */
const PAYLOAD_MEMBERS = JSON.stringify(["exp", "from", "iat", "msgId", "payload", "to", "type"]);
/** The only members a message body's JWS header may carry; `kid`, when present, is the signed `from`. */
const JWS_HEADER_MEMBERS = new Set(["alg", "typ", "kid"]);
const isRecord = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);

/**
 * A recipient's check of a delivered body (a compact JWS, ES256): the signed `from`, `to` and `msgId` equal what the
 * recipient expects — `from` and `msgId` from the `deliver` frame, and `to` its **own** `#sig` kid, never a value a relay
 * asserts (DEC-0066, CON-012) — `iat` is not ahead of the clock by more than the skew, `exp` follows `iat` by at most 7
 * days and has not passed. The tier (T1/T2) is then the recipient's decision from the verified `from`, never from the
 * connection the frame arrived on (DEC-0047 item 6). `checkReplay` follows it.
 */
export function verifyMessageBody(
  body: string,
  expect: { from: string; to: string; msgId: string },
  senderKey: (kid: string) => P256Key | undefined,
  now: Date
): { ok: true; payload: RelayMessagePayload } | { ok: false; reason: MessageRefusal } {
  const parts = body.split(".");
  if (parts.length !== 3) return { ok: false, reason: "malformed" };
  const headerBytes = Buffer.from(parts[0] as string, "base64url"), payloadBytes = Buffer.from(parts[1] as string, "base64url");
  let header: unknown, payload: unknown;
  try {
    header = JSON.parse(headerBytes.toString("utf8"));
    payload = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (!isRecord(header) || !isRecord(payload)) return { ok: false, reason: "malformed" };
  // Both are their own RFC 8785 bytes (DEC-0066): no duplicate member, no second spelling of the signed document.
  if (!isCanonical(header, headerBytes) || !isCanonical(payload, payloadBytes)) return { ok: false, reason: "malformed" };
  if (header.typ !== "fabric-relay-message+jwt" || payload.type !== "fabric-relay-message/1") return { ok: false, reason: "malformed" };
  // The header is closed (DEC-0066): no `crit` can be honoured, and `jwk`, `jku`, `x5u`, `x5c` or `b64` would let the
  // body name its own key or change what is signed. The payload carries exactly its seven members.
  if (!Object.keys(header).every((member) => JWS_HEADER_MEMBERS.has(member))) return { ok: false, reason: "malformed" };
  if (JSON.stringify(Object.keys(payload).sort()) !== PAYLOAD_MEMBERS) return { ok: false, reason: "malformed" };
  const iat = instant(payload.iat), exp = instant(payload.exp);
  if (typeof payload.from !== "string" || iat === undefined || exp === undefined) return { ok: false, reason: "malformed" };
  if (header.kid !== undefined && header.kid !== payload.from) return { ok: false, reason: "malformed" };
  // Every malformed answer comes first, then the algorithm (relay.md's order).
  if (header.alg !== RELAY_ALG) return { ok: false, reason: "unsupported-alg" };
  const key = senderKey(payload.from);
  if (!key) return { ok: false, reason: "unknown-sender" };
  const verdict = verifyEs256(key, `${parts[0]}.${parts[1]}`, parts[2] as string);
  if (verdict === "bad-key" || verdict === "unsupported-alg") return { ok: false, reason: verdict };
  if (!verdict) return { ok: false, reason: "bad-signature" };
  if (payload.from !== expect.from || payload.to !== expect.to || payload.msgId !== expect.msgId) return { ok: false, reason: "mismatch" };
  if (iat - now.getTime() > CLOCK_SKEW_SECONDS * 1000) return { ok: false, reason: "not-yet-valid" };
  if (exp <= iat || exp - iat > MAX_MESSAGE_TTL_SECONDS * 1000) return { ok: false, reason: "lifetime-too-long" };
  if (now.getTime() >= exp) return { ok: false, reason: "expired" };
  return { ok: true, payload: payload as unknown as RelayMessagePayload };
}

/**
 * The recipient's replay window (DEC-0066, CON-011), after `verifyMessageBody` accepted the body: a recipient keeps
 * each accepted `(from, msgId)` until that body's signed `exp`, and refuses a second delivery of a kept pair as `replay`
 * (it acks the duplicate without acting on it, or the relay redelivers it until its `ttl`). After `exp` the body is
 * `expired` whatever the store holds, so the window is exactly the message's signed life and a relay cannot push a
 * replay past it; an `exp` that is not an instant fails closed as `expired`. `seen` is the recipient's own store; a
 * port keeps it as it likes.
 */
export function checkReplay(
  seen: (from: string, msgId: string) => boolean,
  payload: Pick<RelayMessagePayload, "from" | "msgId" | "exp">,
  now: Date
): { ok: true } | { ok: false; reason: "replay" | "expired" } {
  if (now.getTime() >= (instant(payload.exp) ?? Number.NEGATIVE_INFINITY)) return { ok: false, reason: "expired" };
  return seen(payload.from, payload.msgId) ? { ok: false, reason: "replay" } : { ok: true };
}

/**
 * What a relay admits from: the estate record it holds, which it applies only when the candidate is valid against
 * `estate-record.schema.json` (`schemaValid`) and `verifyEstateRecord` accepts it against the revision held — or, for
 * revision 1, against the passkeys `pinned` when the relay was set up for the estate (DEC-0047 item 4, DEC-0055).
 */
export interface AdmissionInput {
  held?: JsonObject; // the revision the relay verified and applied last, if any
  candidate?: unknown; // a newer revision offered to it
  pinned: readonly unknown[]; // the estate's first passkeys, pinned at setup
  at: Date;
  schemaValid: (record: unknown) => boolean;
  // Revocations the relay applied from verified `revocation-delta/1` entries (DEC-0054 `deltaRevocations`), subtracted
  // like the record's own: `{kind: "machine" | "device-key", ref}` (DEC-0066).
  extraRevocations?: readonly JsonObject[];
}

/** A `#sig` key of the record that the admission set leaves out, and why: it could never verify a relay signature. */
export interface ExcludedKey { kid: string; reason: "unsupported-alg" | "bad-key" }

export type AdmissionResult =
  | { ok: true; held: JsonObject; revision: number; set: Map<string, Uint8Array>; excluded: ExcludedKey[] }
  | { ok: false; refusal: "no-record" | "invalid" | "unverified" | "not-yet-valid" | "expired"; problem?: EstateRecordProblem };

/**
 * The admission set — kid → `#sig` key as SEC 1 octets — of the machines in the verified estate record, minus revoked
 * machines and keys, and minus every key that could never verify a relay signature (an Ed25519 key, or one SEC 1
 * refuses), which `excluded` names for the relay's log; or why there is none. A refused candidate changes nothing: the caller keeps `held`. When the held
 * revision's window has ended the relay fails closed (`expired`): no new `auth` is admitted until a newer verified
 * revision arrives. The organization record has no reference yet (`org-authority/1`, Fabric D8), so an organization's
 * relay has no admission source of its own.
 */
export function relayAdmissionSet(input: AdmissionInput): AdmissionResult {
  let record = input.held;
  if (input.candidate !== undefined) {
    if (!input.schemaValid(input.candidate)) return { ok: false, refusal: "invalid" };
    const verdict = verifyEstateRecord(input.candidate, input.held ? { parent: input.held, at: input.at } : { authorities: input.pinned, at: input.at });
    if (!verdict.ok) return { ok: false, refusal: "unverified", problem: verdict.problem };
    record = input.candidate as JsonObject;
  }
  if (!record) return { ok: false, refusal: "no-record" };
  const now = input.at.getTime();
  // The window is read by the parser verifyEstateRecord uses, so the relay judges it as the record's verifier did.
  const from = strictTime(record.issuedAt), until = strictTime(record.validUntil);
  if (!Number.isFinite(now) || !Number.isFinite(from) || !Number.isFinite(until) || now > until) return { ok: false, refusal: "expired" };
  // A window not yet started is not-yet-valid, within the same skew as verifyEstateRecord (DEC-0066, CON-017).
  if (now < from - CLOCK_SKEW_SECONDS * 1000) return { ok: false, refusal: "not-yet-valid" };
  const list = (value: unknown): JsonObject[] => (Array.isArray(value) ? value.filter(isObject) : []);
  const revocations = [...list(record.revocations), ...list(input.extraRevocations)];
  const revoked = (kind: string) => new Set(revocations.filter((entry) => entry.kind === kind).map((entry) => entry.ref));
  const machines = revoked("machine"), keys = revoked("device-key");
  const set = new Map<string, Uint8Array>();
  const excluded: ExcludedKey[] = [];
  for (const machine of list(record.machines)) {
    if (machines.has(machine.id)) continue;
    for (const key of list(machine.deviceKeys)) {
      if (key.use === "sig" && typeof key.kid === "string" && key.kid.endsWith("#sig") && typeof key.publicKey === "string" && !keys.has(key.kid)) {
        const octets = new Uint8Array(Buffer.from(key.publicKey, "base64"));
        if (isEd25519Key(octets)) excluded.push({ kid: key.kid, reason: "unsupported-alg" });
        else if (p256KeyRefusal(octets) !== null) excluded.push({ kid: key.kid, reason: "bad-key" });
        else set.set(key.kid, octets);
      }
    }
  }
  return { ok: true, held: record, revision: Number(record.revision), set, excluded };
}

// ---- Fabric-Relay-Request: the blob request's wire form (annotated under DEC-0047, 2026-10-12) ----------------------

/** The header a blob request carries; its value is base64url (no padding) of RFC 8785 `{alg, kid, recipients, iat, sig}`. */
export const RELAY_REQUEST_HEADER = "Fabric-Relay-Request";
/** The header value's limit, in bytes; a longer one is refused 431 `too-large` before it is decoded. */
export const MAX_RELAY_REQUEST_BYTES = 8192;
/** Recipients of one blob: 1 to 64 `#sig` kids, each at most 256 characters. */
export const MAX_BLOB_RECIPIENTS = 64;
export const MAX_KID_CHARS = 256;

export interface RelayRequest { alg: string; kid: string; recipients: string[]; iat: string; sig: string }
export type BlobRefusal = { ok: false; status: number; code: RelayErrorCode };
/**
 * Every (status, code) a blob request is refused with by `verifyBlobRequest` and `decideBlobAccess`; the shared vectors
 * carry each (DEC-0066). The relay adds its own steps between them, in the order relay.md gives: 411 and 413 for the
 * length, 413 `too-large` and 422 `digest-mismatch` for the bytes.
 */
export const BLOB_REFUSALS: ReadonlyArray<readonly [number, RelayErrorCode]> = [
  [400, "malformed"], [431, "too-large"], [401, "unsupported-alg"], [401, "not-yet-valid"], [401, "unauthenticated"],
  [403, "unknown-recipient"], [403, "not-admitted"], [409, "recipients-mismatch"]
];
/** The largest blob a relay accepts, in bytes (32 MiB): a declared or counted length above it is 413 `too-large`. */
export const MAX_BLOB_BYTES = 33_554_432;

const REQUEST_MEMBERS = ["alg", "iat", "kid", "recipients", "sig"];
const isSigKid = (value: unknown) => typeof value === "string" && value.length > 0 && value.length <= MAX_KID_CHARS && value.endsWith("#sig");

/**
 * Reads a `Fabric-Relay-Request` value strictly: at most 8192 bytes; canonical base64url without padding (re-encoding
 * the bytes gives the same string); a JSON object whose RFC 8785 serialisation is those exact bytes; exactly the members
 * `alg`, `kid`, `recipients`, `iat`, `sig`, all strings except `recipients`, an array. Anything else is 400 `malformed`.
 * (Distinct recipients and the other limits are `verifyBlobRequest`'s.)
 */
export function parseRelayRequest(value: string | null | undefined): { ok: true; request: RelayRequest } | BlobRefusal {
  if (typeof value !== "string" || value.length === 0) return { ok: false, status: 400, code: "malformed" };
  if (Buffer.byteLength(value, "utf8") > MAX_RELAY_REQUEST_BYTES) return { ok: false, status: 431, code: "too-large" };
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return { ok: false, status: 400, code: "malformed" };
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) return { ok: false, status: 400, code: "malformed" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    return { ok: false, status: 400, code: "malformed" };
  }
  if (!isRecord(parsed) || JSON.stringify(Object.keys(parsed).sort()) !== JSON.stringify(REQUEST_MEMBERS)) return { ok: false, status: 400, code: "malformed" };
  // The bytes must be their own RFC 8785 form, compared as bytes; a value with none (a lone surrogate) is malformed.
  if (!isCanonical(parsed, bytes)) return { ok: false, status: 400, code: "malformed" };
  const { alg, kid, recipients, iat, sig } = parsed;
  if (typeof alg !== "string" || typeof kid !== "string" || typeof iat !== "string" || typeof sig !== "string" || !Array.isArray(recipients)) {
    return { ok: false, status: 400, code: "malformed" };
  }
  return { ok: true, request: { alg, kid, recipients: recipients as string[], iat, sig } };
}

const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const IPV4 = `${OCTET}(?:\\.${OCTET}){3}`;
const H16 = "(?:0|[1-9a-f][0-9a-f]{0,3})";
const IPV6 = [
  `(?:${H16}:){7}${H16}`, `(?:${H16}:){1,7}:`, `(?:${H16}:){1,6}:${H16}`, `(?:${H16}:){1,5}(?::${H16}){1,2}`,
  `(?:${H16}:){1,4}(?::${H16}){1,3}`, `(?:${H16}:){1,3}(?::${H16}){1,4}`, `(?:${H16}:){1,2}(?::${H16}){1,5}`,
  `${H16}:(?::${H16}){1,6}`, `:(?:(?::${H16}){1,7}|:)`
].join("|");
const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
// A host name of at most 253 characters whose last label is not a number (a URL parser reads `0x7f.1` or `relay.1` as IPv4).
const NAME = `(?=[a-z0-9.-]{1,253}(?::|$))(?:${LABEL}\\.)*(?![0-9]+(?::|$))(?!0x[0-9a-f]*(?::|$))${LABEL}`;
const PORT = "(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]\\d{4}|[1-9]\\d{0,3})";
/** The pattern of `hello.relay` in `relay-frame.schema.json`; `isRelayOrigin` is the same rule, and a test holds them equal. */
export const RELAY_ORIGIN_PATTERN =
  `^(?:https://(?:${IPV4}|\\[(?:${IPV6})\\]|${NAME})(?::(?!443$)${PORT})?|http://(?:127\\.${OCTET}\\.${OCTET}\\.${OCTET}|\\[::1\\])(?::(?!80$)${PORT})?)$`;
const RELAY_ORIGIN = new RegExp(RELAY_ORIGIN_PATTERN);

/**
 * What `hello.relay` may be (DEC-0066): a serialised origin and nothing else. https on a lowercase host name of at most
 * 253 characters whose last label is not a number, a dotted IPv4 address, or a bracketed lowercase IPv6 address without
 * leading zeros; or, for a relay on the same machine, http on a loopback literal, 127.0.0.0/8 or `[::1]`. The port is
 * 1 to 65535 without leading zeros and never the scheme's default (443, 80); there is no path or user information. A name such as `localhost` is refused:
 * a name resolves somewhere a literal cannot.
 */
export function isRelayOrigin(value: unknown): boolean {
  return typeof value === "string" && RELAY_ORIGIN.test(value);
}

/**
 * What a relay knows when it checks a blob request. It holds no blob state: whether the relay holds the blob is
 * `decideBlobAccess`'s question, asked only once the signer is proven (DEC-0066, CON-001).
 */
export interface BlobRequestContext {
  relay: string; // this relay's origin
  method: "PUT" | "GET";
  digest: string; // from the path
  now: Date;
  admittedKey: (kid: string) => P256Key | undefined; // the current verified admission set (relayAdmissionSet)
}

/** A blob request whose signer is proven: its kid and the recipient list it signed. */
export interface VerifiedBlobRequest { ok: true; kid: string; recipients: string[] }

/**
 * The relay's check of a blob request's signer (DEC-0047 item 8, its 2026-10-12 annotation, DEC-0066), in order: the
 * header's form (400, 431); `alg` (401 `unsupported-alg`); the recipients (1–64 distinct `#sig` kids, each ≤ 256
 * characters), the signer's kid and `iat` a real instant (400); `iat` within 60 s either way (401 `unauthenticated`,
 * 401 `not-yet-valid`); then, as one step with one answer, the signer's key in the admission set and the signature
 * under it (401 `unauthenticated` for an unknown kid, a revoked one, a relay that holds no record and a bad
 * signature); then, for a PUT, every recipient in the admission set (403 `unknown-recipient`). Until the signer is
 * proven the answer depends only on the request's own bytes. A GET signature reused within its 60 s fetches the same
 * blob for the same machine again, which reveals nothing new.
 */
export function verifyBlobRequest(header: string | null | undefined, ctx: BlobRequestContext): VerifiedBlobRequest | BlobRefusal {
  const parsed = parseRelayRequest(header);
  if (!parsed.ok) return parsed;
  const { alg, kid, recipients, iat, sig } = parsed.request;
  if (alg !== RELAY_ALG) return { ok: false, status: 401, code: "unsupported-alg" };
  if (!isSigKid(kid) || recipients.length < 1 || recipients.length > MAX_BLOB_RECIPIENTS || !recipients.every(isSigKid)
      || new Set(recipients).size !== recipients.length) {
    return { ok: false, status: 400, code: "malformed" };
  }
  const t = instant(iat);
  if (t === undefined) return { ok: false, status: 400, code: "malformed" };
  if (t - ctx.now.getTime() > CLOCK_SKEW_SECONDS * 1000) return { ok: false, status: 401, code: "not-yet-valid" };
  if (ctx.now.getTime() - t > AUTH_WINDOW_SECONDS * 1000) return { ok: false, status: 401, code: "unauthenticated" };
  const key = ctx.admittedKey(kid);
  const proven = proveEs256(key, relayBlobSigningInput({ relay: ctx.relay, method: ctx.method, digest: ctx.digest, recipients, iat }), sig);
  if (!proven) return { ok: false, status: 401, code: "unauthenticated" };
  if (ctx.method === "PUT" && !recipients.every((recipient) => ctx.admittedKey(recipient) !== undefined)) return { ok: false, status: 403, code: "unknown-recipient" };
  return { ok: true, kid, recipients };
}

/**
 * The blob's state, asked only after `verifyBlobRequest` proved the signer (DEC-0066). `stored` is the blob's recipient
 * list when the relay holds it live (not expired, not every recipient done), else undefined. A PUT stores a blob the
 * relay does not hold (`repeat: false`), accepts the same list again (`repeat: true`, 200, restoring a lost object),
 * and refuses another list as 409 `recipients-mismatch` (never merged); the relay asks this after the bytes hash to
 * the digest, so only a holder of the bytes learns that. A GET is answered only to a stored recipient that signed the
 * stored list letter for letter; anything else — not held, expired, not a recipient, another list — is one 403
 * `not-admitted`, never 404.
 */
export function decideBlobAccess(method: "PUT" | "GET", verified: VerifiedBlobRequest, stored: { recipients: readonly string[] } | undefined): { ok: true; repeat: boolean } | BlobRefusal {
  const same = stored !== undefined && JSON.stringify(stored.recipients) === JSON.stringify(verified.recipients);
  if (method === "PUT") return stored === undefined || same ? { ok: true, repeat: same } : { ok: false, status: 409, code: "recipients-mismatch" };
  return same && stored.recipients.includes(verified.kid) ? { ok: true, repeat: false } : { ok: false, status: 403, code: "not-admitted" };
}

/** A `Fabric-Relay-Request` value from its fields: base64url of the RFC 8785 bytes (for senders and vectors). */
export function relayRequestHeader(request: RelayRequest): string {
  return Buffer.from(rfc8785({ alg: request.alg, kid: request.kid, recipients: request.recipients, iat: request.iat, sig: request.sig }), "utf8").toString("base64url");
}
// #endregion relay
