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
import { isEd25519Key, p256Jwk, p256KeyRefusal, type P256Key } from "./p256.js";
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
/** How far ahead of the verifier's clock a signed `iat` may be before it is `not-yet-valid`. */
export const CLOCK_SKEW_SECONDS = 60;
export const AUTH_DEADLINE_SECONDS = 10;
export const IDLE_CLOSE_SECONDS = 90;

export const FRAME_TYPES = [
  "hello", "auth", "welcome", "send", "accepted", "deliver", "ack", "presence", "presence-query",
  "delta", "heartbeat", "delta-query", "ping", "pong", "error"
] as const;
export type FrameType = (typeof FRAME_TYPES)[number];

export const RELAY_ERROR_CODES = [
  "protocol-unsupported", "unauthenticated", "not-admitted", "bad-key", "unsupported-alg", "not-yet-valid", "replay",
  "unknown-type", "unknown-recipient", "too-large", "rate-limited", "mailbox-full", "expired", "digest-mismatch", "internal",
  "malformed", "recipients-mismatch"
] as const;
export type RelayErrorCode = (typeof RELAY_ERROR_CODES)[number];

/** WebSocket close codes the relay uses after an `error` frame. */
export const CLOSE_CODES = { unauthenticated: 4401, notAdmitted: 4403, tooLarge: 1009, binary: 1003, idle: 1001 } as const;

export interface AuthFrame { v: 1; type: "auth"; id: string; protocol: string; alg: string; estate: string; kid: string; iat: string; sig: string }
export interface AuthContext {
  relay: string; // this relay's origin, e.g. "https://relay.example"
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

/** The instant of an RFC 3339 UTC string, or undefined when it does not match or does not parse ("2026-13-45T25:61:61Z"). */
export function instant(value: unknown): number | undefined {
  if (typeof value !== "string" || !RFC3339.test(value)) return undefined;
  const t = Date.parse(value);
  return Number.isFinite(t) ? t : undefined;
}

/**
 * ES256 (raw r ‖ s) under a validated P-256 key in either form: `unsupported-alg` for an Ed25519 key, `bad-key` when the
 * key fails SEC 1, `false` when the signature is not 64 canonical bytes or does not verify.
 */
export function verifyEs256(key: P256Key, bytes: string, sig: string): boolean | "bad-key" | "unsupported-alg" {
  if (isEd25519Key(key)) return "unsupported-alg";
  if (p256KeyRefusal(key) !== null) return "bad-key";
  const raw = Buffer.from(sig, "base64url");
  if (raw.length !== 64 || raw.toString("base64url") !== sig) return false;
  return nodeVerify("sha256", Buffer.from(bytes, "utf8"), { key: p256Jwk(key), format: "jwk", dsaEncoding: "ieee-p1363" }, raw);
}

/**
 * Admits a machine on its `auth` frame (DEC-0047 item 3), or names why not. The relay attributes every later frame on
 * the connection to the returned kid and to nothing a frame claims.
 */
export function admit(frame: AuthFrame, ctx: AuthContext): { ok: true; kid: string } | { ok: false; code: RelayErrorCode } {
  if (frame.protocol !== RELAY_PROTOCOL) return { ok: false, code: "protocol-unsupported" };
  if (frame.alg !== RELAY_ALG) return { ok: false, code: "unsupported-alg" };
  const iat = instant(frame.iat);
  if (iat === undefined) return { ok: false, code: "unauthenticated" };
  if (iat - ctx.now.getTime() > CLOCK_SKEW_SECONDS * 1000) return { ok: false, code: "not-yet-valid" };
  if (ctx.now.getTime() - iat > AUTH_WINDOW_SECONDS * 1000) return { ok: false, code: "unauthenticated" };
  if (ctx.nonceUsed) return { ok: false, code: "replay" };
  const key = ctx.admittedKey(frame.kid);
  if (!key) return { ok: false, code: "not-admitted" };
  const verdict = verifyEs256(key, relayAuthSigningInput({ relay: ctx.relay, nonce: ctx.nonce, estate: frame.estate, kid: frame.kid, iat: frame.iat }), frame.sig);
  if (verdict === "bad-key" || verdict === "unsupported-alg") return { ok: false, code: verdict };
  return verdict ? { ok: true, kid: frame.kid } : { ok: false, code: "unauthenticated" };
}

/**
 * The signed payload of a message body (`fabric-relay-message/1`). `exp` is signed: the recipient judges a message's
 * life by it, never by the `ttl` of the frame, which the relay could change and which only bounds its mailbox.
 */
export interface RelayMessagePayload { type: "fabric-relay-message/1"; from: string; to: string; msgId: string; iat: string; exp: string; payload: unknown }

export type MessageRefusal =
  | "malformed" | "unsupported-alg" | "unknown-sender" | "bad-key" | "bad-signature" | "mismatch"
  | "not-yet-valid" | "lifetime-too-long" | "expired";

const isRecord = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);

/**
 * A recipient's check of a delivered body (a compact JWS, ES256): the signed `from`, `to` and `msgId` equal the frame's,
 * `iat` is not ahead of the clock by more than the skew, `exp` follows `iat` by at most 7 days and has not passed. The
 * tier (T1/T2) is then the recipient's decision from the verified `from`, never from the connection the frame arrived
 * on (DEC-0047 item 6).
 */
export function verifyMessageBody(
  body: string,
  frame: { from: string; to: string; msgId: string },
  senderKey: (kid: string) => P256Key | undefined,
  now: Date
): { ok: true; payload: RelayMessagePayload } | { ok: false; reason: MessageRefusal } {
  const parts = body.split(".");
  if (parts.length !== 3) return { ok: false, reason: "malformed" };
  let header: unknown, payload: unknown;
  try {
    header = JSON.parse(Buffer.from(parts[0] as string, "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1] as string, "base64url").toString("utf8"));
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (!isRecord(header) || !isRecord(payload)) return { ok: false, reason: "malformed" };
  if (header.typ !== "fabric-relay-message+jwt" || payload.type !== "fabric-relay-message/1") return { ok: false, reason: "malformed" };
  if (header.alg !== RELAY_ALG) return { ok: false, reason: "unsupported-alg" };
  const iat = instant(payload.iat), exp = instant(payload.exp);
  if (typeof payload.from !== "string" || iat === undefined || exp === undefined) return { ok: false, reason: "malformed" };
  const key = senderKey(payload.from);
  if (!key) return { ok: false, reason: "unknown-sender" };
  const verdict = verifyEs256(key, `${parts[0]}.${parts[1]}`, parts[2] as string);
  if (verdict === "bad-key" || verdict === "unsupported-alg") return { ok: false, reason: verdict };
  if (!verdict) return { ok: false, reason: "bad-signature" };
  if (payload.from !== frame.from || payload.to !== frame.to || payload.msgId !== frame.msgId) return { ok: false, reason: "mismatch" };
  if (iat - now.getTime() > CLOCK_SKEW_SECONDS * 1000) return { ok: false, reason: "not-yet-valid" };
  if (exp <= iat || exp - iat > MAX_MESSAGE_TTL_SECONDS * 1000) return { ok: false, reason: "lifetime-too-long" };
  if (now.getTime() >= exp) return { ok: false, reason: "expired" };
  return { ok: true, payload: payload as unknown as RelayMessagePayload };
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
}

export type AdmissionResult =
  | { ok: true; held: JsonObject; revision: number; set: Map<string, Uint8Array> }
  | { ok: false; refusal: "no-record" | "invalid" | "unverified" | "expired"; problem?: EstateRecordProblem };

/**
 * The admission set — kid → `#sig` key as SEC 1 octets — of the machines in the verified estate record, minus revoked
 * machines and keys; or why there is none. A refused candidate changes nothing: the caller keeps `held`. When the held
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
  const from = Date.parse(String(record.issuedAt)), until = Date.parse(String(record.validUntil));
  if (!Number.isFinite(now) || !Number.isFinite(from) || !Number.isFinite(until) || now < from || now > until) return { ok: false, refusal: "expired" };
  const list = (value: unknown): JsonObject[] => (Array.isArray(value) ? value.filter(isObject) : []);
  const revoked = (kind: string) => new Set(list(record.revocations).filter((entry) => entry.kind === kind).map((entry) => entry.ref));
  const machines = revoked("machine"), keys = revoked("device-key");
  const set = new Map<string, Uint8Array>();
  for (const machine of list(record.machines)) {
    if (machines.has(machine.id)) continue;
    for (const key of list(machine.deviceKeys)) {
      if (key.use === "sig" && typeof key.kid === "string" && key.kid.endsWith("#sig") && typeof key.publicKey === "string" && !keys.has(key.kid)) {
        set.set(key.kid, Buffer.from(key.publicKey, "base64"));
      }
    }
  }
  return { ok: true, held: record, revision: Number(record.revision), set };
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
  // Whatever JSON.parse returns has an RFC 8785 form, so this cannot throw; the bytes must be that form exactly.
  if (rfc8785(parsed) !== bytes.toString("utf8")) return { ok: false, status: 400, code: "malformed" };
  const { alg, kid, recipients, iat, sig } = parsed;
  if (typeof alg !== "string" || typeof kid !== "string" || typeof iat !== "string" || typeof sig !== "string" || !Array.isArray(recipients)) {
    return { ok: false, status: 400, code: "malformed" };
  }
  return { ok: true, request: { alg, kid, recipients: recipients as string[], iat, sig } };
}

/** What a relay knows when it checks a blob request. */
export interface BlobRequestContext {
  relay: string; // this relay's origin
  method: "PUT" | "GET";
  digest: string; // from the path
  now: Date;
  admittedKey: (kid: string) => P256Key | undefined; // the current verified admission set (relayAdmissionSet)
  stored?: { recipients: string[] }; // the blob's recipient list, when the relay already holds the blob
}

/**
 * The relay's check of a blob request (DEC-0047 item 8 and its 2026-10-12 annotation), in order: the header's form;
 * `alg`; the recipients (1–64 distinct `#sig` kids, each ≤ 256 characters) and the signer's kid; `iat` (60 s either way); who may
 * ask — a PUT's signer and every recipient in the admission set, a GET's signer in the admission set and in the stored
 * recipients, with the signed list equal to the stored one letter for letter; a PUT of a held blob with another list
 * is 409 `recipients-mismatch`; then the signature. A GET signature reused within its 60 s fetches the same blob for
 * the same machine again, which reveals nothing new.
 */
export function verifyBlobRequest(header: string | null | undefined, ctx: BlobRequestContext): { ok: true; kid: string; recipients: string[]; repeat: boolean } | BlobRefusal {
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
  if (!key) return { ok: false, status: 403, code: "not-admitted" };
  const same = ctx.stored !== undefined && JSON.stringify(ctx.stored.recipients) === JSON.stringify(recipients);
  if (ctx.method === "PUT") {
    if (!recipients.every((recipient) => ctx.admittedKey(recipient) !== undefined)) return { ok: false, status: 403, code: "unknown-recipient" };
    if (ctx.stored !== undefined && !same) return { ok: false, status: 409, code: "recipients-mismatch" };
  } else if (ctx.stored === undefined || !ctx.stored.recipients.includes(kid) || !same) {
    return { ok: false, status: 403, code: "not-admitted" };
  }
  const verdict = verifyEs256(key, relayBlobSigningInput({ relay: ctx.relay, method: ctx.method, digest: ctx.digest, recipients, iat }), sig);
  if (verdict === "bad-key") return { ok: false, status: 403, code: "bad-key" };
  if (verdict === "unsupported-alg") return { ok: false, status: 401, code: "unsupported-alg" };
  if (!verdict) return { ok: false, status: 401, code: "unauthenticated" };
  return { ok: true, kid, recipients, repeat: ctx.method === "PUT" && same };
}

/** A `Fabric-Relay-Request` value from its fields: base64url of the RFC 8785 bytes (for senders and vectors). */
export function relayRequestHeader(request: RelayRequest): string {
  return Buffer.from(rfc8785({ alg: request.alg, kid: request.kid, recipients: request.recipients, iat: request.iat, sig: request.sig }), "utf8").toString("base64url");
}
// #endregion relay
