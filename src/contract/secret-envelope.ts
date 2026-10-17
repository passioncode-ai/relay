// #region secret-envelope — docs: docs/specification/relay.md#the-secret-envelope
/**
 * The secret envelope (`fabric-secret-envelope/1`, DEC-0047): a secret sealed to one machine's key-agreement key by
 * the machine that holds its slot, carried by a relay as a blob, opened only in the target's vault.
 *
 * Seal: HPKE (RFC 9180) base mode, DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM — suite 0x0010/0x0001/0x0001,
 * checked against RFC 9180 §A.3.1. The header is the AEAD's additional data and names its signature algorithm
 * (`alg: "ES256"`); the sender signs `{header, ct}` (ES256, RFC 8785 bytes). Every key passes SEC 1 validation
 * (`p256KeyRefusal`) before it is used, in either form (SEC 1 octets as DEC-0053 records them, or a JWK).
 */
import { PERSONAL_CONTEXT } from "./context-route.js";
import { createCipheriv, createDecipheriv, createECDH, createHash, createHmac, type KeyObject } from "node:crypto";
import { rfc8785 } from "./canonical.js";
import { isEd25519Key, p256KeyRefusal, p256Point, signEs256, type P256Key } from "./p256.js";
import { CLOCK_SKEW_SECONDS, RELAY_ALG, instant, verifyEs256 } from "./relay.js";
import { isObject, type JsonObject } from "./findings.js";

export const ENVELOPE_TYPE = "fabric-secret-envelope/1";
export const ENVELOPE_SUITE = [16, 1, 1] as const; // kem_id, kdf_id, aead_id
export const MAX_ENVELOPE_LIFETIME_SECONDS = 86_400;
const INFO = Buffer.from(ENVELOPE_TYPE, "ascii");

// ---- HPKE base mode for the one suite the contract admits -------------------------------------------------------

const i2osp = (value: number, length: number) => {
  const out = Buffer.alloc(length);
  out.writeUIntBE(value, 0, length);
  return out;
};
const KEM_SUITE = Buffer.concat([Buffer.from("KEM"), i2osp(16, 2)]);
const HPKE_SUITE = Buffer.concat([Buffer.from("HPKE"), i2osp(16, 2), i2osp(1, 2), i2osp(1, 2)]);
const V1 = Buffer.from("HPKE-v1");

const extract = (salt: Buffer, ikm: Buffer) => createHmac("sha256", salt.length ? salt : Buffer.alloc(32)).update(ikm).digest();
function expand(prk: Buffer, info: Buffer, length: number): Buffer {
  const blocks: Buffer[] = [];
  let previous = Buffer.alloc(0);
  for (let i = 1; Buffer.concat(blocks).length < length; i += 1) {
    previous = createHmac("sha256", prk).update(Buffer.concat([previous, info, Buffer.from([i])])).digest();
    blocks.push(previous);
  }
  return Buffer.concat(blocks).subarray(0, length);
}
const labeledExtract = (suite: Buffer, salt: Buffer, label: string, ikm: Buffer) =>
  extract(salt, Buffer.concat([V1, suite, Buffer.from(label), ikm]));
const labeledExpand = (suite: Buffer, prk: Buffer, label: string, info: Buffer, length: number) =>
  expand(prk, Buffer.concat([i2osp(length, 2), V1, suite, Buffer.from(label), info]), length);

function sharedSecret(dh: Buffer, enc: Buffer, pkR: Buffer): Buffer {
  const prk = labeledExtract(KEM_SUITE, Buffer.alloc(0), "eae_prk", dh);
  return labeledExpand(KEM_SUITE, prk, "shared_secret", Buffer.concat([enc, pkR]), 32);
}

function keySchedule(shared: Buffer, info: Buffer): { key: Buffer; baseNonce: Buffer } {
  const pskIdHash = labeledExtract(HPKE_SUITE, Buffer.alloc(0), "psk_id_hash", Buffer.alloc(0));
  const infoHash = labeledExtract(HPKE_SUITE, Buffer.alloc(0), "info_hash", info);
  const context = Buffer.concat([Buffer.from([0]), pskIdHash, infoHash]);
  const secret = labeledExtract(HPKE_SUITE, shared, "secret", Buffer.alloc(0));
  return { key: labeledExpand(HPKE_SUITE, secret, "key", context, 16), baseNonce: labeledExpand(HPKE_SUITE, secret, "base_nonce", context, 12) };
}

/** HPKE SealBase with sequence number 0. `skE` (32 bytes) fixes the ephemeral key for vectors; omit it otherwise. */
export function hpkeSealBase(pkR: Buffer, info: Buffer, aad: Buffer, pt: Buffer, skE?: Buffer): { enc: Buffer; ct: Buffer } {
  const ephemeral = createECDH("prime256v1");
  if (skE) ephemeral.setPrivateKey(skE);
  else ephemeral.generateKeys();
  const enc = ephemeral.getPublicKey(null, "uncompressed");
  const { key, baseNonce } = keySchedule(sharedSecret(ephemeral.computeSecret(pkR), enc, pkR), info);
  const cipher = createCipheriv("aes-128-gcm", key, baseNonce);
  cipher.setAAD(aad);
  return { enc, ct: Buffer.concat([cipher.update(pt), cipher.final(), cipher.getAuthTag()]) };
}

/** HPKE OpenBase with sequence number 0; throws when the ciphertext, the header or the key does not match. */
export function hpkeOpenBase(skR: Buffer, enc: Buffer, info: Buffer, aad: Buffer, ct: Buffer): Buffer {
  const recipient = createECDH("prime256v1");
  recipient.setPrivateKey(skR);
  const pkR = recipient.getPublicKey(null, "uncompressed");
  const { key, baseNonce } = keySchedule(sharedSecret(recipient.computeSecret(enc), enc, pkR), info);
  const decipher = createDecipheriv("aes-128-gcm", key, baseNonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]);
}

// ---- The envelope ------------------------------------------------------------------------------------------------

export interface EnvelopeHeader {
  type: typeof ENVELOPE_TYPE;
  alg: typeof RELAY_ALG; // the sender's signature algorithm, signed with everything else
  suite: number[];
  recipient: string; // the target's key-agreement kid (`#kem`)
  sender: string; // the sealing machine's signing kid (`#sig`)
  agentRef: string; // the placed agent the slot belongs to (DEC-0050): a slot name alone is ambiguous across agents
  slot: string; // the credential's name, never its value
  placement: number; // the estate revision that placed this secret on the target
  envelopeSequence: number; // the sealer's sequence for (agentRef, slot), 1 to 2^53 − 1 (DEC-0066)
  iat: string; // RFC 3339 UTC
  exp: string;
  enc: string; // base64url, the HPKE encapsulated key
}
export interface SecretEnvelope { header: EnvelopeHeader; ct: string; sig: string }

/** Every refusal `openEnvelope` names, in the order it checks; the shared vectors carry each (DEC-0066). */
export const ENVELOPE_REFUSALS = [
  "malformed", "unsupported-alg", "wrong-recipient", "bad-key", "bad-signature", "sender-not-allowed",
  "placement-stale", "replayed", "sequence-reused", "not-yet-valid", "lifetime-too-long", "expired", "cannot-open"
] as const;
export type EnvelopeRefusal = (typeof ENVELOPE_REFUSALS)[number];
const signingInput = (envelope: { header: EnvelopeHeader; ct: string }) => Buffer.from(rfc8785({ header: envelope.header, ct: envelope.ct }), "utf8");

/** `sha256:` and the hex SHA-256 of the envelope's RFC 8785 bytes: the name a relay stores it under. */
export function envelopeDigest(envelope: SecretEnvelope): string {
  return `sha256:${createHash("sha256").update(rfc8785(envelope), "utf8").digest("hex")}`;
}

export interface SealInput {
  recipientKid: string;
  recipientKey: P256Key; // the target's `#kem` public key, SEC 1 octets or a JWK
  senderKid: string;
  senderKey: KeyObject; // the sender's ES256 private key
  agentRef: string;
  slot: string;
  placement: number;
  // The sealer's next sequence for (agentRef, slot): the last it sealed plus one, kept durably beside its vault slot,
  // or max(last + 1, now in ms) after it lost that record. Never one it used: a re-send sends the stored envelope.
  envelopeSequence: number;
  iat: Date;
  exp: Date;
  secret: Buffer;
  ephemeralPrivateKey?: Buffer; // vectors only
}

export function sealEnvelope(input: SealInput): SecretEnvelope {
  // A secret is sealed only to a key-agreement key and signed only by a signing key: the kids say which is which.
  if (!input.recipientKid.endsWith("#kem")) throw new Error("wrong-recipient: an envelope is sealed to a #kem key");
  if (!input.senderKid.endsWith("#sig")) throw new Error("bad-key: an envelope is signed by a #sig key");
  if (p256KeyRefusal(input.recipientKey) !== null) throw new Error("bad-key: the recipient key is not a valid P-256 key");
  if (!counter(input.envelopeSequence)) throw new Error("malformed: envelopeSequence is an integer from 1 to 2^53 - 1");
  const pkR = p256Point(input.recipientKey);
  const partial = {
    type: ENVELOPE_TYPE, alg: RELAY_ALG, suite: [...ENVELOPE_SUITE], recipient: input.recipientKid, sender: input.senderKid, agentRef: input.agentRef, slot: input.slot,
    placement: input.placement, envelopeSequence: input.envelopeSequence, iat: input.iat.toISOString().replace(/\.\d{3}Z$/, "Z"), exp: input.exp.toISOString().replace(/\.\d{3}Z$/, "Z")
  };
  // The encapsulated key is part of the header the AEAD authenticates, so it is computed first and sealed under.
  const ephemeral = createECDH("prime256v1");
  if (input.ephemeralPrivateKey) ephemeral.setPrivateKey(input.ephemeralPrivateKey);
  else ephemeral.generateKeys();
  const header: EnvelopeHeader = { ...partial, enc: ephemeral.getPublicKey(null, "uncompressed").toString("base64url") } as EnvelopeHeader;
  // A sealer never consumes a sequence on an envelope every target refuses: the shape (with a placeholder ct and sig)
  // and the life, both read to the whole second as written, are checked before anything is sealed or signed.
  if (!envelopeShape({ header, ct: "AA", sig: "A".repeat(86) })) throw new Error("malformed: the envelope would not have the schema's shape");
  const life = (instant(header.exp) as number) - (instant(header.iat) as number);
  if (life <= 0 || life > MAX_ENVELOPE_LIFETIME_SECONDS * 1000) throw new Error("lifetime-too-long: an envelope lives more than zero and at most 24 hours");
  const { ct } = hpkeSealBase(pkR, INFO, Buffer.from(rfc8785(header), "utf8"), input.secret, ephemeral.getPrivateKey());
  const unsigned = { header, ct: ct.toString("base64url") };
  const sig = signEs256(input.senderKey, signingInput(unsigned));
  return { ...unsigned, sig };
}

export interface OpenContext {
  ownKemKid: string;
  ownKemPrivateKey: Buffer; // 32 bytes
  senderKey: (kid: string) => P256Key | undefined; // the estate record's `#sig` key for a machine
  // The estate record (`estate-record/1`, DEC-0055) lets this machine hold the agent's slot: the target's placement of
  // (agentRef, slot) names the sender's machine as its `from`. `estateEnvelopeContext` derives both from the record.
  mayHold: (senderKid: string, agentRef: string, slot: string) => boolean;
  // The revision from which the target's current placement of (agentRef, slot) holds unchanged, in the latest revision
  // the target verified and applied; an envelope sealed under an older placement is stale.
  currentPlacement: (agentRef: string, slot: string) => number | undefined;
  // The latest estate-record revision the target verified and applied. An envelope placed by a newer revision is
  // `placement-stale` until the target has fetched and verified that revision itself.
  appliedRevision: () => number | undefined;
  // The target's mark for (agentRef, slot), written with the secret in one transaction: the placement run it belongs
  // to (`since`, the current placement when it was written), the sequence and the envelope's digest. Required; a
  // target that keeps no marks is not conformant (DEC-0066).
  lastOpened: (agentRef: string, slot: string) => EnvelopeMark | undefined;
  now: Date;
}

/** A target's mark of the last envelope it opened for one (agentRef, slot). */
export interface EnvelopeMark { since: number; sequence: number; digest: string }

const HEADER_MEMBERS = ["agentRef", "alg", "enc", "envelopeSequence", "exp", "iat", "placement", "recipient", "sender", "slot", "suite", "type"];
const AGENT_REF = /^urn:fabric:agent:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const SLOT = /^[A-Z][A-Z0-9_]{0,63}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const SIG = /^[A-Za-z0-9_-]{86}$/;
const sameMembers = (value: Record<string, unknown>, members: readonly string[]) => JSON.stringify(Object.keys(value).sort()) === JSON.stringify(members);
const kid = (value: unknown) => typeof value === "string" && value.length >= 1 && value.length <= 256;
const counter = (value: unknown) => Number.isSafeInteger(value) && (value as number) >= 1;

/**
 * Whether a value has exactly the shape `secret-envelope.schema.json` gives, with `iat` and `exp` real instants (a
 * schema cannot say that a day exists): `{header, ct, sig}` and nothing else; the header's twelve members and nothing
 * else; `type` and `suite` the constants; `recipient` and `sender` 1–256 characters; `agentRef` and `slot` their
 * patterns; `placement` and `envelopeSequence` integers from 1 to 2^53 − 1; `enc` and `ct` base64url; `sig` 86
 * characters. A parity test holds it equal to the schema over every fixture and vector (DEC-0066, CON-005).
 */
export function envelopeShape(value: unknown): value is SecretEnvelope {
  if (!isObject(value) || !sameMembers(value, ["ct", "header", "sig"]) || !isObject(value.header)) return false;
  const h = value.header;
  return sameMembers(h, HEADER_MEMBERS) && h.type === ENVELOPE_TYPE && typeof h.alg === "string" && JSON.stringify(h.suite) === JSON.stringify(ENVELOPE_SUITE)
    && kid(h.recipient) && kid(h.sender) && typeof h.agentRef === "string" && h.agentRef.length <= 146 && AGENT_REF.test(h.agentRef)
    && typeof h.slot === "string" && SLOT.test(h.slot) && counter(h.placement) && counter(h.envelopeSequence)
    && instant(h.iat) !== undefined && instant(h.exp) !== undefined && typeof h.enc === "string" && B64URL.test(h.enc)
    && typeof value.ct === "string" && B64URL.test(value.ct) && typeof value.sig === "string" && SIG.test(value.sig);
}

/**
 * Opens an envelope only when every check of DEC-0047 item 7, as DEC-0066 amends it, holds; otherwise names the first
 * that failed. On success it returns the mark the target writes with the secret, in one transaction; nothing is
 * stored after a refusal.
 */
export function openEnvelope(value: unknown, ctx: OpenContext): { ok: true; secret: Buffer; mark: EnvelopeMark & { agentRef: string; slot: string } } | { ok: false; refusal: EnvelopeRefusal } {
  if (!envelopeShape(value)) return { ok: false, refusal: "malformed" };
  const { header } = value;
  if (header.alg !== RELAY_ALG) return { ok: false, refusal: "unsupported-alg" };
  if (header.recipient !== ctx.ownKemKid) return { ok: false, refusal: "wrong-recipient" };
  const senderKey = ctx.senderKey(header.sender);
  if (senderKey && isEd25519Key(senderKey)) return { ok: false, refusal: "unsupported-alg" };
  const encPoint = Buffer.from(header.enc, "base64url");
  if (!senderKey || p256KeyRefusal(senderKey) !== null || p256KeyRefusal(encPoint) !== null) return { ok: false, refusal: "bad-key" };
  // One verifier for the relay family: 64 canonical bytes, low-S, and the signature (DEC-0066).
  if (verifyEs256(senderKey, rfc8785({ header: value.header, ct: value.ct }), value.sig) !== true) return { ok: false, refusal: "bad-signature" };
  if (!ctx.mayHold(header.sender, header.agentRef, header.slot)) return { ok: false, refusal: "sender-not-allowed" };
  const current = ctx.currentPlacement(header.agentRef, header.slot);
  const applied = ctx.appliedRevision();
  if (current === undefined || applied === undefined || header.placement < current || header.placement > applied) {
    return { ok: false, refusal: "placement-stale" };
  }
  // Anti-rollback (DEC-0066, CON-003): the mark of this placement run. An equal sequence passes only for the same
  // envelope (a repeat delivery); another envelope at it is sequence-reused. A mark ahead of the run fails closed.
  const digest = envelopeDigest(value);
  const mark = ctx.lastOpened(header.agentRef, header.slot);
  if (mark !== undefined && mark.since >= current) {
    if (mark.since > current || header.envelopeSequence < mark.sequence) return { ok: false, refusal: "replayed" };
    if (header.envelopeSequence === mark.sequence && mark.digest !== digest) return { ok: false, refusal: "sequence-reused" };
  }
  const iat = instant(header.iat) as number, exp = instant(header.exp) as number;
  if (iat - ctx.now.getTime() > CLOCK_SKEW_SECONDS * 1000) return { ok: false, refusal: "not-yet-valid" };
  if (exp <= iat || exp - iat > MAX_ENVELOPE_LIFETIME_SECONDS * 1000) return { ok: false, refusal: "lifetime-too-long" };
  if (ctx.now.getTime() >= exp) return { ok: false, refusal: "expired" };
  try {
    const secret = hpkeOpenBase(ctx.ownKemPrivateKey, encPoint, INFO, Buffer.from(rfc8785(header), "utf8"), Buffer.from(value.ct, "base64url"));
    return { ok: true, secret, mark: { agentRef: header.agentRef, slot: header.slot, since: current, sequence: header.envelopeSequence, digest } };
  } catch {
    return { ok: false, refusal: "cannot-open" };
  }
}

// ---- The open context from the estate record (DEC-0055) -------------------------------------------------------------

const list = (value: unknown): JsonObject[] => (Array.isArray(value) ? value.filter(isObject) : []);
const revokedRefs = (record: JsonObject, kind: string) =>
  new Set(list(record.revocations).filter((entry) => entry.kind === kind).map((entry) => entry.ref));

/**
 * The `from` of a machine's personal placement of (agentRef, slot) in one revision, or undefined. Only a personal
 * secret placement (no `context`, or `personal`) is read (DEC-0082): an envelope names no context, and an organization's
 * instance fills its slot on its own machine, never by an envelope (the estate record's slot rule), so the answer never depends on the
 * order of the record's secret placements.
 */
function placedFrom(record: JsonObject, machineId: string, agentRef: string, slot: string): unknown {
  const machine = list(record.machines).find((entry) => entry.id === machineId);
  return list(machine?.secrets).find((secret) => secret.agentRef === agentRef && secret.slot === slot && (secret.context === undefined || secret.context === PERSONAL_CONTEXT))?.from;
}

/** A machine's `#sig` key in one revision, as its kid and SEC 1 octets; none when the machine or the key is revoked. */
function signingKey(record: JsonObject, machineId: unknown): { kid: string; key: Uint8Array } | undefined {
  if (revokedRefs(record, "machine").has(machineId)) return undefined;
  const machine = list(record.machines).find((entry) => entry.id === machineId);
  const key = list(machine?.deviceKeys).find((entry) => entry.use === "sig" && typeof entry.kid === "string" && entry.kid.endsWith("#sig"));
  if (!key || typeof key.publicKey !== "string" || revokedRefs(record, "device-key").has(key.kid)) return undefined;
  return { kid: key.kid as string, key: Buffer.from(key.publicKey, "base64") };
}

/**
 * The three record-bound members of `OpenContext` for the machine `machineId`, from the estate-record revisions it has
 * verified (`verifyEstateRecord`) and applied, oldest first. The latest revision decides who may hold an agent's slot
 * and under which `#sig` key; the current placement is the earliest revision of the unbroken run, ending at the latest,
 * in which the placement names the same `from` — so an envelope sealed after the placement was made opens, and one
 * sealed under a placement since replaced is `placement-stale`.
 */
export function estateEnvelopeContext(applied: readonly JsonObject[], machineId: string): Pick<OpenContext, "mayHold" | "currentPlacement" | "senderKey" | "appliedRevision"> {
  const latest = applied[applied.length - 1];
  return {
    appliedRevision: () => (latest ? Number(latest.revision) : undefined),
    mayHold: (senderKid, agentRef, slot) => {
      if (!latest) return false;
      const from = placedFrom(latest, machineId, agentRef, slot);
      return from !== undefined && signingKey(latest, from)?.kid === senderKid;
    },
    currentPlacement: (agentRef, slot) => {
      if (!latest) return undefined;
      const from = placedFrom(latest, machineId, agentRef, slot);
      if (from === undefined) return undefined;
      let since = applied.length - 1;
      while (since > 0 && placedFrom(applied[since - 1] as JsonObject, machineId, agentRef, slot) === from) since -= 1;
      return Number((applied[since] as JsonObject).revision);
    },
    senderKey: (kid) => {
      if (!latest) return undefined;
      for (const machine of list(latest.machines)) {
        const key = signingKey(latest, machine.id);
        if (key?.kid === kid) return key.key;
      }
      return undefined;
    }
  };
}
// #endregion secret-envelope
