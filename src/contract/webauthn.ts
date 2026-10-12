import { createHash, createPublicKey, verify as verifySignature, type KeyObject } from "node:crypto";
import { isSmallOrderKey } from "./ed25519.js";
import { type JsonObject, isObject } from "./findings.js";
import { isValidP256Key } from "./p256.js";

// #region webauthn — docs: docs/specification/estate-record.md#the-signature
/**
 * Offline verification of a passkey assertion (W3C Web Authentication Level 3, Recommendation 2026-08-25, §7.2), as
 * the estate record's signature uses it (DEC-0055). What it checks: clientDataJSON's `type`, `challenge` and
 * `origin`, no cross-origin use, the authenticator data's `rpIdHash` and its UP and UV flags, and the signature over
 * `authenticatorData ‖ SHA-256(clientDataJSON)` under the credential public key the verifier already trusts. What it
 * does not: attestation (an assertion carries none), the authenticator's provenance or AAGUID, the signature counter
 * (passkeys sync between devices and machines do not share a counter), extension outputs, and how the credential
 * was enrolled — the caller supplies a key it pinned.
 */

/** The algorithms admitted (v4 rule 12 puts passkeys on P-256): ES256 is COSE −7, EdDSA COSE −8 with Ed25519. */
export const ASSERTION_ALGORITHMS: readonly string[] = ["ES256", "EdDSA"];

/** A trusted credential: its algorithm, its public JWK, its RP ID and the origins a ceremony may run in. */
export interface PasskeyCredential {
  credentialId: string;
  alg: string;
  publicKey: JsonObject;
  rpId: string;
  origins: readonly string[];
}

/** An assertion response as recorded: base64url fields, without the user handle. */
export interface Assertion {
  credentialId: string;
  alg: string;
  authenticatorData: string;
  clientDataJSON: string;
  sig: string;
}

export type AssertionProblem =
  | "malformed"
  | "unknown-algorithm"
  | "key-algorithm-mismatch"
  | "unusable-key"
  | "small-order-key"
  | "wrong-type"
  | "wrong-challenge"
  | "wrong-origin"
  | "cross-origin"
  | "wrong-rp"
  | "bad-flags"
  | "no-user-presence"
  | "no-user-verification"
  | "bad-signature";

export type AssertionVerdict = { ok: true; flags: number; signCount: number } | { ok: false; problem: AssertionProblem };

const B64URL = /^[A-Za-z0-9_-]+$/;
const isString = (value: unknown): value is string => typeof value === "string";
const bytes = (text: string) => Buffer.from(text, "base64url");
/** Whether `text` is the one canonical unpadded base64url form of its bytes, so two verifiers never disagree on a key. */
const canonical = (text: string) => Buffer.from(text, "base64url").toString("base64url") === text;

/** Flag bits of the authenticator data (§6.1). */
export const FLAGS = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40, ED: 0x80 } as const;

/**
 * The credential's public key, validated before use: a P-256 point valid by SEC 1 §3.2.2 (`isValidP256Key`) for ES256,
 * an Ed25519 key of full order (`isSmallOrderKey`, DEC-0045) for EdDSA.
 */
export function credentialKey(publicKey: unknown, alg: string): { key: KeyObject } | { problem: "unusable-key" | "small-order-key" } {
  if (!ASSERTION_ALGORITHMS.includes(alg)) return { problem: "unusable-key" };
  if (!isObject(publicKey) || publicKey.d !== undefined || !isString(publicKey.x) || !B64URL.test(publicKey.x) || !canonical(publicKey.x)) return { problem: "unusable-key" };
  if (alg === "ES256") {
    if (publicKey.kty !== "EC" || publicKey.crv !== "P-256" || !isString(publicKey.y) || !B64URL.test(publicKey.y) || !canonical(publicKey.y)) return { problem: "unusable-key" };
    const x = bytes(publicKey.x);
    const y = bytes(publicKey.y);
    if (x.length !== 32 || y.length !== 32 || !isValidP256Key(Buffer.concat([Buffer.from([4]), x, y]))) return { problem: "unusable-key" };
    return { key: createPublicKey({ key: { kty: "EC", crv: "P-256", x: publicKey.x, y: publicKey.y }, format: "jwk" }) };
  }
  if (publicKey.kty !== "OKP" || publicKey.crv !== "Ed25519") return { problem: "unusable-key" };
  const raw = bytes(publicKey.x);
  if (raw.length !== 32) return { problem: "unusable-key" };
  // DEC-0045 (CT-29): a small-order key verifies forged signatures on Node 20 and 22; it is refused before any use.
  if (isSmallOrderKey(raw)) return { problem: "small-order-key" };
  return { key: createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: publicKey.x }, format: "jwk" }) };
}

/**
 * Verify `assertion` under `credential` for the expected `challenge` bytes, in this order: shape, algorithm, key,
 * client data (type, challenge, origin, cross-origin), authenticator data (length, rpIdHash, flags), signature.
 * `credential.credentialId` must equal the assertion's; the caller picks the credential by it.
 */
export function verifyAssertion(assertion: unknown, credential: PasskeyCredential, challenge: Uint8Array): AssertionVerdict {
  if (!isObject(assertion)) return { ok: false, problem: "malformed" };
  const { credentialId, alg, authenticatorData, clientDataJSON, sig } = assertion;
  for (const field of [credentialId, alg, authenticatorData, clientDataJSON, sig]) if (!isString(field)) return { ok: false, problem: "malformed" };
  if (![credentialId, authenticatorData, clientDataJSON, sig].every((field) => B64URL.test(field as string))) return { ok: false, problem: "malformed" };
  if (credentialId !== credential.credentialId) return { ok: false, problem: "malformed" };
  if (!ASSERTION_ALGORITHMS.includes(alg as string)) return { ok: false, problem: "unknown-algorithm" };
  // v4 rule 12: a credential names its algorithm and a verifier accepts only that one for it.
  if (alg !== credential.alg) return { ok: false, problem: "key-algorithm-mismatch" };
  const found = credentialKey(credential.publicKey, alg as string);
  if ("problem" in found) return { ok: false, problem: found.problem };

  const cData = bytes(clientDataJSON as string);
  let client: unknown;
  try {
    // §7.2: UTF-8 decode, a leading byte order mark stripped, then JSON.
    client = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(cData));
  } catch {
    return { ok: false, problem: "malformed" };
  }
  if (!isObject(client)) return { ok: false, problem: "malformed" };
  if (client.type !== "webauthn.get") return { ok: false, problem: "wrong-type" };
  if (client.challenge !== Buffer.from(challenge).toString("base64url")) return { ok: false, problem: "wrong-challenge" };
  if (!isString(client.origin) || !credential.origins.includes(client.origin)) return { ok: false, problem: "wrong-origin" };
  // The signing ceremony runs top-level in a pinned origin (v4 §7), never in a frame.
  if (client.crossOrigin === true || client.topOrigin !== undefined) return { ok: false, problem: "cross-origin" };

  const authData = bytes(authenticatorData as string);
  if (authData.length < 37) return { ok: false, problem: "malformed" };
  const rpIdHash = createHash("sha256").update(credential.rpId, "utf8").digest();
  if (!authData.subarray(0, 32).equals(rpIdHash)) return { ok: false, problem: "wrong-rp" };
  const flags = authData[32] as number;
  // §6.1: an assertion never carries attested credential data; BS is never set without BE (§7.2).
  if ((flags & FLAGS.AT) !== 0 || ((flags & FLAGS.BS) !== 0 && (flags & FLAGS.BE) === 0)) return { ok: false, problem: "bad-flags" };
  if ((flags & FLAGS.UP) === 0) return { ok: false, problem: "no-user-presence" };
  // v4 §3: a passkey signs with user verification required.
  if ((flags & FLAGS.UV) === 0) return { ok: false, problem: "no-user-verification" };

  const signed = Buffer.concat([authData, createHash("sha256").update(cData).digest()]);
  const signature = bytes(sig as string);
  // ES256: an ASN.1 DER Ecdsa-Sig-Value (§6.5.5, RFC 3279 §2.2.3); EdDSA: 64 bytes (RFC 8032 §5.1.7).
  let good: boolean;
  try {
    good = alg === "ES256"
      ? verifySignature("sha256", signed, { key: found.key, dsaEncoding: "der" }, signature)
      // Node's verify also refuses other lengths; the check keeps the rule independent of the runtime.
      : signature.length === 64 && verifySignature(null, signed, found.key, signature);
  } catch {
    good = false;
  }
  if (!good) return { ok: false, problem: "bad-signature" };
  return { ok: true, flags, signCount: authData.readUInt32BE(33) };
}
// #endregion webauthn
