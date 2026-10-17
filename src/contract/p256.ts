// #region p256 — docs: docs/specification/devices.md#device-keys
/**
 * P-256 public keys the contract refuses before verifying, or sealing, anything under them (DEC-0053, DEC-0047). Keys held by
 * hardware — device signing keys (ES256), device key-agreement keys (ECDH, a relay envelope's `#kem`), passkeys,
 * organization roots — are P-256, and a key that is not a point of the curve's group is never used: an off-curve or
 * out-of-range point fed to ECDH leaks the private key one small subgroup at a time (the invalid-curve attack), and a
 * signature "verified" under the identity proves nothing.
 *
 * The check is SEC 1 v2 §3.2.2 (Validation of Elliptic Curve Public Keys): Q is not the point at infinity; its
 * coordinates are integers in [0, p − 1]; Q satisfies y² = x³ + ax + b (mod p). The fourth step, nQ = O, holds for
 * every point on P-256 because its cofactor is 1 (SEC 2 §2.4.2), so it is not computed. One function for every
 * consumer — relay envelopes (DEC-0047), packages (DEC-0051), estate records — so no two of them disagree on a key.
 */

import { createPublicKey, sign as nodeSign, type KeyObject } from "node:crypto";

/** SEC 2 v2 §2.4.2, secp256r1 (NIST P-256). */
export const P256_CURVE = {
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n
} as const;

/** Why a key is refused; `null` from `p256KeyRefusal` means the key is a valid public key. */
export type P256Refusal =
  | "bad-encoding" // not a JWK of kty EC / crv P-256 with 32-byte x and y, nor 65 bytes 0x04 ‖ X ‖ Y
  | "point-at-infinity" // the SEC 1 encoding of the identity, the single byte 0x00
  | "coordinate-out-of-range" // x or y is p or larger
  | "not-on-curve"; // y² ≠ x³ + ax + b (mod p)

/** A P-256 public key as a JWK (RFC 7518 §6.2.1) or as SEC 1 octets (§2.3.3); compressed points are not accepted. */
export type P256Key = { kty?: unknown; crv?: unknown; x?: unknown; y?: unknown } | Uint8Array;

const B64URL = /^[A-Za-z0-9_-]*$/;

function coordinate(value: unknown): bigint | undefined {
  if (typeof value !== "string" || !B64URL.test(value)) return undefined;
  const bytes = Buffer.from(value, "base64url");
  // RFC 7518 §6.2.1.2: "the full coordinate, even if leading zero octets" — exactly 32 bytes, and canonical base64url.
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) return undefined;
  return BigInt(`0x${bytes.toString("hex")}`);
}

/** Reduction mod p of a non-negative value: every operand here is (a is p − 3, not −3), so the remainder is too. */
function mod(value: bigint): bigint {
  return value % P256_CURVE.p;
}

/** The coordinates of a key, the refusal of an encoding that has none, or the identity. */
function decode(key: P256Key): { x: bigint; y: bigint } | P256Refusal {
  if (key instanceof Uint8Array) {
    if (key.length === 1 && key[0] === 0x00) return "point-at-infinity";
    if (key.length !== 65 || key[0] !== 0x04) return "bad-encoding";
    const hex = Buffer.from(key).toString("hex");
    return { x: BigInt(`0x${hex.slice(2, 66)}`), y: BigInt(`0x${hex.slice(66)}`) };
  }
  if (key === null || typeof key !== "object" || key.kty !== "EC" || key.crv !== "P-256") return "bad-encoding";
  const x = coordinate(key.x);
  const y = coordinate(key.y);
  if (x === undefined || y === undefined) return "bad-encoding";
  return { x, y };
}

/**
 * SEC 1 §3.2.2 validation of a P-256 public key: `null` when it is a point of the group other than the identity,
 * otherwise the reason it is refused. A key this refuses is never used to verify a signature or to seal a secret.
 */
export function p256KeyRefusal(key: P256Key): P256Refusal | null {
  const point = decode(key);
  if (typeof point === "string") return point;
  const { x, y } = point;
  if (x >= P256_CURVE.p || y >= P256_CURVE.p) return "coordinate-out-of-range";
  if (mod(y * y) !== mod(x * x * x + P256_CURVE.a * x + P256_CURVE.b)) return "not-on-curve";
  return null;
}

/** Whether a key is a valid P-256 public key: SEC 1 octets (DEC-0053's device keys, policy roots, delegation keys) or a JWK. */
export function isValidP256Key(key: P256Key): boolean {
  return p256KeyRefusal(key) === null;
}

/**
 * The uncompressed SEC 1 point (65 bytes, `0x04 ‖ X ‖ Y`) of a valid key in either form. DEC-0053 records a device key
 * as base64 SEC 1 octets and a relay names keys as JWKs; both reach the same 65 bytes here, so a verifier or a sealer
 * gives one answer whichever form it was handed. Throws on a key `p256KeyRefusal` refuses: callers check first.
 */
export function p256Point(key: P256Key): Buffer {
  const refusal = p256KeyRefusal(key);
  if (refusal !== null) throw new Error(`bad-key: ${refusal}`);
  if (key instanceof Uint8Array) return Buffer.from(key);
  const { x, y } = key as { x: string; y: string };
  return Buffer.concat([Buffer.from([0x04]), Buffer.from(x, "base64url"), Buffer.from(y, "base64url")]);
}

/**
 * The JWK (RFC 7518 §6.2.1) of a valid key in either form. Verifiers hand Node's `verify` this object with
 * `format: "jwk"`: the one key form both Node and a Cloudflare Worker's `node:crypto` (nodejs_compat) accept inside
 * the options with `dsaEncoding`, where a `KeyObject` throws in the Worker — measured by the relay's Worker tests.
 */
export function p256Jwk(key: P256Key): { kty: "EC"; crv: "P-256"; x: string; y: string } {
  const point = p256Point(key);
  return { kty: "EC", crv: "P-256", x: point.subarray(1, 33).toString("base64url"), y: point.subarray(33).toString("base64url") };
}

/** A Node public `KeyObject` for a valid key in either form (through its JWK). */
export function p256PublicKey(key: P256Key): KeyObject {
  return createPublicKey({ key: p256Jwk(key), format: "jwk" });
}

/**
 * Whether a key is an Ed25519 key (a JWK of kty OKP / crv Ed25519, or 32 raw bytes). devices.md admits an Ed25519
 * `#sig` for a device; a relay participant's `#sig` is ES256 only (DEC-0047), and names this case `unsupported-alg`
 * rather than calling it a malformed P-256 key.
 */
export function isEd25519Key(key: unknown): boolean {
  if (key instanceof Uint8Array) return key.length === 32;
  const jwk = key as { kty?: unknown; crv?: unknown } | null;
  return !!jwk && typeof jwk === "object" && jwk.kty === "OKP" && jwk.crv === "Ed25519";
}
// ---- One ES256 rule for the relay family: low-S (DEC-0066) --------------------------------------------------------

const HALF_N = P256_CURVE.n / 2n;
const scalar = (bytes: Uint8Array) => BigInt(`0x${Buffer.from(bytes).toString("hex")}`);

/** Whether a raw ES256 signature (r ‖ s, 64 bytes) has s ≤ n/2. A signature of another length is not low-S. */
export function isLowS(raw: Uint8Array): boolean {
  return raw.length === 64 && scalar(raw.subarray(32)) <= HALF_N;
}

/**
 * The low-S form of a raw ES256 signature: (r, n − s) when s > n/2, otherwise the same bytes. Both forms verify under
 * plain ECDSA, so any signer — a Secure Enclave, a TPM, Python's `cryptography` — normalises after signing, without
 * its key. Throws on a signature that is not 64 bytes.
 */
export function toLowS(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) throw new Error("an ES256 signature is 64 bytes (r ‖ s)");
  const s = scalar(raw.subarray(32));
  if (s <= HALF_N) return raw;
  return Buffer.concat([Buffer.from(raw.subarray(0, 32)), Buffer.from((P256_CURVE.n - s).toString(16).padStart(64, "0"), "hex")]);
}

/** ES256 over `bytes` (a string is UTF-8) as raw r ‖ s, base64url, in the low-S form a relay-family verifier admits. */
export function signEs256(privateKey: KeyObject, bytes: string | Uint8Array): string {
  const raw = nodeSign("sha256", typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes, { key: privateKey, dsaEncoding: "ieee-p1363" });
  return Buffer.from(toLowS(raw)).toString("base64url");
}
// #endregion p256
