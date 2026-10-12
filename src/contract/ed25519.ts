// #region ed25519 — docs: docs/specification/delegation.md#the-verifier
/**
 * Ed25519 public keys the contract refuses before verifying anything under them (DEC-0045, CT-29). A key of small
 * order — the identity, the point of order 2, those of order 4 and 8 — lets anyone forge a signature with no private
 * key: under the all-zero key (order 4), `R = B`, `S = 1` verifies whenever `H(R ‖ A ‖ M) mod L` is 0 mod 4, which a
 * forger reaches by varying the message. Node 20 and 22 (OpenSSL 3.x) `crypto.verify` accept such a signature; Node
 * 24 and 26 refuse it. The contract does not depend on which: every Ed25519 verification here asks this first.
 */

/**
 * libsodium 1.0.18's `has_small_order` list (`crypto_core/ed25519/ref10/ed25519_ref10.c`; later versions check the
 * point instead of a byte list, with the same result): the 32-byte encodings, sign bit
 * clear, of every point of order 1, 2, 4 or 8 — with the non-canonical `y = p` and `y = p + 1`, which a lax decoder
 * reduces to the points `y = 0` and `y = 1`.
 */
export const SMALL_ORDER_ENCODINGS = [
  // y = 0: order 4
  "0000000000000000000000000000000000000000000000000000000000000000",
  // y = 1: the identity, order 1
  "0100000000000000000000000000000000000000000000000000000000000000",
  // order 8
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  // y = p − 1 = −1: order 2
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  // y = p, non-canonical 0: order 4
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  // y = p + 1, non-canonical 1: order 1
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
] as const;

const SMALL_ORDER = new Set<string>(SMALL_ORDER_ENCODINGS);

/**
 * Whether a raw Ed25519 public key must be refused: it is not 32 bytes, or its encoding with the sign bit (the top
 * bit of byte 31) cleared is one of `SMALL_ORDER_ENCODINGS`. A key this answers `true` for is never used to verify.
 */
export function isSmallOrderKey(raw: Uint8Array): boolean {
  if (raw.length !== 32) return true;
  const cleared = Buffer.from(raw);
  cleared[31] = (cleared[31] as number) & 0x7f;
  return SMALL_ORDER.has(cleared.toString("hex"));
}
// #endregion ed25519
