// #region digest — docs: docs/adr/0001-relay-repository.md#what-the-relay-holds
// Package blobs and sealed envelopes are stored by the digest of their bytes. The relay recomputes the
// digest of every blob it is given and refuses one whose bytes do not match the name it was given, so
// nothing it stores can be read back under a name it was not computed for.

const DIGEST = /^sha256:[0-9a-f]{64}$/;

export class DigestMismatch extends Error {
  readonly code = "digest-mismatch";
  constructor(readonly claimed: string, readonly computed: string) {
    super(`the bytes hash to ${computed}, not ${claimed}`);
  }
}

export function isDigest(value: string): boolean {
  return DIGEST.test(value);
}

export async function sha256Digest(bytes: Uint8Array): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)));
  let hex = "";
  for (const byte of hash) hex += byte.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}

export interface BlobStore {
  /** Stores bytes the caller has already verified against `digest`; use putVerified, never this directly. */
  write(digest: string, bytes: Uint8Array): Promise<void>;
  read(digest: string): Promise<Uint8Array | null>;
}

export async function putVerified(store: BlobStore, digest: string, bytes: Uint8Array): Promise<void> {
  if (!isDigest(digest)) throw new TypeError(`not a sha256 digest: ${JSON.stringify(digest).slice(0, 80)}`);
  const computed = await sha256Digest(bytes);
  if (computed !== digest) throw new DigestMismatch(digest, computed);
  await store.write(digest, bytes);
}

export async function getVerified(store: BlobStore, digest: string): Promise<Uint8Array | null> {
  if (!isDigest(digest)) throw new TypeError(`not a sha256 digest: ${JSON.stringify(digest).slice(0, 80)}`);
  const bytes = await store.read(digest);
  if (bytes === null) return null;
  // A store that hands back other bytes (a corrupted file, a bucket edited by hand) is refused, not served.
  const computed = await sha256Digest(bytes);
  if (computed !== digest) throw new DigestMismatch(digest, computed);
  return bytes;
}

export class MemoryBlobStore implements BlobStore {
  readonly #blobs = new Map<string, Uint8Array>();
  async write(digest: string, bytes: Uint8Array): Promise<void> {
    this.#blobs.set(digest, bytes.slice());
  }
  async read(digest: string): Promise<Uint8Array | null> {
    return this.#blobs.get(digest)?.slice() ?? null;
  }
}
// #endregion digest
