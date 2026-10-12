// #region cloudflare-blob-store — docs: docs/protocol/sessions.md#blobs
// Blobs and their index in R2: the blob under its digest, its recipients and fetches under `blobindex/<digest>`.

import type { BlobStore } from "../core/digest.ts";
import type { BlobIndex, BlobMeta } from "../core/blobs.ts";

export class R2BlobStore implements BlobStore {
  constructor(private readonly bucket: R2Bucket) {}
  async write(digest: string, bytes: Uint8Array): Promise<void> {
    await this.bucket.put(digest, bytes);
  }
  async read(digest: string): Promise<Uint8Array | null> {
    const object = await this.bucket.get(digest);
    return object ? new Uint8Array(await object.arrayBuffer()) : null;
  }
  async delete(digest: string): Promise<void> {
    await this.bucket.delete(digest);
  }
}

/** Each blob's recipients and fetches, as `blobindex/<digest>` objects beside the blobs. */
export class R2BlobIndex implements BlobIndex {
  constructor(private readonly bucket: R2Bucket) {}
  async get(digest: string): Promise<BlobMeta | null> {
    const object = await this.bucket.get(`blobindex/${digest}`);
    return object ? (JSON.parse(await object.text()) as BlobMeta) : null;
  }
  async put(digest: string, meta: BlobMeta): Promise<void> {
    await this.bucket.put(`blobindex/${digest}`, JSON.stringify(meta));
  }
  async delete(digest: string): Promise<void> {
    await this.bucket.delete(`blobindex/${digest}`);
  }
}
// #endregion cloudflare-blob-store
