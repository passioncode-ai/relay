// #region relay-blobs — docs: docs/protocol/sessions.md#blobs
// PUT and GET /v1/blobs/<digest> (DEC-0047 item 8 and its 2026-10-12 annotation). Who may ask is decided by the
// contract's verifyBlobRequest over the request's Fabric-Relay-Request header and the relay's current verified
// admission set; this module stores and serves the bytes by their digest, keeps each blob's recipients, and deletes a
// blob once every recipient fetched it or after 7 days, whichever comes first.

import { RELAY_REQUEST_HEADER, verifyBlobRequest, type AdmissionResult } from "../contract/relay.ts";
import { DigestMismatch, getVerified, isDigest, putVerified, type BlobStore } from "./digest.ts";

/** How long a blob is kept when not every recipient fetched it (DEC-0047 item 8). */
export const BLOB_RETENTION_SECONDS = 7 * 24 * 3600;
/** The largest blob the relay accepts: envelopes are small, a package archive is not. */
export const MAX_BLOB_BYTES = 32 * 1024 * 1024;

export interface BlobMeta {
  recipients: string[];
  fetched: string[];
  expiresAt: number; // epoch ms
}

/** Each blob's recipients and who fetched it. Implementations: memory (tests), files (portable), R2 (hosted). */
export interface BlobIndex {
  get(digest: string): Promise<BlobMeta | null>;
  put(digest: string, meta: BlobMeta): Promise<void>;
  delete(digest: string): Promise<void>;
}

export class MemoryBlobIndex implements BlobIndex {
  readonly #meta = new Map<string, BlobMeta>();
  async get(digest: string): Promise<BlobMeta | null> {
    const meta = this.#meta.get(digest);
    return meta ? structuredClone(meta) : null;
  }
  async put(digest: string, meta: BlobMeta): Promise<void> {
    this.#meta.set(digest, structuredClone(meta));
  }
  async delete(digest: string): Promise<void> {
    this.#meta.delete(digest);
  }
}

/** What the blob routes need beyond the byte store. */
export interface BlobAccess {
  origin: string; // this relay's origin, signed into relay-blob/1
  index: BlobIndex;
  admission: () => AdmissionResult | Promise<AdmissionResult>;
  now?: () => Date;
}

const json = (status: number, body: unknown) => Response.json(body, { status, headers: { "cache-control": "no-store" } });
const refuse = (status: number, code: string, message: string) => json(status, { error: { code, message } });

export async function handleBlob(request: Request, digest: string, blobs: BlobStore, access: BlobAccess): Promise<Response> {
  if (!isDigest(digest)) return refuse(404, "not-found", "a blob is named sha256:<64 hex>");
  const method = request.method;
  if (method !== "PUT" && method !== "GET") return refuse(405, "method-not-allowed", "a blob is PUT or GET");
  const now = access.now?.() ?? new Date();
  let meta = await access.index.get(digest);
  if (meta && meta.expiresAt <= now.getTime()) {
    await Promise.all([blobs.delete(digest), access.index.delete(digest)]);
    meta = null;
  }
  const admission = await access.admission();
  const verdict = verifyBlobRequest(request.headers.get(RELAY_REQUEST_HEADER), {
    relay: access.origin, method, digest, now,
    admittedKey: (kid) => (admission.ok ? admission.set.get(kid) : undefined),
    ...(meta ? { stored: { recipients: meta.recipients } } : {}),
  });
  if (!verdict.ok) return refuse(verdict.status, verdict.code, `the blob request was refused: ${verdict.code}`);

  if (method === "PUT") {
    if (verdict.repeat) return json(200, { digest, stored: true });
    const declared = Number(request.headers.get("content-length") ?? 0);
    if (declared > MAX_BLOB_BYTES) return refuse(413, "too-large", `blobs are at most ${MAX_BLOB_BYTES} bytes`);
    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.byteLength > MAX_BLOB_BYTES) return refuse(413, "too-large", `blobs are at most ${MAX_BLOB_BYTES} bytes`);
    try {
      await putVerified(blobs, digest, bytes);
    } catch (error) {
      if (error instanceof DigestMismatch) return refuse(422, "digest-mismatch", "the bytes do not hash to the digest in the path");
      throw error;
    }
    await access.index.put(digest, { recipients: verdict.recipients, fetched: [], expiresAt: now.getTime() + BLOB_RETENTION_SECONDS * 1000 });
    return json(201, { digest, stored: true });
  }

  const bytes = meta ? await getVerified(blobs, digest) : null;
  if (!meta || bytes === null) return refuse(404, "not-found", "no such blob");
  const fetched = [...new Set([...meta.fetched, verdict.kid])];
  if (meta.recipients.every((kid) => fetched.includes(kid))) {
    await Promise.all([blobs.delete(digest), access.index.delete(digest)]);
  } else {
    await access.index.put(digest, { ...meta, fetched });
  }
  return new Response(new Uint8Array(bytes), { status: 200, headers: { "content-type": "application/octet-stream", "cache-control": "no-store" } });
}
// #endregion relay-blobs
