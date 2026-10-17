// #region relay-blobs — docs: docs/protocol/sessions.md#blobs
// PUT and GET /v1/blobs/<digest> (DEC-0047 item 8 and its 2026-10-12 annotation). Who may ask is decided by the
// contract's verifyBlobRequest over the request's Fabric-Relay-Request header and the relay's current verified
// admission set; this module stores and serves the bytes by their digest, keeps each blob's recipients, and deletes a
// blob once every recipient fetched it or after 7 days, whichever comes first.

import {
  AUTH_WINDOW_SECONDS, CLOCK_SKEW_SECONDS, MAX_BLOB_BYTES, RELAY_REQUEST_HEADER, decideBlobAccess, instant, parseRelayRequest,
  verifyBlobRequest, type AdmissionResult,
} from "../contract/relay.ts";
import { DigestMismatch, getVerified, isDigest, putVerified, type BlobStore } from "./digest.ts";

/** How long a blob is kept when not every recipient fetched it (DEC-0047 item 8). */
export const BLOB_RETENTION_SECONDS = 7 * 24 * 3600;
/** The largest blob the relay accepts (the contract's MAX_BLOB_BYTES, 32 MiB): envelopes are small, a package archive is not. */
export { MAX_BLOB_BYTES };

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

/**
 * Whether the request's own bytes pass the checks before the signer is proven (DEC-0066's order, steps 1 to 4): the
 * header's form, `alg`, the recipients and `iat` within 60 s either way. Only then does a PUT's Content-Length (step 5)
 * decide the answer, so the 411 and 413 a client sees never depend on the admission set.
 */
function pastOwnBytes(header: string | null, now: Date): boolean {
  const parsed = parseRelayRequest(header);
  if (!parsed.ok) return false;
  const t = instant(parsed.request.iat);
  return t !== undefined && t - now.getTime() <= CLOCK_SKEW_SECONDS * 1000 && now.getTime() - t <= AUTH_WINDOW_SECONDS * 1000;
}

/** Reads at most `limit` bytes of a body; undefined when it holds more (the read stops there). */
async function readAtMost(request: Request, limit: number): Promise<Uint8Array | undefined> {
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => undefined);
      return undefined;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.byteLength; }
  return bytes;
}

/**
 * PUT and GET of one blob, in DEC-0066's order of checks: authenticate (`verifyBlobRequest`), then authorize, then
 * touch state (`decideBlobAccess`), then answer. A refusal is `{error: {code, message}}` with `cache-control: no-store`;
 * its message names the code and nothing more, so no answer tells a caller why beyond what the code already says.
 */
export async function handleBlob(request: Request, digest: string, blobs: BlobStore, access: BlobAccess): Promise<Response> {
  if (!isDigest(digest)) return refuse(404, "not-found", "a blob is named sha256:<64 hex>");
  const method = request.method;
  if (method !== "PUT" && method !== "GET") return refuse(405, "method-not-allowed", "a blob is PUT or GET");
  const now = access.now?.() ?? new Date();
  const header = request.headers.get(RELAY_REQUEST_HEADER);
  const admission = await access.admission();
  const verdict = verifyBlobRequest(header, {
    relay: access.origin, method, digest, now,
    admittedKey: (kid) => (admission.ok ? admission.set.get(kid) : undefined),
  });

  // Step 5: a PUT declares its length, at most MAX_BLOB_BYTES, before the signer is proven.
  let declared = 0;
  if (method === "PUT" && (verdict.ok || pastOwnBytes(header, now))) {
    const length = request.headers.get("content-length");
    if (length === null || !/^[0-9]+$/.test(length)) return refuse(411, "malformed", "a blob PUT declares its Content-Length");
    declared = Number(length);
    if (declared > MAX_BLOB_BYTES) return refuse(413, "too-large", `blobs are at most ${MAX_BLOB_BYTES} bytes`);
  }
  if (!verdict.ok) return refuse(verdict.status, verdict.code, `the blob request was refused: ${verdict.code}`);

  // The record: a live one only. An expired blob is forgotten before it is decided on.
  let meta = await access.index.get(digest);
  if (meta && meta.expiresAt <= now.getTime()) {
    await Promise.all([blobs.delete(digest), access.index.delete(digest)]);
    meta = null;
  }

  if (method === "PUT") {
    // Steps 8 and 9: the body at most its declared length, and the bytes hash to the path's digest; only a holder of
    // the bytes reaches the state (step 10). Storing the verified bytes first is what restores a lost object on a
    // repeat; bytes that hash to the digest are the same bytes under any recipient list.
    const bytes = await readAtMost(request, Math.min(declared, MAX_BLOB_BYTES));
    if (bytes === undefined) return refuse(413, "too-large", `the body is longer than its Content-Length or ${MAX_BLOB_BYTES} bytes`);
    try {
      await putVerified(blobs, digest, bytes);
    } catch (error) {
      if (error instanceof DigestMismatch) return refuse(422, "digest-mismatch", "the bytes do not hash to the digest in the path");
      throw error;
    }
    const decision = decideBlobAccess("PUT", verdict, meta ? { recipients: meta.recipients } : undefined);
    if (!decision.ok) return refuse(decision.status, decision.code, `the blob request was refused: ${decision.code}`);
    if (decision.repeat) return json(200, { digest, stored: true });
    await access.index.put(digest, { recipients: verdict.recipients, fetched: [], expiresAt: now.getTime() + BLOB_RETENTION_SECONDS * 1000 });
    return json(201, { digest, stored: true });
  }

  // A GET: one 403 not-admitted for anything but a live record, its object present, the signer a recipient of the list
  // it signed letter for letter. Never 404.
  const decision = decideBlobAccess("GET", verdict, meta ? { recipients: meta.recipients } : undefined);
  if (!decision.ok || !meta) return refuse(403, "not-admitted", "the blob request was refused: not-admitted");
  const bytes = await getVerified(blobs, digest);
  if (bytes === null) return refuse(403, "not-admitted", "the blob request was refused: not-admitted");
  const fetched = [...new Set([...meta.fetched, verdict.kid])];
  if (meta.recipients.every((kid) => fetched.includes(kid))) {
    await Promise.all([blobs.delete(digest), access.index.delete(digest)]);
  } else {
    await access.index.put(digest, { ...meta, fetched });
  }
  return new Response(new Uint8Array(bytes), { status: 200, headers: { "content-type": "application/octet-stream", "cache-control": "no-store" } });
}
// #endregion relay-blobs
