// #region cloudflare-estate-source — docs: docs/protocol/sessions.md#admission
// The estate the hosted relay admits from, as the operator placed it in R2.

import type { EstateSource } from "../core/admission.ts";

/** Key prefix of the estate in the bucket; blobs are keyed by `sha256:…`, so the two never meet. */
export const ESTATE_PREFIX = "estate/";

/**
 * The estate as the operator placed it in R2: `estate/pinned.json` (the estate's first passkeys, public keys pinned at
 * setup) and `estate/revisions/<n>.json`. Nothing here is trusted: every revision is verified by the contract.
 */
export class R2EstateSource implements EstateSource {
  constructor(private readonly bucket: R2Bucket) {}
  async pinned(): Promise<unknown[]> {
    const object = await this.bucket.get(`${ESTATE_PREFIX}pinned.json`);
    if (!object) return [];
    const value = JSON.parse(await object.text()) as unknown;
    return Array.isArray(value) ? value : [];
  }
  async revisions(): Promise<unknown[]> {
    const listed = await this.bucket.list({ prefix: `${ESTATE_PREFIX}revisions/` });
    const out: unknown[] = [];
    for (const entry of listed.objects) {
      const object = await this.bucket.get(entry.key);
      if (object) out.push(JSON.parse(await object.text()) as unknown);
    }
    return out;
  }
}
// #endregion cloudflare-estate-source
