// #region cloudflare-estate-source — docs: docs/protocol/sessions.md#admission
// The estate the hosted relay admits from, as the operator placed it in R2 (keys from context.ts).

import type { EstateSource } from "../core/admission.ts";
import { estatePrefix } from "./context.ts";

/** A revision object that does not parse: offered as is, so the contract refuses it and the walk stops there. */
export interface UnreadableRevision {
  revision: number;
  unreadable: string;
}

/**
 * The estate as the operator placed it in R2: the estate's first passkeys (`pinned.json`, public keys pinned at setup)
 * and `revisions/<n>.json`, under `estatePrefix()`. Nothing here is trusted: every revision is verified by the
 * contract. A revision file that does not parse is not thrown: it becomes an `UnreadableRevision` numbered by its key,
 * which the contract refuses, so the revisions before it still hold and the refusal is reported.
 */
export class R2EstateSource implements EstateSource {
  constructor(private readonly bucket: R2Bucket) {}
  async pinned(): Promise<unknown[]> {
    const object = await this.bucket.get(`${estatePrefix()}pinned.json`);
    if (!object) return [];
    const value = JSON.parse(await object.text()) as unknown;
    return Array.isArray(value) ? value : [];
  }
  async revisions(): Promise<unknown[]> {
    const listed = await this.bucket.list({ prefix: `${estatePrefix()}revisions/` });
    const out: unknown[] = [];
    for (const entry of listed.objects) {
      const object = await this.bucket.get(entry.key);
      if (!object) continue;
      const text = await object.text();
      try {
        out.push(JSON.parse(text) as unknown);
      } catch {
        const numbered = /\/(\d+)\.json$/.exec(entry.key);
        out.push({ revision: numbered ? Number(numbered[1]) : Number.MAX_SAFE_INTEGER, unreadable: entry.key } satisfies UnreadableRevision);
      }
    }
    return out;
  }
}
// #endregion cloudflare-estate-source
