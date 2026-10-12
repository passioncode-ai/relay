// #region cloudflare-adapter — docs: docs/adr/0001-relay-repository.md#two-builds
// The hosted relay: a Worker in front of the runtime-neutral core. Every session's socket goes to the estate hub, one
// hibernating Durable Object per estate (estate.ts, docs/adr/0002-estate-hub.md); each recipient's mail to a mailbox
// object (mailbox.ts); blobs and the estate record the relay admits from to R2. Bindings are declared in wrangler.jsonc;
// no deployment's values live in this repository.

import validateEstateRecord from "../contract/estate-record.validate.js";
import { loadAdmission } from "../core/admission.ts";
import { CONNECT_PATH, handle } from "../core/relay.ts";
import { R2BlobIndex, R2BlobStore } from "./blob-store.ts";
import { hubName } from "./context.ts";
import type { RelayEstate } from "./estate.ts";
import { R2EstateSource } from "./estate-source.ts";
import type { RelayMailbox } from "./mailbox.ts";

// Every Durable Object class a binding names is exported by the Worker's main module.
export { R2BlobIndex, R2BlobStore } from "./blob-store.ts";
export { RelayEstate } from "./estate.ts";
export { R2EstateSource } from "./estate-source.ts";
export { RelayMailbox } from "./mailbox.ts";

export interface Env {
  ESTATE: DurableObjectNamespace<RelayEstate>;
  MAILBOX: DurableObjectNamespace<RelayMailbox>;
  BLOBS: R2Bucket;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname === CONNECT_PATH && (request.headers.get("upgrade") ?? "").toLowerCase() === "websocket") {
      // Every session of the estate lives in its one hub: the hub holds only machines of one estate record.
      return env.ESTATE.get(env.ESTATE.idFromName(hubName())).fetch(request);
    }
    return handle(request, {
      runtime: "cloudflare",
      blobs: new R2BlobStore(env.BLOBS),
      blobAccess: {
        origin: new URL(request.url).origin,
        index: new R2BlobIndex(env.BLOBS),
        admission: async () => (await loadAdmission(new R2EstateSource(env.BLOBS), (record) => validateEstateRecord(record), () => new Date())).holder.current(),
      },
    });
  },
} satisfies ExportedHandler<Env>;
// #endregion cloudflare-adapter
