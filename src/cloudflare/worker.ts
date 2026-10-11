// #region cloudflare-adapter — docs: docs/adr/0001-relay-repository.md#two-builds
// The hosted relay: a Worker in front of the runtime-neutral core, Durable Objects for sessions and R2
// for blobs. Bindings are declared in wrangler.jsonc; no deployment's values live in this repository.

import { DurableObject } from "cloudflare:workers";
import type { BlobStore } from "../core/digest.ts";
import { errorResponse, handle, PROTOCOL } from "../core/relay.ts";

export interface Env {
  SESSIONS: DurableObjectNamespace<RelaySession>;
  BLOBS: R2Bucket;
}

export class R2BlobStore implements BlobStore {
  constructor(private readonly bucket: R2Bucket) {}
  async write(digest: string, bytes: Uint8Array): Promise<void> {
    await this.bucket.put(digest, bytes);
  }
  async read(digest: string): Promise<Uint8Array | null> {
    const object = await this.bucket.get(digest);
    return object ? new Uint8Array(await object.arrayBuffer()) : null;
  }
}

/** One relay session per Durable Object. It holds no state until the DEC-0047 handshake exists. */
export class RelaySession extends DurableObject<Env> {
  override async fetch(_request: Request): Promise<Response> {
    return errorResponse(501, "protocol-not-ready", `sessions open once ${PROTOCOL.decision} is accepted`);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handle(request, { runtime: "cloudflare", blobs: new R2BlobStore(env.BLOBS) });
  },
} satisfies ExportedHandler<Env>;
// #endregion cloudflare-adapter
