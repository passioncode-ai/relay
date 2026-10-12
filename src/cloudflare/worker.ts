// #region cloudflare-adapter — docs: docs/adr/0001-relay-repository.md#two-builds
// The hosted relay: a Worker in front of the runtime-neutral core, one Durable Object per connection for its session,
// and R2 for blobs and for the estate record the relay admits from. Bindings are declared in wrangler.jsonc; no
// deployment's values live in this repository.

import { DurableObject } from "cloudflare:workers";
import validateEstateRecord from "../contract/estate-record.validate.js";
import { loadAdmission, type EstateSource } from "../core/admission.ts";
import type { BlobStore } from "../core/digest.ts";
import { CONNECT_PATH, handle, SUBPROTOCOL, upgradeRefusal } from "../core/relay.ts";
import { RelaySession as Session } from "../core/session.ts";

export interface Env {
  SESSIONS: DurableObjectNamespace<RelaySession>;
  BLOBS: R2Bucket;
}

/** Key prefix of the estate in the bucket; blobs are keyed by `sha256:…`, so the two never meet. */
export const ESTATE_PREFIX = "estate/";
/** How often a session checks its 10 s auth deadline and its 90 s idle close. */
const TICK_MS = 1000;

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

const base64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const log = (event: Record<string, unknown>) => console.log(JSON.stringify({ service: "relay", ...event }));

/** One connection's session. It reads the estate when the connection opens and admits only from what verifies. */
export class RelaySession extends DurableObject<Env> {
  override async fetch(request: Request): Promise<Response> {
    const refusal = upgradeRefusal(request);
    if (refusal) return refusal;
    const { holder, refused } = await loadAdmission(new R2EstateSource(this.env.BLOBS), (record) => validateEstateRecord(record), () => new Date());
    if (refused.length > 0) log({ event: "estate-revision-refused", refused });
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    server.accept();
    let timer: ReturnType<typeof setInterval> | undefined;
    const session = new Session(
      {
        send: (text) => server.send(text),
        close: (code, reason) => {
          if (timer) clearInterval(timer);
          server.close(code, reason);
        },
      },
      {
        relay: new URL(request.url).origin,
        now: () => new Date(),
        nonce: () => base64url(crypto.getRandomValues(new Uint8Array(32))),
        sessionId: () => crypto.randomUUID(),
        admission: () => holder.current(),
        log,
      },
    );
    server.addEventListener("message", (event) => session.receive(event.data as string | ArrayBuffer));
    server.addEventListener("close", () => {
      if (timer) clearInterval(timer);
    });
    session.open();
    timer = setInterval(() => session.tick(), TICK_MS);
    return new Response(null, { status: 101, webSocket: client, headers: { "sec-websocket-protocol": SUBPROTOCOL } });
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname === CONNECT_PATH && (request.headers.get("upgrade") ?? "").toLowerCase() === "websocket") {
      // One Durable Object per connection: a session holds nothing another connection may read.
      return env.SESSIONS.get(env.SESSIONS.newUniqueId()).fetch(request);
    }
    return handle(request, { runtime: "cloudflare", blobs: new R2BlobStore(env.BLOBS) });
  },
} satisfies ExportedHandler<Env>;
// #endregion cloudflare-adapter
