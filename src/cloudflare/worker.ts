// #region cloudflare-adapter — docs: docs/adr/0001-relay-repository.md#two-builds
// The hosted relay: a Worker in front of the runtime-neutral core, one Durable Object per connection for its session,
// and R2 for blobs and for the estate record the relay admits from. Bindings are declared in wrangler.jsonc; no
// deployment's values live in this repository.

import { DurableObject } from "cloudflare:workers";
import validateEstateRecord from "../contract/estate-record.validate.js";
import { loadAdmission } from "../core/admission.ts";
import { CONNECT_PATH, handle, SUBPROTOCOL, upgradeRefusal } from "../core/relay.ts";
import type { DeliveryHub } from "../core/mailbox.ts";
import { RelaySession as Session } from "../core/session.ts";
import type { PresenceRecord } from "../core/presence.ts";
import { R2BlobIndex, R2BlobStore } from "./blob-store.ts";
import { R2EstateSource } from "./estate-source.ts";
import { DurableMailbox, type RelayMailbox } from "./mailbox.ts";
import { DurablePresence, type RelayPresence } from "./presence.ts";

// Every Durable Object class a binding names is exported by the Worker's main module.
export { R2BlobIndex, R2BlobStore } from "./blob-store.ts";
export { R2EstateSource } from "./estate-source.ts";
export { RelayMailbox } from "./mailbox.ts";
export { RelayPresence } from "./presence.ts";

export interface Env {
  SESSIONS: DurableObjectNamespace<RelaySession>;
  MAILBOX: DurableObjectNamespace<RelayMailbox>;
  PRESENCE: DurableObjectNamespace<RelayPresence>;
  BLOBS: R2Bucket;
}

/** How often a session checks its 10 s auth deadline and its 90 s idle close. */
const TICK_MS = 1000;

const base64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const log = (event: Record<string, unknown>) => console.log(JSON.stringify({ service: "relay", ...event }));

/** One connection's session. It reads the estate when the connection opens and admits only from what verifies. */
export class RelaySession extends DurableObject<Env> {
  #wake: (() => void) | undefined;
  #presence: ((record: PresenceRecord) => void) | undefined;
  #open = false;

  /** Called by a mailbox object when a message for this connection's machine is queued. */
  async wake(): Promise<void> {
    if (!this.#wake) throw new Error("no live connection");
    this.#wake();
  }

  /** Called by the presence object when another machine of the estate comes online or goes offline. */
  async presence(record: PresenceRecord): Promise<void> {
    if (!this.#presence) throw new Error("no live connection");
    this.#presence(record);
  }

  /** Asked by the presence object: does this object still hold an open connection? */
  async alive(): Promise<boolean> {
    return this.#open;
  }

  override async fetch(request: Request): Promise<Response> {
    const refusal = upgradeRefusal(request);
    if (refusal) return refusal;
    const { holder, refused } = await loadAdmission(new R2EstateSource(this.env.BLOBS), (record) => validateEstateRecord(record), () => new Date());
    if (refused.length > 0) log({ event: "estate-revision-refused", refused });
    const admission = holder.current();
    log({ event: "admission", ...(admission.ok ? { revision: admission.revision, machines: admission.set.size } : { refusal: admission.refusal }) });
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    server.accept();
    let timer: ReturnType<typeof setInterval> | undefined;
    // This connection's hub: one subscription, to its own machine's mailbox object, woken through wake().
    const self = this.ctx.id.toString();
    const hub: DeliveryHub = {
      subscribe: (kid, listener) => {
        this.#wake = listener;
        const box = this.env.MAILBOX.get(this.env.MAILBOX.idFromName(kid));
        void box.subscribe(self);
        return () => {
          this.#wake = undefined;
          void box.unsubscribe(self);
        };
      },
      notify: () => {}, // the mailbox object wakes its subscribers itself when it queues a message
    };
    const session = new Session(
      {
        send: (text) => server.send(text),
        close: (code, reason) => {
          if (timer) clearInterval(timer);
          this.#open = false;
          server.close(code, reason);
        },
      },
      {
        relay: new URL(request.url).origin,
        now: () => new Date(),
        nonce: () => base64url(crypto.getRandomValues(new Uint8Array(32))),
        sessionId: () => crypto.randomUUID(),
        admission: () => holder.current(),
        mailbox: new DurableMailbox(this.env),
        hub,
        presence: new DurablePresence(this.env, self, (listener) => { this.#presence = listener; }),
        log,
      },
    );
    server.addEventListener("message", (event) => {
      session.receive(event.data as string | ArrayBuffer).catch((error: unknown) => {
        // A fault in the relay is reported and closes the connection as an internal error, never silently.
        log({ event: "session-fault", error: (error as Error).name, message: String((error as Error).message).slice(0, 200) });
        if (timer) clearInterval(timer);
        server.close(1011, "internal error");
      });
    });
    server.addEventListener("close", () => {
      if (timer) clearInterval(timer);
      this.#open = false;
      session.disconnected();
    });
    this.#open = true;
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
