// #region cloudflare-adapter — docs: docs/adr/0001-relay-repository.md#two-builds
// The hosted relay: a Worker in front of the runtime-neutral core, one Durable Object per connection for its session,
// and R2 for blobs and for the estate record the relay admits from. Bindings are declared in wrangler.jsonc; no
// deployment's values live in this repository.

import { DurableObject } from "cloudflare:workers";
import validateEstateRecord from "../contract/estate-record.validate.js";
import { loadAdmission, type EstateSource } from "../core/admission.ts";
import type { BlobStore } from "../core/digest.ts";
import { CONNECT_PATH, handle, SUBPROTOCOL, upgradeRefusal } from "../core/relay.ts";
import { MAILBOX_LIMIT, type AppendResult, type DeliveryHub, type MailboxStore, type MailEntry } from "../core/mailbox.ts";
import { RelaySession as Session } from "../core/session.ts";

export interface Env {
  SESSIONS: DurableObjectNamespace<RelaySession>;
  MAILBOX: DurableObjectNamespace<RelayMailbox>;
  BLOBS: R2Bucket;
}

/** Key prefix of the estate in the bucket; blobs are keyed by `sha256:…`, so the two never meet. */
const ESTATE_PREFIX = "estate/";
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

/**
 * One recipient's mailbox (RLY-03): a Durable Object per machine kid, its messages in the object's SQLite storage, and
 * the session objects of that machine's live connections, woken when a message is queued for it.
 */
export class RelayMailbox extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS mail (seq INTEGER PRIMARY KEY, sender TEXT NOT NULL, msg_id TEXT NOT NULL,
      body TEXT NOT NULL, sent_at TEXT NOT NULL, expires_at INTEGER NOT NULL, UNIQUE (sender, msg_id));
      CREATE TABLE IF NOT EXISTS subscribers (session TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS counter (one INTEGER PRIMARY KEY CHECK (one = 1), next INTEGER NOT NULL);`);
  }

  #purge(now: number): void {
    this.ctx.storage.sql.exec("DELETE FROM mail WHERE expires_at <= ?", now);
  }

  async append(from: string, msgId: string, body: string, ttlSeconds: number, nowMs: number): Promise<AppendResult> {
    this.#purge(nowMs);
    const same = this.ctx.storage.sql.exec<{ seq: number }>("SELECT seq FROM mail WHERE sender = ? AND msg_id = ?", from, msgId).toArray()[0];
    if (same) return { seq: same.seq, duplicate: true };
    const count = this.ctx.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM mail").one().n;
    if (count >= MAILBOX_LIMIT) return { full: true };
    const next = this.ctx.storage.sql.exec<{ next: number }>("SELECT next FROM counter WHERE one = 1").toArray()[0]?.next ?? 1;
    this.ctx.storage.sql.exec("INSERT INTO counter (one, next) VALUES (1, ?) ON CONFLICT (one) DO UPDATE SET next = excluded.next", next + 1);
    this.ctx.storage.sql.exec("INSERT INTO mail (seq, sender, msg_id, body, sent_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
      next, from, msgId, body, new Date(nowMs).toISOString(), nowMs + ttlSeconds * 1000);
    for (const row of this.ctx.storage.sql.exec<{ session: string }>("SELECT session FROM subscribers").toArray()) {
      // A connection that went away without unsubscribing is dropped when its wake-up fails.
      this.env.SESSIONS.get(this.env.SESSIONS.idFromString(row.session)).wake().catch(() => this.unsubscribe(row.session));
    }
    return { seq: next, duplicate: false };
  }

  async pending(to: string, nowMs: number, afterSeq: number): Promise<MailEntry[]> {
    this.#purge(nowMs);
    return this.ctx.storage.sql.exec<{ seq: number; sender: string; msg_id: string; body: string; sent_at: string; expires_at: number }>(
      "SELECT seq, sender, msg_id, body, sent_at, expires_at FROM mail WHERE seq > ? ORDER BY seq", afterSeq).toArray()
      .map((r) => ({ to, from: r.sender, msgId: r.msg_id, seq: r.seq, body: r.body, sentAt: r.sent_at, expiresAt: r.expires_at }));
  }

  async ack(seq: number): Promise<boolean> {
    return this.ctx.storage.sql.exec("DELETE FROM mail WHERE seq = ?", seq).rowsWritten > 0;
  }

  async subscribe(session: string): Promise<void> {
    this.ctx.storage.sql.exec("INSERT OR IGNORE INTO subscribers (session) VALUES (?)", session);
  }

  async unsubscribe(session: string): Promise<void> {
    this.ctx.storage.sql.exec("DELETE FROM subscribers WHERE session = ?", session);
  }
}

/** The core's MailboxStore over the per-recipient mailbox objects. */
class DurableMailbox implements MailboxStore {
  constructor(private readonly env: Env) {}
  #box(to: string) {
    return this.env.MAILBOX.get(this.env.MAILBOX.idFromName(to));
  }
  append(to: string, from: string, msgId: string, body: string, ttlSeconds: number, now: Date): Promise<AppendResult> {
    return this.#box(to).append(from, msgId, body, ttlSeconds, now.getTime());
  }
  pending(to: string, now: Date, afterSeq = 0): Promise<MailEntry[]> {
    return this.#box(to).pending(to, now.getTime(), afterSeq);
  }
  ack(to: string, seq: number): Promise<boolean> {
    return this.#box(to).ack(seq);
  }
}

/** One connection's session. It reads the estate when the connection opens and admits only from what verifies. */
export class RelaySession extends DurableObject<Env> {
  #wake: (() => void) | undefined;

  /** Called by a mailbox object when a message for this connection's machine is queued. */
  async wake(): Promise<void> {
    if (!this.#wake) throw new Error("no live connection");
    this.#wake();
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
      session.disconnected();
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
