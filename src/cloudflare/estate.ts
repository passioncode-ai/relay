// #region cloudflare-estate — docs: docs/adr/0002-estate-hub.md
// The hosted relay's estate hub: one hibernating Durable Object per estate (`ESTATE.idFromName(hubName())`) over the
// runtime-neutral `EstateHub` (src/core/hub.ts). It accepts every session's socket through the WebSocket Hibernation API
// (`ctx.acceptWebSocket`, no `accept()`, no listeners, no interval), keeps each session's record in its socket's
// attachment, derives presence from the sockets it holds, keeps `lastSeen` in its SQLite storage, and runs one alarm at
// the earliest deadline of all its sessions. A deploy restarts the object and drops every socket; the new object starts
// from `ctx.getWebSockets()`, which is then empty, so nothing about connections can be stale (RLY-012).

import { DurableObject } from "cloudflare:workers";
import validateEstateRecord from "../contract/estate-record.validate.js";
import type { AdmissionResult } from "../contract/relay.ts";
import { loadAdmission, type AdmissionHolder } from "../core/admission.ts";
import { EstateHub } from "../core/hub.ts";
import { errorFields, jsonLog } from "../core/log.ts";
import type { LastSeenStore } from "../core/presence.ts";
import { SUBPROTOCOL, upgradeRefusal } from "../core/relay.ts";
import type { SessionIo, SessionRecord } from "../core/session.ts";
import { R2EstateSource } from "./estate-source.ts";
import { DurableMailbox } from "./mailbox.ts";
import type { Env } from "./worker.ts";

const log = jsonLog("cloudflare");
const NO_RECORD: AdmissionResult = { ok: false, refusal: "no-record" };
const base64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** Each machine's `lastSeen` in the hub object's SQLite storage; it never moves back. */
class SqlLastSeen implements LastSeenStore {
  constructor(private readonly sql: SqlStorage) {
    sql.exec("CREATE TABLE IF NOT EXISTS last_seen (kid TEXT PRIMARY KEY, at TEXT NOT NULL)");
  }
  get(kid: string): string | undefined {
    return this.sql.exec<{ at: string }>("SELECT at FROM last_seen WHERE kid = ?", kid).toArray()[0]?.at;
  }
  put(kid: string, at: string): void {
    this.sql.exec("INSERT INTO last_seen (kid, at) VALUES (?, ?) ON CONFLICT (kid) DO UPDATE SET at = max(at, excluded.at)", kid, at);
  }
}

export class RelayEstate extends DurableObject<Env> {
  readonly #hub: EstateHub<WebSocket>;
  #holder: AdmissionHolder | undefined;
  #loading: Promise<void> | undefined;
  #rebuilt = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#hub = new EstateHub<WebSocket>({
      now: () => new Date(),
      nonce: () => base64url(crypto.getRandomValues(new Uint8Array(32))),
      sessionId: () => crypto.randomUUID(),
      admission: () => this.#holder?.current() ?? NO_RECORD,
      mailbox: new DurableMailbox(env),
      lastSeen: new SqlLastSeen(ctx.storage.sql),
      wakeOnQueued: false, // the mailbox object calls wake(kid) once the message is stored
      arm: (at) => void (at === undefined ? ctx.storage.deleteAlarm() : ctx.storage.setAlarm(at)).catch((error: unknown) => log({ event: "alarm-fault", ...errorFields(error) })),
      log,
    });
  }

  #io(ws: WebSocket): SessionIo {
    return {
      send: (text) => ws.send(text),
      close: (code, reason) => {
        try {
          ws.close(code, reason);
        } catch (error) {
          log({ event: "close-fault", code, ...errorFields(error) });
        }
        this.#hub.closed(ws);
      },
      persist: (record) => {
        try {
          ws.serializeAttachment(record);
        } catch {
          // a socket that is closing keeps no attachment; the session is over
        }
      },
    };
  }

  /**
   * After a hibernation wake the object is new: the sockets the runtime kept, and their records, are the hub's set. A
   * socket with no record cannot be continued: it is answered `error internal`, then closed 1011 (ADR-0002 item 3).
   */
  #rebuild(): void {
    if (this.#rebuilt) return;
    this.#rebuilt = true;
    let restored = 0;
    for (const ws of this.ctx.getWebSockets()) {
      const record = ws.deserializeAttachment() as SessionRecord | null;
      if (record?.v === 1) {
        this.#hub.restore(ws, this.#io(ws), record);
        restored += 1;
        continue;
      }
      try {
        ws.send(JSON.stringify({ v: 1, id: "r0", type: "error", code: "internal", message: "the relay lost this session" }));
        ws.close(1011, "internal error");
      } catch (error) {
        log({ event: "close-fault", code: 1011, ...errorFields(error) });
      }
    }
    if (restored > 0) log({ event: "hub-woke", sessions: restored });
  }

  /**
   * The estate as R2 holds it now: read when a connection opens (as each connection always has) and when the object
   * wakes holding nothing. One read at a time, so events that wait on it go on in the order they arrived. It never
   * rejects: a read that fails is logged `estate-unreadable` and the hub keeps what it held (nothing after a wake, which
   * admits nobody: fail closed). A read that would hold an older revision than the one held is not applied, so a slow or
   * partial read never rolls open sessions back.
   */
  #load(): Promise<void> {
    this.#loading ??= (async () => {
      try {
        const { holder, refused } = await loadAdmission(new R2EstateSource(this.env.BLOBS), (record) => validateEstateRecord(record), () => new Date());
        if (refused.length > 0) log({ event: "estate-revision-refused", refused });
        const held = Number(this.#holder?.revision?.revision ?? 0);
        const read = Number(holder.revision?.revision ?? 0);
        if (read < held) {
          log({ event: "estate-rollback-refused", held, read });
          return;
        }
        this.#holder = holder;
        const admission = holder.current();
        log({ event: "admission", ...(admission.ok ? { revision: admission.revision, machines: admission.set.size } : { refusal: admission.refusal }) });
      } catch (error) {
        log({ event: "estate-unreadable", ...errorFields(error), held: this.#holder?.revision?.revision ?? null });
      } finally {
        this.#loading = undefined;
      }
    })();
    return this.#loading;
  }

  /**
   * Every event first rebuilds the hub's set, then, if the object holds no estate (a fresh object after a wake), reads
   * it. The read never fails the event: a frame still reaches its session, an alarm still ticks, a close still ends the
   * session and is announced, a wake still delivers. With no usable estate the sessions admit nobody.
   */
  async #ready(reload = false): Promise<void> {
    this.#rebuild();
    if (reload || !this.#holder || this.#loading) await this.#load();
  }

  override async fetch(request: Request): Promise<Response> {
    const refusal = upgradeRefusal(request);
    if (refusal) return refusal;
    await this.#ready(true);
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    this.ctx.acceptWebSocket(server);
    this.#hub.connect(server, this.#io(server), new URL(request.url).origin);
    return new Response(null, { status: 101, webSocket: client, headers: { "sec-websocket-protocol": SUBPROTOCOL } });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    await this.#ready();
    await this.#hub.receive(ws, message);
  }

  override async webSocketClose(ws: WebSocket): Promise<void> {
    await this.#ready();
    this.#hub.closed(ws);
  }

  override async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    log({ event: "socket-error", error: (error as Error)?.name ?? "Error" });
    await this.#ready();
    this.#hub.closed(ws);
  }

  override async alarm(): Promise<void> {
    await this.#ready();
    await this.#hub.onWake();
  }

  /** Called by a recipient's mailbox object once a message for `kid` is stored: that machine's sessions deliver it. */
  async wake(kid: string): Promise<void> {
    await this.#ready();
    await this.#hub.wake(kid);
  }
}
// #endregion cloudflare-estate
