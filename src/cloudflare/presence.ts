// #region cloudflare-presence — docs: docs/protocol/sessions.md#presence

import { DurableObject } from "cloudflare:workers";
import type { PresenceRecord } from "../core/presence.ts";
import type { RelaySession, SessionHub } from "../core/session.ts";
import type { Env } from "./worker.ts";

/**
 * The estate's presence (RLY-06): one Durable Object for the relay's one estate. It holds which session objects are
 * live connections of which machine, each machine's `lastSeen`, and the sessions to tell when a machine comes online or
 * goes offline. A session object that no longer answers is taken for a connection that ended.
 */
export class RelayPresence extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS connections (session TEXT PRIMARY KEY, kid TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS last_seen (kid TEXT PRIMARY KEY, at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS subscribers (session TEXT PRIMARY KEY);`);
  }

  #live(kid: string): number {
    return this.ctx.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM connections WHERE kid = ?", kid).one().n;
  }

  /** Moves `lastSeen` forward, never back, and answers it. */
  #seen(kid: string, atMs: number): string {
    const at = new Date(atMs).toISOString();
    this.ctx.storage.sql.exec("INSERT INTO last_seen (kid, at) VALUES (?, ?) ON CONFLICT (kid) DO UPDATE SET at = max(at, excluded.at)", kid, at);
    return this.ctx.storage.sql.exec<{ at: string }>("SELECT at FROM last_seen WHERE kid = ?", kid).one().at;
  }

  #publish(record: PresenceRecord): void {
    for (const row of this.ctx.storage.sql.exec<{ session: string }>("SELECT session FROM subscribers").toArray()) {
      this.env.SESSIONS.get(this.env.SESSIONS.idFromString(row.session)).presence(record).catch(() => this.#gone(row.session));
    }
  }

  /** A session object that did not answer: no longer a subscriber, and no longer a connection of its machine. */
  async #gone(session: string): Promise<void> {
    await this.unsubscribe(session);
    const row = this.ctx.storage.sql.exec<{ kid: string }>("SELECT kid FROM connections WHERE session = ?", session).toArray()[0];
    if (row) await this.disconnected(row.kid, session, Date.now());
  }

  async connected(kid: string, session: string, atMs: number): Promise<void> {
    const first = this.#live(kid) === 0;
    this.ctx.storage.sql.exec("INSERT OR IGNORE INTO connections (session, kid) VALUES (?, ?)", session, kid);
    const lastSeen = this.#seen(kid, atMs);
    if (first) this.#publish({ kid, state: "online", lastSeen });
  }

  async disconnected(kid: string, session: string, atMs: number): Promise<void> {
    if (this.ctx.storage.sql.exec("DELETE FROM connections WHERE session = ? AND kid = ?", session, kid).rowsWritten === 0) return;
    const lastSeen = this.#seen(kid, atMs);
    if (this.#live(kid) === 0) this.#publish({ kid, state: "offline", lastSeen });
  }

  async touch(kid: string, atMs: number): Promise<void> {
    this.#seen(kid, atMs);
  }

  /** Each kid seen, in the order asked; a connection whose session object does not answer is ended first. */
  async query(kids: string[]): Promise<PresenceRecord[]> {
    const out: PresenceRecord[] = [];
    for (const kid of new Set(kids)) {
      for (const row of this.ctx.storage.sql.exec<{ session: string }>("SELECT session FROM connections WHERE kid = ?", kid).toArray()) {
        const alive = await this.env.SESSIONS.get(this.env.SESSIONS.idFromString(row.session)).alive().catch(() => false);
        if (!alive) await this.disconnected(kid, row.session, Date.now());
      }
      const seen = this.ctx.storage.sql.exec<{ at: string }>("SELECT at FROM last_seen WHERE kid = ?", kid).toArray()[0];
      if (seen) out.push({ kid, state: this.#live(kid) > 0 ? "online" : "offline", lastSeen: seen.at });
    }
    return out;
  }

  async subscribe(session: string): Promise<void> {
    this.ctx.storage.sql.exec("INSERT OR IGNORE INTO subscribers (session) VALUES (?)", session);
  }

  async unsubscribe(session: string): Promise<void> {
    this.ctx.storage.sql.exec("DELETE FROM subscribers WHERE session = ?", session);
  }
}

/**
 * The core's SessionHub for one session object, over the estate's presence object and the recipient's mailbox object.
 * It lives only until the Worker runs one hub per estate (F-2), which removes this file.
 */
export class DurableSessionHub implements SessionHub {
  readonly #presence: DurableObjectStub<RelayPresence>;
  constructor(private readonly env: Env, private readonly self: string, private readonly log: (event: Record<string, unknown>) => void) {
    this.#presence = env.PRESENCE.get(env.PRESENCE.idFromName("estate"));
  }
  #mailbox(kid: string) {
    return this.env.MAILBOX.get(this.env.MAILBOX.idFromName(kid));
  }
  #fault(error: unknown): void {
    this.log({ event: "presence-fault", error: (error as Error).name, message: String((error as Error).message).slice(0, 200) });
  }
  joined(session: RelaySession): void {
    const kid = session.kid as string;
    void this.#mailbox(kid).subscribe(this.self);
    void this.#presence.subscribe(this.self);
    this.#presence.connected(kid, this.self, Date.now()).catch((error: unknown) => this.#fault(error));
  }
  left(session: RelaySession): void {
    const kid = session.kid as string;
    void this.#mailbox(kid).unsubscribe(this.self);
    void this.#presence.unsubscribe(this.self);
    this.#presence.disconnected(kid, this.self, Date.now()).catch((error: unknown) => this.#fault(error));
  }
  queued(): void {} // the mailbox object wakes its subscribers itself when it queues a message
  readonly presence = {
    touch: (kid: string, at: Date) => this.#presence.touch(kid, at.getTime()),
    query: (kids: readonly string[]) => this.#presence.query([...kids]),
  };
}
// #endregion cloudflare-presence
