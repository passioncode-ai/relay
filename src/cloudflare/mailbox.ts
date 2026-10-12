// #region cloudflare-mailbox — docs: docs/protocol/sessions.md#messages

import { DurableObject } from "cloudflare:workers";
import { MAILBOX_LIMIT, type AppendResult, type MailboxStore, type MailEntry } from "../core/mailbox.ts";
import type { Env } from "./worker.ts";

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
export class DurableMailbox implements MailboxStore {
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
// #endregion cloudflare-mailbox
