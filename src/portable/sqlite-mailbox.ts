// #region portable-mailbox — docs: docs/protocol/sessions.md#messages
// The self-hosted relay's mailboxes: one SQLite file, owner-only, so a queued message survives a restart. The same
// contract as MemoryMailbox (src/core/mailbox.ts): per-recipient seq, a repeat of (from, msgId) answered with its first
// seq while it is queued, expired messages deleted as they are met, MAILBOX_LIMIT per recipient.

import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { MAILBOX_LIMIT, type AppendResult, type MailboxStore, type MailEntry } from "../core/mailbox.ts";

export class SqliteMailbox implements MailboxStore {
  readonly #db: DatabaseSync;

  constructor(file: string) {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    this.#db = new DatabaseSync(file);
    chmodSync(file, 0o600);
    this.#db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS mail (
        recipient TEXT NOT NULL, seq INTEGER NOT NULL, sender TEXT NOT NULL, msg_id TEXT NOT NULL,
        body TEXT NOT NULL, sent_at TEXT NOT NULL, expires_at INTEGER NOT NULL,
        PRIMARY KEY (recipient, seq), UNIQUE (recipient, sender, msg_id));
      CREATE TABLE IF NOT EXISTS counters (recipient TEXT PRIMARY KEY, next INTEGER NOT NULL);`);
  }

  #purge(to: string, now: Date): void {
    this.#db.prepare("DELETE FROM mail WHERE recipient = ? AND expires_at <= ?").run(to, now.getTime());
  }

  async append(to: string, from: string, msgId: string, body: string, ttlSeconds: number, now: Date): Promise<AppendResult> {
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      this.#purge(to, now);
      const same = this.#db.prepare("SELECT seq FROM mail WHERE recipient = ? AND sender = ? AND msg_id = ?").get(to, from, msgId) as { seq: number } | undefined;
      if (same) {
        this.#db.exec("COMMIT");
        return { seq: same.seq, duplicate: true };
      }
      const count = (this.#db.prepare("SELECT count(*) AS n FROM mail WHERE recipient = ?").get(to) as { n: number }).n;
      if (count >= MAILBOX_LIMIT) {
        this.#db.exec("COMMIT");
        return { full: true };
      }
      const row = this.#db.prepare("SELECT next FROM counters WHERE recipient = ?").get(to) as { next: number } | undefined;
      const seq = row?.next ?? 1;
      this.#db.prepare("INSERT INTO counters (recipient, next) VALUES (?, ?) ON CONFLICT (recipient) DO UPDATE SET next = excluded.next").run(to, seq + 1);
      this.#db.prepare("INSERT INTO mail (recipient, seq, sender, msg_id, body, sent_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .run(to, seq, from, msgId, body, now.toISOString(), now.getTime() + ttlSeconds * 1000);
      this.#db.exec("COMMIT");
      return { seq, duplicate: false };
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  async pending(to: string, now: Date, afterSeq = 0): Promise<MailEntry[]> {
    this.#purge(to, now);
    const rows = this.#db.prepare("SELECT seq, sender, msg_id, body, sent_at, expires_at FROM mail WHERE recipient = ? AND seq > ? ORDER BY seq")
      .all(to, afterSeq) as Array<{ seq: number; sender: string; msg_id: string; body: string; sent_at: string; expires_at: number }>;
    return rows.map((r) => ({ to, from: r.sender, msgId: r.msg_id, seq: r.seq, body: r.body, sentAt: r.sent_at, expiresAt: r.expires_at }));
  }

  async ack(to: string, seq: number): Promise<boolean> {
    return Number(this.#db.prepare("DELETE FROM mail WHERE recipient = ? AND seq = ?").run(to, seq).changes) > 0;
  }

  close(): void {
    this.#db.close();
  }
}
// #endregion portable-mailbox
