// #region portable-presence — docs: docs/protocol/sessions.md#presence
// The self-hosted relay's presence: who is connected lives in memory (connections end with the process), and each
// machine's `lastSeen` lives in one owner-only SQLite file, so after a restart the relay can still say when an offline
// machine was last seen.

import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { MemoryPresence } from "../core/presence.ts";

export class SqlitePresence extends MemoryPresence {
  readonly #db: DatabaseSync;

  constructor(file: string) {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    const db = new DatabaseSync(file);
    chmodSync(file, 0o600);
    db.exec("PRAGMA journal_mode = WAL; CREATE TABLE IF NOT EXISTS last_seen (kid TEXT PRIMARY KEY, at TEXT NOT NULL);");
    const rows = db.prepare("SELECT kid, at FROM last_seen").all() as Array<{ kid: string; at: string }>;
    const upsert = db.prepare("INSERT INTO last_seen (kid, at) VALUES (?, ?) ON CONFLICT (kid) DO UPDATE SET at = excluded.at");
    super(rows.map((row) => [row.kid, row.at] as [string, string]), (kid, at) => void upsert.run(kid, at));
    this.#db = db;
  }

  close(): void {
    this.#db.close();
  }
}
// #endregion portable-presence
