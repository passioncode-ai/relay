// #region portable-last-seen — docs: docs/protocol/sessions.md#presence
// The self-hosted relay's `lastSeen`: one owner-only SQLite file, so after a restart the relay can still say when an
// offline machine was last seen. Who is connected is not stored: the estate hub derives it from its live connections.

import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync, type StatementSync } from "node:sqlite";
import type { LastSeenStore } from "../core/presence.ts";

export class SqliteLastSeen implements LastSeenStore {
  readonly #db: DatabaseSync;
  readonly #get: StatementSync;
  readonly #put: StatementSync;

  constructor(file: string) {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    this.#db = new DatabaseSync(file);
    chmodSync(file, 0o600);
    this.#db.exec("PRAGMA journal_mode = WAL; CREATE TABLE IF NOT EXISTS last_seen (kid TEXT PRIMARY KEY, at TEXT NOT NULL);");
    this.#get = this.#db.prepare("SELECT at FROM last_seen WHERE kid = ?");
    this.#put = this.#db.prepare("INSERT INTO last_seen (kid, at) VALUES (?, ?) ON CONFLICT (kid) DO UPDATE SET at = max(at, excluded.at)");
  }

  get(kid: string): string | undefined {
    return (this.#get.get(kid) as { at: string } | undefined)?.at;
  }

  put(kid: string, at: string): void {
    this.#put.run(kid, at);
  }

  close(): void {
    this.#db.close();
  }
}
// #endregion portable-last-seen
