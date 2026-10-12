// #region relay-presence — docs: docs/protocol/sessions.md#presence
// Presence and "last seen" (DEC-0047, Messages: Presence; Fabric ADR-0088's offline rule). A relay serves one estate,
// and every machine it admits is a machine of that estate's record, so every admitted machine is of the same owner:
// presence goes to them and to nobody else, and only for kids in the set the relay currently admits (the same verified
// set as admission). A machine is online while it holds at least one admitted connection; `lastSeen` is when the relay
// last heard from it — a connection admitted, a frame, a connection ended. The relay reports what it saw and never
// invents a time: a machine it never saw has no presence to report.

/** One machine's presence, as the `presence` frame carries it. */
export interface PresenceRecord {
  kid: string;
  state: "online" | "offline";
  lastSeen: string; // RFC 3339, UTC
}

/**
 * Who is connected and when each machine was last seen. Implementations: `MemoryPresence` (tests, one process; the
 * portable build with its last-seen times in SQLite) and the Worker's presence Durable Object.
 */
export interface PresenceStore {
  /** A connection of `kid` was admitted. Its first connection publishes `online` to every subscriber. */
  connected(kid: string, connection: string, at: Date): Promise<void>;
  /** That connection ended. Its last connection publishes `offline` to every subscriber. */
  disconnected(kid: string, connection: string, at: Date): Promise<void>;
  /** The machine was heard from: `lastSeen` moves, nothing is published. */
  touch(kid: string, at: Date): Promise<void>;
  /** The presence of each kid the relay has seen, in the order asked; a kid never seen is left out. */
  query(kids: readonly string[]): Promise<PresenceRecord[]>;
  /** Changes reach `listener` until the returned function is called. */
  subscribe(connection: string, listener: (record: PresenceRecord) => void): () => void;
}

/** How often a session moves `lastSeen` while frames keep arriving: often enough for a person, cheap for a store. */
export const TOUCH_INTERVAL_SECONDS = 30;

const stamp = (at: Date) => at.toISOString();

export class MemoryPresence implements PresenceStore {
  readonly #connections = new Map<string, Set<string>>(); // kid → its live connections
  readonly #lastSeen: Map<string, string>;
  readonly #listeners = new Map<string, (record: PresenceRecord) => void>();

  /** `lastSeen` restored from a previous run, if the adapter keeps one; `remember` is told every change. */
  constructor(lastSeen: Iterable<[string, string]> = [], private readonly remember?: (kid: string, lastSeen: string) => void) {
    this.#lastSeen = new Map(lastSeen);
  }

  #seen(kid: string, at: Date): string {
    const value = stamp(at);
    const before = this.#lastSeen.get(kid);
    if (before && before > value) return before; // a late report never moves the time back
    this.#lastSeen.set(kid, value);
    this.remember?.(kid, value);
    return value;
  }

  #publish(record: PresenceRecord): void {
    for (const listener of this.#listeners.values()) listener({ ...record });
  }

  async connected(kid: string, connection: string, at: Date): Promise<void> {
    let live = this.#connections.get(kid);
    if (!live) this.#connections.set(kid, (live = new Set()));
    const first = live.size === 0;
    live.add(connection);
    const lastSeen = this.#seen(kid, at);
    if (first) this.#publish({ kid, state: "online", lastSeen });
  }

  async disconnected(kid: string, connection: string, at: Date): Promise<void> {
    const live = this.#connections.get(kid);
    if (!live?.delete(connection)) return; // never connected, or already gone: nothing changed
    const lastSeen = this.#seen(kid, at);
    if (live.size === 0) {
      this.#connections.delete(kid);
      this.#publish({ kid, state: "offline", lastSeen });
    }
  }

  async touch(kid: string, at: Date): Promise<void> {
    this.#seen(kid, at);
  }

  async query(kids: readonly string[]): Promise<PresenceRecord[]> {
    const out: PresenceRecord[] = [];
    for (const kid of new Set(kids)) {
      const lastSeen = this.#lastSeen.get(kid);
      if (lastSeen) out.push({ kid, state: this.#connections.has(kid) ? "online" : "offline", lastSeen });
    }
    return out;
  }

  subscribe(connection: string, listener: (record: PresenceRecord) => void): () => void {
    this.#listeners.set(connection, listener);
    return () => this.#listeners.delete(connection);
  }
}
// #endregion relay-presence
