// #region relay-presence — docs: docs/protocol/sessions.md#presence
// Presence and "last seen" (DEC-0047, Messages: Presence; Fabric ADR-0088's offline rule). A relay serves one estate,
// and every machine it admits is a machine of that estate's record, so every admitted machine is of the same owner:
// presence goes to them and to nobody else, and only for kids in the set the relay currently admits (the same verified
// set as admission). A machine is online while it holds at least one admitted connection; `lastSeen` is when the relay
// last heard from it — a connection admitted, a frame, a connection ended. The relay reports what it saw and never
// invents a time: a machine it never saw has no presence to report.
//
// Who is online is not stored anywhere: the estate hub (hub.ts) derives it from its live connection set, so nothing can
// go stale when a runtime drops every socket at once (RLY-012). `lastSeen` is the only presence state that is kept.

/** One machine's presence, as the `presence` frame carries it. */
export interface PresenceRecord {
  kid: string;
  state: "online" | "offline";
  lastSeen: string; // RFC 3339, UTC
}

/**
 * Each machine's `lastSeen`, durable across restarts. The hub moves it forward only. Implementations: `MemoryLastSeen`
 * (tests), `SqliteLastSeen` (portable, `presence.sqlite`) and the hub Durable Object's SQLite storage (hosted).
 */
export interface LastSeenStore {
  get(kid: string): string | undefined;
  put(kid: string, at: string): void;
}

/** How often a session moves `lastSeen` while frames keep arriving: often enough for a person, cheap for a store. */
export const TOUCH_INTERVAL_SECONDS = 30;

export class MemoryLastSeen implements LastSeenStore {
  readonly #seen: Map<string, string>;
  constructor(seen: Iterable<[string, string]> = []) {
    this.#seen = new Map(seen);
  }
  get(kid: string): string | undefined {
    return this.#seen.get(kid);
  }
  put(kid: string, at: string): void {
    this.#seen.set(kid, at);
  }
}
// #endregion relay-presence
