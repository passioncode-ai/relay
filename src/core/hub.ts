// #region relay-hub — docs: docs/adr/0002-estate-hub.md
// The estate hub: one per estate in both builds (RLY-012, RLY-014). It owns everything that spans connections:
// - the connection set, each entry a transport paired with its `RelaySession`;
// - presence, derived from that set (a kid is online iff an admitted session in the set has it) and pushed to the other
//   sessions synchronously, so `presence` frames arrive in event order; only `lastSeen` is stored;
// - the admission set sessions admit from (today the adapter's holder; the estate cache of RLY-001 replaces it);
// - one scheduler: `nextWake()` is the earliest deadline of every session (and of the admission refresh, when one is
//   hooked in), handed to the adapter's single timer through `arm` after every event;
// - mailbox wake-ups: `wake(kid)` flushes that machine's sessions, each flush single-flight with a "run again" flag;
// - shutdown: `stop()` closes every session through the session's own close and waits for the transports.
//
// The hosted build runs one hub in one hibernating Durable Object per estate (src/cloudflare/estate.ts), the portable
// build one hub in its process (src/portable/server.ts). A hub holds only machines of one estate record, all of one
// owner (DEC-0047 item 4); each session still writes only to its own socket and acts only for its own kid.

import type { AdmissionResult } from "../contract/relay.ts";
import { errorFields, type Log } from "./log.ts";
import type { MailboxStore } from "./mailbox.ts";
import type { LastSeenStore, PresenceRecord } from "./presence.ts";
import { RelaySession, type SessionEnv, type SessionHub, type SessionIo, type SessionRecord } from "./session.ts";

export interface HubDeps {
  now: () => Date;
  nonce: () => string; // 32 random bytes, base64url
  sessionId: () => string;
  /** The verified admission set every session of the hub admits from (src/core/admission.ts). */
  admission: () => AdmissionResult;
  /** Store-and-forward (RLY-03); without it messages are answered "not served yet". */
  mailbox?: MailboxStore;
  /** Each machine's `lastSeen` (RLY-06); without it presence is answered "not served yet". */
  lastSeen?: LastSeenStore;
  /**
   * The adapter's one timer: called after every event with the hub's next wake (epoch ms), or undefined when nothing is
   * due. The Worker maps it to the Durable Object's alarm, the portable build to one `setTimeout`. It calls `onWake()`.
   */
  arm?: (at: number | undefined) => void;
  /**
   * Whether a session's `send` wakes the recipient's sessions in process (default). The Worker sets false: its mailbox
   * object calls the hub's `wake(kid)` itself once the message is stored.
   */
  wakeOnQueued?: boolean;
  /**
   * A hook for the admission refresh (RLY-001): its deadline joins `nextWake()`, and `onWake()` runs it when due and
   * awaits it. A run that throws or rejects is logged `refresh-fault`, and one that succeeds while its deadline stays
   * due is logged `refresh-stalled`; either way the hub retries it no sooner than `REFRESH_RETRY_MS` later, so a
   * refresh never spins the timer.
   */
  refresh?: { deadline(): number | undefined; run(now: Date): void | Promise<void> };
  /** At most this many admitted sessions per machine (default DEFAULT_MAX_SESSIONS_PER_MACHINE); the next is refused 1013. */
  maxSessionsPerMachine?: number;
  log?: Log;
}

/**
 * How many admitted sessions one machine may hold at once in a hub. Each session gets its own copy of every delivery,
 * so this bounds what one machine can make the relay hold for it: at most this many times one session's send window.
 */
export const DEFAULT_MAX_SESSIONS_PER_MACHINE = 8;

/** How long the hub waits before running a refresh again after one failed, or one that left its deadline due. */
export const REFRESH_RETRY_MS = 5000;

export interface StopOptions {
  code?: number;
  reason?: string;
  /** How long to wait for every transport to report its close. */
  graceMs?: number;
}

export class EstateHub<C = unknown> implements SessionHub {
  readonly #entries = new Map<C, RelaySession>();
  #stopping = false;
  #armed: number | undefined;
  #drained: (() => void) | undefined;
  #stopped: Promise<{ sessions: number; unclosed: C[] }> | undefined;
  #refreshRetryAt: number | undefined;
  #refreshing: Promise<void> | undefined;
  readonly presence: SessionHub["presence"];

  constructor(private readonly deps: HubDeps) {
    const lastSeen = deps.lastSeen;
    this.presence = lastSeen
      ? {
          touch: (kid, at) => void this.#seen(kid, at),
          query: (kids) => {
            const out: PresenceRecord[] = [];
            for (const kid of new Set(kids)) {
              const seen = this.#read(kid);
              if (seen) out.push({ kid, state: this.#online(kid) ? "online" : "offline", lastSeen: seen });
            }
            return out;
          },
        }
      : undefined;
  }

  #env(relay: string): SessionEnv {
    return {
      relay, now: this.deps.now, nonce: this.deps.nonce, sessionId: this.deps.sessionId, admission: () => this.admission(),
      ...(this.deps.mailbox ? { mailbox: this.deps.mailbox } : {}), hub: this, ...(this.deps.log ? { log: this.deps.log } : {}),
    };
  }

  /** The admission set right now, the same for every session of the estate. */
  admission(): AdmissionResult {
    return this.deps.admission();
  }

  /** A new connection: its session greets it with `hello`. While the hub stops, the connection is closed 1001 at once. */
  connect(conn: C, io: SessionIo, relay: string): RelaySession | undefined {
    if (this.#stopping) {
      io.close(1001, "relay stopping");
      return undefined;
    }
    const session = new RelaySession(io, this.#env(relay));
    this.#entries.set(conn, session);
    session.open();
    this.#arm();
    return session;
  }

  /** A connection the runtime kept while the hub was away (a hibernation wake): its session continues from its record. */
  restore(conn: C, io: SessionIo, record: SessionRecord): RelaySession {
    const session = RelaySession.restore(io, this.#env(record.relay), record);
    this.#entries.set(conn, session);
    return session;
  }

  session(conn: C): RelaySession | undefined {
    return this.#entries.get(conn);
  }

  /** How many transports the hub holds, closed sessions whose transport has not reported its close included. */
  get size(): number {
    return this.#entries.size;
  }

  /** One frame from a connection. A fault while handling it closes that session 1011 through `RelaySession.fault`. */
  async receive(conn: C, data: string | Uint8Array | ArrayBuffer): Promise<void> {
    const session = this.#entries.get(conn);
    if (!session) return;
    try {
      await session.receive(data);
    } catch (error) {
      session.fault(error);
    } finally {
      this.#arm();
    }
  }

  /** The transport of `conn` closed, from either side: its session ends and leaves the set. */
  closed(conn: C): void {
    const session = this.#entries.get(conn);
    if (!session) return;
    this.#entries.delete(conn);
    session.disconnected();
    this.#arm();
    if (this.#entries.size === 0) this.#drained?.();
  }

  /** The earliest instant (epoch ms) at which a session or the admission refresh needs the hub; undefined for none. */
  nextWake(): number | undefined {
    // A refresh that is running is not due again: its deadline joins the timer once it has finished.
    let at = this.#refreshing ? undefined : this.deps.refresh?.deadline();
    if (at !== undefined && this.#refreshRetryAt !== undefined && at < this.#refreshRetryAt) at = this.#refreshRetryAt;
    for (const session of this.#entries.values()) {
      const due = session.nextDeadline();
      if (due !== undefined && (at === undefined || due < at)) at = due;
    }
    return at;
  }

  /**
   * The adapter's timer fired: every due session acts on its deadline, the refresh runs (awaited) if due, and the timer
   * is armed again for whatever is due next. One refresh runs at a time: a wake while one runs does not start another.
   * A session whose deadline throws (its transport's `send` throws) is faulted alone; the timer is re-armed whatever
   * happens, and `onWake` never rejects.
   */
  async onWake(): Promise<void> {
    const now = this.deps.now();
    try {
      for (const session of [...this.#entries.values()]) {
        const due = session.nextDeadline();
        if (due === undefined || due > now.getTime()) continue;
        try {
          session.tick();
        } catch (error) {
          session.fault(error);
        }
      }
      const refresh = this.deps.refresh;
      const due = refresh?.deadline();
      const retryOk = this.#refreshRetryAt === undefined || this.#refreshRetryAt <= now.getTime();
      if (refresh && !this.#refreshing && due !== undefined && due <= now.getTime() && retryOk) {
        this.#refreshing = (async () => {
          try {
            await refresh.run(now);
            const next = refresh.deadline();
            if (next !== undefined && next <= now.getTime()) {
              // It succeeded but is still due: arming that deadline would fire the timer again at once, for ever.
              this.deps.log?.({ event: "refresh-stalled", deadline: new Date(next).toISOString() });
              this.#refreshRetryAt = now.getTime() + REFRESH_RETRY_MS;
            } else {
              this.#refreshRetryAt = undefined;
            }
          } catch (error) {
            this.deps.log?.({ event: "refresh-fault", ...errorFields(error) });
            this.#refreshRetryAt = now.getTime() + REFRESH_RETRY_MS;
          } finally {
            this.#refreshing = undefined;
          }
        })();
        await this.#refreshing;
      }
    } finally {
      this.#armed = Number.NaN; // the timer that fired is spent: arm again whatever is due next
      this.#arm();
    }
  }

  /**
   * The transport of `conn` can take more (its socket drained): the machine is reading, which counts as activity for
   * the idle close, and its session goes on delivering from the mailbox. Never rejects.
   */
  async drained(conn: C): Promise<void> {
    const session = this.#entries.get(conn);
    if (!session) return;
    session.progressed();
    await session.wake();
    this.#arm();
  }

  /** A message was queued for `kid`: every session that machine holds delivers what waits for it. */
  async wake(kid: string): Promise<void> {
    const sessions = [...this.#entries.values()].filter((session) => session.state === "admitted" && session.kid === kid);
    await Promise.all(sessions.map((session) => session.wake()));
    this.#arm();
  }

  /**
   * Stop: every session is closed with `code` (1001, "going away") through its own close, so each admitted machine's
   * `lastSeen` is written; nothing is announced meanwhile. Resolves when every transport has reported its close, or at
   * `graceMs`, naming the connections that did not (the adapter terminates them). A second call returns the first
   * call's promise; its options are not applied.
   */
  stop(options: StopOptions = {}): Promise<{ sessions: number; unclosed: C[] }> {
    // A second call (a second signal, an adapter and a test both stopping) shares the first one's wait rather than
    // replacing its drain callback, which would leave the first waiting out the whole grace period.
    this.#stopped ??= this.#stop(options);
    return this.#stopped;
  }

  async #stop({ code = 1001, reason = "relay stopping", graceMs = 5000 }: StopOptions): Promise<{ sessions: number; unclosed: C[] }> {
    this.#stopping = true;
    const sessions = this.#entries.size;
    for (const session of [...this.#entries.values()]) {
      try {
        session.close(code, reason);
      } catch (error) {
        session.fault(error);
      }
    }
    this.#arm();
    if (this.#entries.size > 0) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      await new Promise<void>((resolve) => {
        this.#drained = resolve;
        timer = setTimeout(resolve, graceMs);
      });
      clearTimeout(timer);
      this.#drained = undefined;
    }
    return { sessions, unclosed: [...this.#entries.keys()] };
  }

  get stopping(): boolean {
    return this.#stopping;
  }

  // SessionHub: what a session tells the hub.

  joined(session: RelaySession): void {
    const kid = session.kid as string;
    const wasOnline = this.#online(kid, session);
    const lastSeen = this.#seen(kid, this.deps.now());
    if (!wasOnline) this.#publish({ kid, state: "online", lastSeen });
  }

  left(session: RelaySession): void {
    const kid = session.kid as string;
    const lastSeen = this.#seen(kid, this.deps.now());
    if (!this.#online(kid)) this.#publish({ kid, state: "offline", lastSeen });
  }

  hasRoom(kid: string): boolean {
    const limit = this.deps.maxSessionsPerMachine ?? DEFAULT_MAX_SESSIONS_PER_MACHINE;
    let held = 0;
    for (const session of this.#entries.values()) if (session.state === "admitted" && session.kid === kid) held += 1;
    if (held < limit) return true;
    this.deps.log?.({ event: "session-limit", kid, limit });
    return false;
  }

  queued(kid: string): void {
    if (this.deps.wakeOnQueued !== false) void this.wake(kid);
  }

  /** Online iff an admitted session in the set (other than `except`) has the kid. */
  #online(kid: string, except?: RelaySession): boolean {
    for (const session of this.#entries.values()) if (session !== except && session.state === "admitted" && session.kid === kid) return true;
    return false;
  }

  /**
   * Pushes one presence change to every session. A session whose transport throws is faulted after the loop, so it
   * neither costs the session whose event caused the change (its auth, its close) nor stops the others hearing it.
   */
  #publish(record: PresenceRecord): void {
    if (this.#stopping || !this.presence) return;
    const failed: Array<[RelaySession, unknown]> = [];
    for (const session of [...this.#entries.values()]) {
      try {
        session.presence(record);
      } catch (error) {
        failed.push([session, error]);
      }
    }
    for (const [session, error] of failed) session.fault(error);
  }

  #read(kid: string): string | undefined {
    try {
      return this.deps.lastSeen?.get(kid);
    } catch (error) {
      this.deps.log?.({ event: "presence-fault", ...errorFields(error) });
      return undefined;
    }
  }

  /** Moves `lastSeen` forward, never back, and answers it. A store that fails is logged; it costs no session. */
  #seen(kid: string, at: Date): string {
    const value = at.toISOString();
    if (!this.deps.lastSeen) return value;
    const before = this.#read(kid);
    if (before && before >= value) return before;
    try {
      this.deps.lastSeen.put(kid, value);
    } catch (error) {
      this.deps.log?.({ event: "presence-fault", ...errorFields(error) });
    }
    return value;
  }

  #arm(): void {
    const at = this.nextWake();
    if (at === this.#armed) return;
    this.#armed = at;
    this.deps.arm?.(at);
  }
}
// #endregion relay-hub
