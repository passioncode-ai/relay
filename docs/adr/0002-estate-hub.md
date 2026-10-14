# ADR-0002 — One estate hub per estate, and a session that is a serializable record

- **Date:** 2026-10-12
- **Status:** accepted for release iteration 1 (orchestrator decision D1, "one hibernating Durable Object per estate";
  design in the iteration's dossier FG §3.1–3.5 and §4.1–4.2, Project Observatory
  `docs/runs/2026-10-12-release-iteration-1/`).
- **Closes:** RLY-012 (presence wrong after a session object dies without a close), RLY-014 (one non-hibernating
  Durable Object per connection with a 1 s interval), with RLY-013 (the subscribe/pending race) closed as a consequence.

## Context

Before this decision each build ran a session per connection with its own 1 s timer, and everything that spans
connections was a separate store reached by message:

- **Hosted.** Every upgrade got a fresh Durable Object that held its socket without hibernation (`server.accept()`, a
  1 s `setInterval`, so billed around the clock). It registered itself by object id with the recipient's mailbox object
  and with one presence object. Presence counted persisted connection rows. A deploy restarts every Durable Object and
  drops every socket without a close event, so every row went stale and a machine that reconnected was never announced
  `online` again (RLY-012).
- **Portable.** One process held every socket but still ran a 1 s interval per connection, and its presence store kept
  its own connection map beside the server's.
- **Neither** could stop: nothing knew every session (RLY-010).

## Decision

1. **One `EstateHub` per estate, in the runtime-neutral core** (`src/core/hub.ts`). It owns what spans connections:
   - the connection set: each entry is a transport paired with its `RelaySession`;
   - **presence, derived from that set**: a kid is online iff an admitted session in the set has it. `online` and
     `offline` are computed by comparing before and after each event and pushed to the other sessions synchronously,
     inside the hub, so they arrive in event order. Only `lastSeen` is stored (`LastSeenStore`), forward only;
   - the admission set every session admits from (`hub.admission()`; the adapter's holder today, the estate cache of
     RLY-001 later);
   - **one scheduler**: `nextWake()` is the earliest deadline over every session (and the admission refresh, through
     the `refresh` hook), handed to the adapter's single timer through `arm` after every event; `onWake()` ticks the due
     sessions; a refresh that fails (`refresh-fault`) or succeeds while still due (`refresh-stalled`) is retried no
     sooner than `REFRESH_RETRY_MS` later, so it never spins the timer;
   - mailbox wake-ups: `wake(kid)` flushes that machine's sessions, each flush single-flight with a "run again" flag;
     a flush reads the mailbox a page at a time and stops while the transport says it is backlogged
     (`SessionIo.backlogged`); `drained(conn)` resumes it and counts as activity for the idle close;
   - at most `maxSessionsPerMachine` (default 8) admitted sessions per machine: the next is refused `rate-limited`, 1013;
   - `stop()`: closes every session through its own close (1001), writes `lastSeen`, announces nothing, and waits for
     the transports. A second call shares the first one's wait.
2. **A session is a serializable `SessionRecord`** (`snapshot()`, `RelaySession.restore()`, `nextDeadline()`), handed
   to `SessionIo.persist` after every change. It is under 1 KiB, well inside a WebSocket attachment's 16 KiB. **Any
   per-session state a later change adds goes into the record**, never into a hub-side map keyed by connection (A's
   admitted revision, D's token bucket, C's delivered seq).
3. **A relay fault is closed through the session**: `RelaySession.fault()` logs `session-fault`, sends `error internal`,
   then closes 1011. The hub calls it when handling a frame rejects. It never throws: a transport whose `send` throws
   is still closed. The hub faults such a session alone wherever it writes to it (a presence push, a deadline, a
   mailbox wake), so one bad socket never costs another session its event, rejects `receive` or stops the timer from
   re-arming. An adapter closes 1011 itself only where there is no session to fault, and then the same way: the hosted hub, waking with a socket that carries no session record,
   sends that socket `error internal` and then closes it 1011 (`RelayEstate`'s rebuild).
4. **Each build hosts exactly one hub per estate.**
   - Hosted: one hibernating Durable Object, `RelayEstate` (`src/cloudflare/estate.ts`), with the WebSocket
     Hibernation API and one alarm. The per-connection `RelaySession` and the `RelayPresence` objects are deleted.
   - Portable: one hub in the process, one `setTimeout`.
5. **The core stays web-standard**: no `Buffer` (the body-size check computes a base64url length), and one log line
   shape for both builds, `{at, service: "relay", runtime, event, …}` (`src/core/log.ts`).

## Options considered

1. **Presence after an object dies without a close.**
   - (a) Leases on connection rows plus per-kid version stamps.
   - (b) One hub per estate that derives presence from the live socket set. **Chosen.** It removes the stored state
     that goes stale instead of expiring it, and push order becomes a property of one single-threaded object.
   - (c) Keep per-connection objects and sweep with `alive()` probes on an alarm: keeps the RPC fan-out and a stale
     window.
2. **Hibernation shape.**
   - (a) A hibernating Durable Object per connection: one alarm per connection, and presence and mailbox objects still
     address sessions by object id, so it inherits RLY-012.
   - (b) One hibernating Durable Object per estate. **Chosen.** The one-alarm-per-object limit is no constraint, since
     the hub computes one earliest deadline; 32 768 hibernatable sockets per object is far above an estate of a
     person's machines. An organization relay with thousands of machines would shard the hub by kid later.
3. **The mailbox inside the hub, or separate.** **Separate.** Per-recipient mailbox objects keep each recipient's
   storage out of the hub; the hub only receives `wake(kid)`.

## Consequences

- **Isolation moves from the connection to the estate.** One hub holds only machines of one estate record, all of one
  owner (DEC-0047 item 4). Each session still writes only to its own socket and acts only for its own kid.
- **Keys go through one `contextKey()`** (relay RLY-08; CX-REL-01): the hub's and the mailboxes' Durable Object names
  and every R2 key are derived from it in `src/cloudflare/context.ts`. It is a constant while one relay origin serves one context; in a multi-context relay it becomes
  the per-context pseudonymous id, **never the estate id**.
- The protocol `ping` carries a varying id, so the runtime's exact-match auto-response cannot answer it: each ping wakes
  the hub for one event, and duration is billed only while an event runs.
- Wire protocol unchanged: shutdown uses 1001, already the contract's `CLOSE_CODES.idle`.
