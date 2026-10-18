# Handoff

**Wave 2 status (2026-10-17).** Wave 1 is merged (relay#8, relay#10 as `5fa0d881`). The first wave-2 pull request,
branch `wave2/rp-dec0066`, carries:
- **RP:** the contract pinned at fabric-agent-contract `bf3fd6b`; every shared-vector case runs here; tests sign
  through the contract's `signEs256`.
- **D-1:** frames classified against the AOT relay-frame schema (`src/core/frames.ts`); `replyTo` on every answer;
  `presence-result`; close codes from `closeCodeFor`; `malformed` and `unknown-type` as DEC-0066 splits them.
- **DEC-0066's other relay deltas that need no new state:** one-answer `unauthenticated` auth refusals with the
  estate bound; the genesis delta head; blobs in the contract's order of checks (411, 409 after the digest, 403 never
  404, a repeat `PUT` restores); the portable origin checked against `RELAY_ORIGIN_PATTERN`.
- **Regression:** the engine's walking skeleton (`observatory/engine/tools/node_skeleton.py`, project-observatory-dashboard
  `main`) passes every step against this branch on loopback, presence included; against relay `main` its presence
  step times out, because the engine's node waits for the `presence-result` this branch adds.
- **Still open from DEC-0066, by node:** A-4 (revalidate open sessions: 4403 `not-admitted`/`expired` before any
  frame), D-2 (`welcome.limits`, `rate-limited` with `retryAfter`, msgId tombstones after an ack), H-1/H-2 (delta and
  heartbeat ingress and carry, `delta-query`, `extraRevocations`), A-3/A-5/A-6/A-7 (estate cache, adapters' estate
  handling, health).
- **A flake to watch:** `tests/shutdown.test.ts` "a distinct second press … forces the stop" failed once in a full
  Node 24 run of this branch (the exit code was not seen within 3 s) and passed in isolation three times and on the
  next full run. It is a timing test of the portable process; if it fails again, widen its wait or measure the stop
  under load.
- **A CI flake to settle before merge:** on GitHub's Node 24 job, the round-8 flood tests (`overflow()` in
  `tests/flow-control.test.ts`, pongs alone) either pass in under a second or find no `send-overflow` in 30 s. They
  failed in 3 of 7 Node 24 attempts on this branch's heads and in none of `main`'s runs, and never locally. The
  helper now prints the client's state and the relay's last events when it fails; read that log the next time it
  fails, before changing anything.
- **Exact next task:** A-3 (`EstateCache`), then A-6, A-4, A-5, A-7; then D-2; then G-4, in the order of the
  iteration's `workgraph.json`.

**Where the work stood (2026-10-12, release iteration 1, wave 1).**

- **Done and merged on `main`:**
  - RLY-01: DEC-0047 merged in fabric-agent-contract (#53, `8060254`).
  - RLY-02: relay#1 `fa3d07f`.
  - RLY-03: relay#3 `05072c9`.
  - RLY-06: relay#5 `20bf599`.
  - Backlog rows RLY-07 and RLY-08: relay#6 and #7.
- **Pin.** fabric-agent-contract `51719e4`, the merge of #61, until wave 2's node RP moved it to `bf3fd6b` (above).
- **In review (wave 1 of release iteration 1):**
  - relay#8: FB-0 (Worker split), F-1 (the serializable session record and the runtime-neutral estate hub) and F-2
    (the Worker on one hibernating Durable Object per estate).
  - The pull request stacked on it: F-4 (one normalised origin), F-3 (graceful stop), G-3 (`revise()`/`forge()`)
    and G-1 (this truth pass).
  - The plan, the inventory and the canvas are in Project Observatory
    `docs/runs/2026-10-12-release-iteration-1/`.
- **Durable state, both builds.**
  - Mailboxes: one SQLite-backed Durable Object per recipient (hosted); `mailbox.sqlite` (portable).
  - `lastSeen`: the estate hub's SQLite storage (hosted); `presence.sqlite` (portable).
  - Sessions are records in their sockets' attachments (hosted) or in memory (portable). Who is online is derived,
    never stored.
- **Flow control** ([sessions.md, Flow control](protocol/sessions.md)): a session's flush reads the mailbox a page at
  a time and, where the transport reports a backlog (portable), sends only while under 1 MiB is queued, going on at
  each drain; the socket is always read; replies are capped at 3 MiB or 4096 frames per session, checked before each
  write (`send-overflow`, 1008); ids and msgIds are held to 128 code points, so no frame exceeds 1 MiB; at most 8
  sessions per machine (1013); the portable socket heartbeat (10 s, monotonic) terminates only a socket with nothing
  outstanding that stopped answering (30 to 40 s); a socket with bytes outstanding is left to the idle close, 5 minutes
  while bytes are outstanding (90 s otherwise). Progress is only what the peer confirms (a frame, or a pong matching
  a heartbeat ping with a random payload); the relay answers WebSocket pings itself under the send caps. Floor: about
  9 to 10 KiB/s on Linux defaults (about 7 KiB/s on macOS), acks not required; a slower reader is closed 1001 and keeps
  its mail. The hosted build has no backlog signal (page of 64) and no
  heartbeat (90 s idle close). Bound: 8 x 3 MiB queued per machine; `Served.flow().peakBuffered` shows it.
- Decision records: [ADR-0001](adr/0001-relay-repository.md) (with Amendment 1) and [ADR-0002](adr/0002-estate-hub.md).

**Decisions already taken:**
- own repository;
- AGPL-or-commercial;
- Project Observatory owns the server code;
- protocol in fabric-agent-contract DEC-0047, admission from DEC-0055's estate record;
- the hosted relay is run by PassionCode.ai; one hibernating estate hub per estate;
- the self-hosted relay stays, as the portable build.

**The exact next task.** Wave 2 of release iteration 1, after relay#8 and its stacked pull request merge:
- RP: re-pin the contract at N19's merge;
- then, in the order of the iteration's `workgraph.json`:
  - A-3 (`EstateCache`; it reuses `tests/estate-fixture.ts` `revise()`/`forge()`), A-6 (`/healthz` reports
    admission), A-4 (revalidating open sessions through the hub), then A-5 and A-7;
  - D-1, D-2;
  - G-4.
- RLY-07 (deltas and heartbeats) is unblocked and is wave 4 (H-1, H-2).
- **Wave 2 backlog, from relay#10 review round 14: byte-based heartbeat markers.** Today a marker ping follows only a
  frame of 64 KiB or more, no beat ping is sent while an earlier one is unwritten, `bufferedAmount` misses the kernel's
  buffers, and markers stop at 64 awaiting pongs; round 14 measured gaps of 1.9 to 2.7 MiB between confirmable points
  (its probes P2b, P2c and P3), hence a floor of about 9 to 10 KiB/s on Linux. Place a marker every 64 KiB written,
  whatever the frame size, and allow markers past an unwritten ping; then re-measure the floor and restate it in
  `docs/protocol/sessions.md` (Flow control).

**RLY-05, the hosted deployment, is agent work** (iteration nodes F-6, F-7, F-8):
- scoped tokens are issued through Observatory's Cloudflare door into vault slots;
- the release workflow is built behind the organization's release guard, and the agent deploys and tags.
- **One conditional human gate:** if the door reports that R2 is not enabled on the account, enabling it asks for
  billing details, and the operator does that. Until the first deploy, the hosted build is tested locally (workerd
  through Miniflare).
