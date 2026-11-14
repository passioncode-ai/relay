# Handoff

**Board read (2026-11-14, second read).** A session Fabric started for the board's one unread message (thread
`16093ded`, 01:28 UTC; workflow `wf_e49020921a6c68aa`) read it; no relay code changed and no answer was owed.
- **Read:** Kira's (passioncode-pm-agent) message `781c7dbf` to fabric-agents-database: the org-administrator 1.28.4
  template receipt and five template proposals from Ania's layer. It names no relay track (RM-21, RLY-*) and changes
  no fact the relay records.
- **Exact next task:** unchanged, A-3 (`EstateCache`), then A-6, A-4, A-7 by 2026-11-15. None is started; a miss is
  reported in thread `d5abc880` with a new date the same day.

**Board read, lifecycle and rule acceptances (2026-11-14, first read).** A session Fabric started for the board's
unread messages (23, thread `16093ded`, 2026-11-13 20:27 to 2026-11-14 00:35 UTC; workflow `wf_be3bce54653120e0`)
read them all; no relay code changed and no answer was owed.
- **Nothing addressed to the relay:** the one request (`db3df88e`, the launcher's `release.yml` parse of
  `npm pack --json`) targets passioncode; fabric-workspace's SL roll-call (`9c492375`) lists the relay as answered.
- **Read:** acceptances of the coordinator's rule and step 0 (copylot-agent, passioncode, Kira, fabric-inbox,
  passioncode-platform, fabric-agents-database), SL-1 to SL-8 answers (fabric-agent-adapter, studio-agent,
  passioncode-platform, fabric-switchboard), the architect's audits for other agents, and passioncode-platform 0.19.1
  in production (`af43c281`). None changes a fact the relay records.
- **Exact next task:** unchanged, A-3 (`EstateCache`), then A-6, A-4, A-7 by 2026-11-15. None is started; a miss is
  reported in thread `d5abc880` with a new date the same day.

**Board read, step 0 and the coordinator's rule (2026-11-13, fifth read).** A session Fabric started for the board's
unread messages (34, thread `16093ded`, 11:32 to 20:13 UTC; workflow `wf_bfa2d07c4d4e8f42`) read them all; no relay
code changed.
- **Taken:** the operator's step 0 (relayed `3390f915`, fabric-workspace `5694460b`) is item 1c in `AGENTS.md`; the
  Fabric coordinator's rule (`35556d27`) is a paragraph under *Questions and access levels*. Both answered on the thread.
- **Step 0 run here:** `npx @passioncode-ai/passioncode doctor --json` read `fail: 0` (25 ok, 13 warn, 6 info;
  Observatory degraded on some collectors, a warn); `npx --yes sshlg-skills@latest update` ran and printed
  "super-ux: conflicting marketplace declaration", a warning for the family's updater, not for the relay.
- **Also read:** the contract's DEC-0162 and CT-299 relay (`7bb9a362`), Fabric's state (`e909c659`), Dashboards
  0.8.69 to 0.8.74 (`f293429e`), and SL, approval and step-0 answers from other projects; nothing for relay (it reads
  no `entitlement/1`; the SL-7 lease residue others name is agent-sync's, as the third read said).
- **Exact next task:** unchanged, A-3 (`EstateCache`), then A-6, A-4, A-7 by 2026-11-15. None is started; a miss is
  reported in thread `d5abc880` with a new date the same day.

**Board read, «делай на все апрув» (2026-11-13, fourth read).** A session Fabric started for the board's unread
messages (9, thread `16093ded`, 10:59 to 11:21 UTC; workflow `wf_dc90755cf773f802`) read them all; no relay code
changed.
- **Answered:** fabric-workspace's relay of the operator's decision `bd1b59db` («делай на все апрув», confirmed «Да, в
  этих рамках»: every approval waiting on him is decided with its recorded recommendation), reply `f5db82b0`: the relay
  holds none. `fabric_access_list` reads `pending: []`, `fabric_whoami` reads `questions.open: 0`, no held release, and
  no row of `docs/backlog.md` waits on an operator decision; RLY-05's deploy and access are already the agent's by
  *Questions and access levels* in `AGENTS.md`.
- **Also read:** the unlimited-tier ask for fabric-agent-contract (`caab9b65`), the roles relay for Vesta and Kira
  (`7fdbc2ed`), Vesta's org ids (`49802138`), and approval and SL answers from copylot-agent, fabric-agents-database
  and passioncode; nothing for relay (it reads no `entitlement/1` and keeps no roles).
- **Exact next task:** unchanged, A-3 (`EstateCache`), then A-6, A-4, A-7 by 2026-11-15. None is started; a miss is
  reported in thread `d5abc880` with a new date the same day.

**Board read, session lifecycle (2026-11-13, third read).** A session Fabric started for the board's unread messages
(10, thread `16093ded`, 04:14 to 09:44 UTC; workflow `wf_d717eb434fd64c0f`) read them all; no relay code changed.
- **Answered:** fabric-workspace's announcement `54f4ae9b` (coding-agent sessions SL-1 to SL-8, fabric-workspace
  `knowledge/lifecycle.md`), reply `94a8c9c1`: SL-2, SL-4, SL-6, SL-7 hold, the rest are not the relay's; no gap, no
  new row. The one residue named is agent-sync's: a lock directory of a cut run stays until reaped
  (`docs/AGENT_SYNC.md:51`).
- **Correction `39ef6f47`** (DEC-0162 and DEC-0166 are the contract's per-question record, not «все дефолты»): the
  relay never recorded 36b1981b, DEC-0162 or DEC-0166 (`git grep` on `e99bdd8` empty), nothing to correct.
- **Also read:** acceptances of the questions rule from passioncode, fabric-agents-database, fabric-agent-contract and
  Vesta, Vesta's 0.6.0/0.6.1 receipt, and SL answers from passioncode and copylot-agent; nothing for relay.
- **Exact next task:** unchanged, A-3 (`EstateCache`), then A-6, A-4, A-7 by 2026-11-15. None is started; a miss is
  reported in thread `d5abc880` with a new date the same day.

**Board read, the questions rule (2026-11-13, second read).** A session Fabric started for the board's unread
messages (26, thread `16093ded`, 2026-11-13 01:43 to 03:35 UTC) read them all; no relay code changed.
- **Taken:** the operator's standing rule «Agents close questions themselves, by access level» (fabric-workspace
  `knowledge/authority.md`, `4e2a1491`, board message `b910f019`) is now the section *Questions and access levels* in
  `AGENTS.md`, with the relay's levels. The Cloudflare account, R2 and the passioncode.ai hostname have no written
  level yet: decided by the narrowest access, recorded on RLY-05, never a stop.
- **G30 confirmed:** fabric-agents-database (`41d12991`, `95198064`) keeps the relay outside the judged audit for the
  owner's recorded reason (no model, prompt or tool), as item 1b says; fabric-workspace merged the G5 checkpoint to
  2026-11-15 into the North Star (`3e28fc4d`, `main` `37ece5d2`).
- **Also read:** relays of the operator's decisions for Vesta, Kira, studio-agent and fabric-agent-contract, and
  status replies from other projects; nothing for relay.
- **Exact next task:** unchanged, A-3 (`EstateCache`), then A-6, A-4, A-7 by 2026-11-15. None is started; a miss is
  reported in thread `d5abc880` with a new date the same day.

**North Star merge and the architect (2026-11-13).** A session Fabric started for the board's unread messages (10,
thread `16093ded`) answered fabric-workspace's announcement `d4404828` (the operator's rules of 2026-11-13, North Star
§6 "Merged with the North Star, validated by the architect").
- **Sections:** item 1b in `AGENTS.md` names §2, §4 and §6 *Where we stand*, §13 *Where we stand* and G5.
- **Architect:** `audit.py scan` fits no template; the judged half does not apply because the relay is not an agent
  ([docs/evidence/architect/README.md](evidence/architect/README.md)). Rescan at each release.
- **Also read:** nine replies and messages from other projects in that thread, nothing for relay.
- **Exact next task:** unchanged, A-3 (`EstateCache`), then A-6, A-4, A-7 by 2026-11-15. None is started; a miss is
  reported in thread `d5abc880` with a new date the same day.

**Board read (2026-11-13).** A session Fabric started for the board's unread messages (3, 2026-11-13) read and marked
them; no relay code changed and no answer was owed.
- **G5 dated:** fabric-workspace confirmed in thread `2aa32848` (message `a980fa51`) that the North Star's G5 now
  carries RLY-05's S1 by 2026-11-20 and F-8 by 2026-12-04, with a relay row in the S4.1 deadline table and checkpoints
  by 2026-11-15 (fabric-workspace `main` `160a5092`). The 2026-11-12 entry's "still read as undated" no longer holds
  for G5; fabric-vr was not re-checked.
- **Also read:** two status replies from project-observatory-contract (`e06cba18`, `9cfa64fb`), nothing for relay.
- **Exact next task:** unchanged, A-3 (`EstateCache`), then A-6, A-4, A-7 by 2026-11-15. None is started; a miss is
  reported in thread `d5abc880` with a new date the same day.

**Board read, course check added (2026-11-12).** A session Fabric started for the board's unread messages (44,
2026-11-11 to 2026-11-12) handled them; no relay code changed.
- **Course check:** item 1a (fabric-workspace `knowledge/rules.md` §0, announcement `7a62a183`) is in `AGENTS.md`
  *Read first*, naming RM-21, the unified plan's *Relay* row and North Star gap G5.
- **Branches:** `iter1/node22-refused-upgrade` (8 commits, 2026-10-14, no PR) was fully covered by `main` through the
  squash merges of relay#8 and relay#10 (its Node 22 fix is `tests/portable.test.ts:111`); kept as
  `refs/archive/2026-11-12/iter1/node22-refused-upgrade` on origin (`7041d22`) and deleted. Origin now has only `main`.
- **Answered:** `54bb0e84` (clock, merge, course; thread `2aa32848`) and the roll call `1881418d` (thread `0b120c4b`).
  Both say RLY-05 is dated (S1 by 2026-11-20, full by 2026-12-04), which fabric-vr and the North Star's G5 still
  read as undated.
- **Exact next task:** unchanged, A-3 (`EstateCache`), then A-6, A-4, A-7 by 2026-11-15. None is started; a miss is
  reported in thread `d5abc880` with a new date the same day.

**RP done (2026-11-11, the RLY-05 checkpoint of this date).** A session Fabric started for the board's unread
messages took the coordinator's ask `1234fffe` (thread `eeab2c3f`: "RP from your `docs/handoff.md:18`, then A-3").
- **Pin:** fabric-agent-contract `c14db0e9` (its `main`, 7 commits after `v0.1.0+2026-11-08.1`), 46 vendored files
  byte-equal (`src/contract/VENDORED.json`); `npm run check` exit 0, 245 of 245 tests.
- **What had to change:** `scripts/vendor-contract.ts` (two `welcome` branches since DEC-0134; `strictRequired` off; the
  closure gains `share-registration.ts`, `protocol-revisions.ts`); test fixtures add `unread: []` to an
  `AdmissionResult` and `revise({dropKids})` revokes what it drops (FAC-SEM-114).
- **Not done here:** the relay core ignores `AdmissionResult.unread` (delta entries the contract cannot read); A-3
  should decide whether to log them. The organization relay (DEC-0134) is the new row RLY-09.
- **Board:** 627 unread messages read and marked (2026-10-16 to 2026-11-11). Answered: `1234fffe` (RP done), the
  RLY-05 checkpoint in thread `d5abc880`, the roll calls `6a36fbf5` (status), `893a8198` and `51375420` (cleanup),
  `66b5bfbe` (no Appvillis copy), `8bd78e76` (S6, late). The expired requests `0922be65` and `d722586a` were already
  answered by the RLY-05 dating of 2026-11-08.
- **Left on purpose:** 12 local review branches from 2026-10-12 (`p-8`, `p-9`, `r2p-8`, `r2p-9`, `r2s-8`, `r2s-9`,
  `r2u-8`, `r2u-9`, `s-8`, `s-9`, `u-8`, `u-9`) in the main checkout, on no remote. Their work landed through the
  squash merges of relay#8 and relay#10, so they are not ancestors of `main`; archive them under
  `refs/archive/2026-10-12/` before deleting, by the cleanup rule.
- **Exact next task:** A-3 (`EstateCache`), then A-6, A-4, A-7 by 2026-11-15, as RLY-05's S1 row orders them.

**RLY-05 dated (2026-11-08, board request `736b4049`, plan row 4.2 of the Studio-move plan, thread `d5abc880`).**
No relay work landed between 2026-10-18 (`00937e0`) and this entry. The coordinator (fabric-workspace) asked for a
date before 2026-11-10, or it picks Observatory's OBS-287 as the interim relay instead.
- **Dates given:** first hosted deploy, scoped to stage S1 of RM-21 (one estate, the operator's machines), by
  2026-11-20; the workgraph's full F-8 (with B-2, C-2, H-1/H-2 = RLY-07, F-3S, F-5 = RLY-04) by 2026-12-04.
- **Why the split:** F-8 in project-observatory `docs/runs/2026-10-12-release-iteration-1/workgraph.json` depends on
  about 17 open nodes; S1 needs admission that follows the estate record (A-3, A-4, A-6, A-7), limits on a public
  endpoint (D-2) and the hosted half of the release workflow (F-6). Blob and mailbox durability (B-2, C-2), the delta
  carry (H-1/H-2) and the portable executable (F-5) do not block one estate's first hosted use.
- **Checkpoints the coordinator can watch:** RP merged by 2026-11-11 (the contract moved 1073 commits past
  `bf3fd6b`); A-3, A-6, A-4, A-7 by 2026-11-15; D-2 by 2026-11-16; F-6 hosted half by 2026-11-18; F-8 by
  2026-11-20. A missed checkpoint is reported in thread `d5abc880` with a new date the same day.
- **Gates:** the hostname from the passioncode.ai zone owner (F-8 peer gate); enabling R2 on the account, a human
  gate only if the Cloudflare door reports it. The deploy itself has no outside users, so the agent does it; a session
  started by a board request alone stops before it and hands it on.
- **Exact next task:** RP, re-pin fabric-agent-contract to its current `main` and make `npm run check` green, then A-3.

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
- **A CI flake found and fixed in the tests:** on GitHub's runners the round-8 flood tests (`overflow()` in
  `tests/flow-control.test.ts`) found no `send-overflow` in 30 s in about a third of runs on this branch's heads
  (none on `main`, never locally). Diagnostics added to `Served.flow()` (frames read, paused sockets, each socket's
  byte counts and read state) showed a TCP-level stall: the relay was reading and had nothing buffered, yet received
  nothing after about 730 KB, while the client, which never reads and keeps writing, had a full receive buffer and
  megabytes unsent. `overflow()` now fills the kernel's buffers with self-addressed mail first, as round 6 already did,
  so the pongs queue in the relay at once; both flood loops also hold the client's own unsent backlog under 8 MiB.
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
