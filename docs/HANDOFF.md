# Handoff

**Where the work stands (2026-10-12, release iteration 1, wave 1).**

- **Done and merged on `main`:**
  - RLY-01: DEC-0047 merged in fabric-agent-contract (#53, `8060254`).
  - RLY-02: relay#1 `fa3d07f`.
  - RLY-03: relay#3 `05072c9`.
  - RLY-06: relay#5 `20bf599`.
  - Backlog rows RLY-07 and RLY-08: relay#6 and #7.
- **Pin.** fabric-agent-contract `51719e4`, the merge of #61. Re-pinning to the merge of the contract's iteration
  pull request (N19) is wave 2's node RP.
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

**RLY-05, the hosted deployment, is agent work** (iteration nodes F-6, F-7, F-8):
- scoped tokens are issued through Observatory's Cloudflare door into vault slots;
- the release workflow is built behind the organization's release guard, and the agent deploys and tags.
- **One conditional human gate:** if the door reports that R2 is not enabled on the account, enabling it asks for
  billing details, and the operator does that. Until the first deploy, the hosted build is tested locally (workerd
  through Miniflare).
