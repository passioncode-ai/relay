# Handoff

**Where the work stands (2026-10-12, afternoon).**
- **RLY-01 is done.** DEC-0047 is merged in fabric-agent-contract (#53, `8060254`).
- **RLY-02 is done (relay#1).** A machine opens a `fabric-relay/0.1` session and is admitted only from
  a verified estate record. Both builds do this; how is in [protocol/sessions.md](protocol/sessions.md).
  - The contract's reference code is vendored at the pinned commit, and its vectors run here.
  - `npm run check` is green: typecheck clean, 45 tests.
  - The Worker's tests run a whole session in workerd, for estate records signed by an EdDSA and by an ES256 passkey.
- **Pin.** fabric-agent-contract `c00a0c3`, the merge of #59: the fix this work found (the contract's verifiers
  threw in a Worker).
- **Sessions live in memory.** A Durable Object holds one connection; the portable build holds its sockets.
  - Durable state starts with RLY-03 (mailboxes): SQLite in the Durable Object, files or SQLite in the portable
    build.
- Decision record: [ADR-0001](adr/0001-relay-repository.md).

**Decisions already taken:**
- own repository;
- AGPL-or-commercial;
- Project Observatory owns the server code;
- protocol in fabric-agent-contract DEC-0047, admission from DEC-0055's estate record;
- the hosted relay is run by PassionCode.ai;
- the self-hosted relay stays, as the portable build.

**The exact next task.** RLY-06: presence and "last seen" for machines of the same owner, and the offline rule
(a queued command never reported done); deltas and heartbeats wait for DEC-0054. RLY-03 (mailboxes and blobs) is done.

**Prerequisites nobody here can skip:** a Cloudflare account and route for the hosted deployment (RLY-05). Until
then, the hosted build is tested locally only.
