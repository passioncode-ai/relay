# Handoff

**Where the work stands (2026-10-12, evening).**
- **RLY-01 is done.** DEC-0047 is merged in fabric-agent-contract (#53, `8060254`).
- **RLY-02 is done (relay#1).** A machine opens a `fabric-relay/0.1` session and is admitted only from
  a verified estate record. Both builds do this; how is in [protocol/sessions.md](protocol/sessions.md).
  - The contract's reference code is vendored at the pinned commit, and its vectors run here.
  - `npm run check` is green: typecheck clean, 73 tests (after RLY-06).
  - The Worker's tests run a whole session in workerd, for estate records signed by an EdDSA and by an ES256 passkey.
- **Pin.** fabric-agent-contract `51719e4`, the merge of #61 (distinct blob recipients). Before it: `c00a0c3`, the merge of #59: the fix this work found (the contract's verifiers
  threw in a Worker).
- **RLY-03 and RLY-06 are done (relay#3, this change).** Store-and-forward messages, blob routes, and presence with
  `lastSeen` run in both builds. In the Worker, presence lives in one Durable Object per estate, `PRESENCE`, under
  migration `v3`.
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

**The exact next task.** RLY-04: the portable build as a single executable (Node single-executable application),
with a reproducible-build check. RLY-03 (mailboxes and blobs) and RLY-06 (presence, `lastSeen`, the offline rule;
[sessions](protocol/sessions.md#presence)) are done. Deltas and heartbeats wait for DEC-0054. RLY-05, the hosted
deployment, waits on the Cloudflare account and route below.

**Prerequisites nobody here can skip:** a Cloudflare account and route for the hosted deployment (RLY-05). Until
then, the hosted build is tested locally only.
