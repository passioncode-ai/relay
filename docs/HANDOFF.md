# Handoff

**Where the work stands (2026-10-12).**
- The repository exists, with the walking skeleton (RLY-00):
  - one runtime-neutral core, with a hosted build (Cloudflare Worker, Durable Objects, R2) and a portable build
    (Node);
  - health;
  - digest-verified blob stores;
  - every session refused until the protocol is accepted.
- `npm run check` is green: typecheck clean, 17 tests. The Worker's tests run its own bundle in workerd.
- Decision record: [ADR-0001](adr/0001-relay-repository.md).

**Decisions already taken:**
- own repository;
- AGPL-or-commercial;
- Project Observatory owns the server code;
- protocol in fabric-agent-contract DEC-0047;
- the hosted relay is run by PassionCode.ai;
- the self-hosted relay stays, as the portable build.

**The exact next task: RLY-01, review round.** The draft is [protocol/dec-0047-draft.md](protocol/dec-0047-draft.md), sent to the contract owner on 2026-10-12. It carries three open questions. Land it in fabric-agent-contract under that repository's lease on
`docs/DECISIONS.md`. Design it together with the contract's v4 revocation delta, heartbeat and secret envelope,
and meet the contract owner's four review conditions:
1. RFC 8785 for everything signed or hashed;
2. the small-order check on every Ed25519 key;
3. T1/T2 by call origin;
4. revocation vectors in `fixtures/vectors/`.

Then RLY-02 implements the handshake from the accepted text: [backlog](backlog.md).

**Prerequisites nobody here can skip:** a Cloudflare account and route for the hosted deployment (RLY-05). Until
then, the hosted build is tested locally only.
