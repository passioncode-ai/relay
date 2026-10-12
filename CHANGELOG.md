# Changelog

## Unreleased

Release iteration 1, wave 1 (relay#8 and its stacked pull request):

- **One estate hub per estate** (RLY-012, RLY-014, RLY-013; [ADR-0002](docs/adr/0002-estate-hub.md)).
  - A session is a serializable `SessionRecord`.
  - Presence is derived from the hub's live connection set, and only `lastSeen` is stored.
  - One timer serves every session's deadline.
  - Delivery wake-ups run single-flight.
  - A relay fault closes 1011 through `RelaySession.fault()`.
- **Hosted.** The Worker runs one hibernating Durable Object per estate, `RelayEstate`, on the WebSocket Hibernation
  API with one alarm.
  - The per-connection session objects and the presence object are gone.
  - The bindings are `ESTATE`, `MAILBOX` and `BLOBS`, and the migrations collapse to one `v1`. Nothing was ever deployed.
  - Durable Object names go through `contextKey()` (RLY-08).
- **Portable.**
  - **One origin** for sessions and blob routes (RLY-017): `RELAY_ORIGIN` is normalised or refused, with exit 2.
    `http://` is allowed only on a loopback literal. When it is unset, the origin is the loopback host and the
    bound port.
  - **Graceful stop** on SIGTERM/SIGINT (RLY-010): every session is closed 1001, `lastSeen` is written, the
    SQLite stores are closed, and the process exits 0.
- **One log line shape** in both builds: `{at, service, runtime, event, …}`.
- **Tests.**
  - The Worker test is split per module.
  - The estate fixture gains `revise()` and `forge()` (RLY-025).
- **Docs.** Truth pass (RLY-018, RLY-019, PLN-084, PLN-085).
  - The claim that the relay never holds plaintext is corrected: it stores message bodies as sent, and a secret is never
    in plaintext at the relay.
  - ADR-0001 Amendment 1; this history.

## History before release iteration 1

Each entry is one merged pull request in this repository.

- **relay#7 (`cff8648`), backlog.** RLY-08: one relay session per (relay, context). Contexts are told apart by a
  pseudonymous id, never the estate id.
- **relay#6 (`7d5898c`), backlog.** RLY-07: carry DEC-0054's revocation delta and heartbeat.
- **relay#5 (`20bf599`), RLY-06.**
  - Presence and `lastSeen` for the estate's own machines in both builds.
  - The offline rule (Fabric ADR-0088): a sender learns its message was queued, never that it was done.
- **relay#4 (`152f354`).** Contract pinned at `51719e4` (#61): a blob recipient named twice is 400 `malformed`, and an
  unknown blob is 403.
- **relay#3 (`05072c9`), RLY-03.** Store-and-forward messages (`send`, `accepted`, `deliver`, `ack`) and blob routes
  (`PUT`/`GET /v1/blobs/<digest>` with `Fabric-Relay-Request`), in both builds.
- **relay#2 (`d97af11`).** RLY-02 recorded done; the pin named at #59's merge.
- **relay#1 (`fa3d07f`), RLY-02.** `fabric-relay/0.1` sessions, with admission from a verified estate record in both
  builds. The contract's reference code is vendored at the pinned commit, and its vectors run here.
- **RLY-00, the walking skeleton.**
  - A runtime-neutral core with two builds: a Cloudflare Worker with Durable Objects and R2, and a portable Node
    server.
  - `GET /healthz`.
  - Blob stores that verify the SHA-256 digest of every blob on write and on read.
  - Every session refused with a not-ready refusal until fabric-agent-contract DEC-0047 was accepted (it was, at #53
    `8060254`).
