# Changelog

## Unreleased

### Release iteration 1, wave 2: the contract at `bf3fd6b` (DEC-0066), nodes RP and D-1

- **Contract re-pinned** from `51719e4` to fabric-agent-contract `bf3fd6b` (RP). The vendored closure gains
  `rfc3339.ts`, `signing-challenges.ts`, `revocation-delta.ts`, `context-route.ts`, `context-rules.ts`,
  `identifiers.ts` and the shared-vector runner `relay-vectors.ts`; the relay-frame schema is compiled ahead of time
  (`src/contract/relay-frame.validate.js`) next to the estate-record validator, as one fail-fast validator per frame
  type (the whole schema under `allErrors` cost about 200 µs a ping). Every case of the shared vectors runs
  in `tests/contract.test.ts`, and the `admit` group runs again through `RelaySession`.
- **Changed, visible to a client (DEC-0066):**
  - **`presence-query` is answered by one `presence-result {replyTo, presences, unknown}`**, every asked kid exactly
    once; a kid outside the estate and a kid never seen are both `unknown`. It used to be answered by one `presence`
    frame per seen kid.
  - **Every answer carries `replyTo`**: `pong` (it used to reuse the ping's `id`), `accepted`, `presence-result` and an
    `error` answering a frame, each with its own fresh `id`.
  - **`malformed`** for a known frame type that fails the schema or FAC-SEM-071 (a `send` with `ttl` 0, a bad `msgId`,
    recipient or body, `kids` that is not a list) and for text after `auth` that is not a `{v: 1, type, id}` frame
    (an empty or over-long `id` included). These used to be `unknown-type`, which now means an unknown type or one only
    the relay sends (`hello`, `welcome`, `accepted`, `deliver`, `presence`, `presence-result`, `error`).
  - **Auth refusals: one answer past the frame's own bytes.** An unknown kid, a revoked one, a relay holding no record
    or an expired one, another estate, a bad or high-S signature: `unauthenticated`, close 4401, with a fixed message;
    the reason goes to the log (`auth-refused`). These used to be `not-admitted`, 4403. Close codes come from the
    contract's `closeCodeFor`.
  - **The estate is bound into admission**: a proof signed for another estate than the held record's is refused.
  - **`welcome.deltaHead`** is the revocation delta's genesis head, `{sequence: 0, sha256: deltaGenesis(estate)}` (it
    was the SHA-256 of no bytes).
  - **Blobs in DEC-0066's order of checks** (`verifyBlobRequest`, then `decideBlobAccess`): a `PUT` without
    `Content-Length` is **411 `malformed`**; a body longer than declared is 413; another recipient list for held bytes
    is 409 `recipients-mismatch` only after the bytes hash to the digest (wrong bytes are 422 whatever is stored); a
    repeat `PUT` with the same list is 200 and restores an object the store lost; a `GET` whose signed list differs
    from the stored one, or of a lost object, is 403 `not-admitted`. A recipient no longer admitted is 401
    `unauthenticated` (its signer is not proven), where it was 403. The portable server closes the connection after a
    refused `PUT`.
  - **Portable: `RELAY_ORIGIN` must also match the contract's relay-origin pattern** (`isRelayOrigin`), or the relay
    refuses to start.
- **Tests sign with the contract's `signEs256`** (low-S) through `tests/test-signer.ts`; a raw `crypto.sign` was
  high-S half the time, which the contract now refuses.
- **Not yet applied, by node:** open-session revalidation (4403 `not-admitted`/`expired`, A-4); `welcome.limits`,
  `rate-limited` with `retryAfter` and msgId tombstones after an ack (D-2); delta and heartbeat ingress and
  `delta-query` (H-1, H-2: still `error internal`); the estate cache, health and the rest of the estate handling
  (A-3, A-5, A-6, A-7).

### Release iteration 1, wave 1

Release iteration 1, wave 1 (relay#8 and #9). Ids: `RLY-0n` are this repository's backlog rows; `RLY-0nn` are
release iteration 1's inventory findings (Project Observatory `docs/runs/2026-10-12-release-iteration-1/`).

- **One estate hub per estate** (RLY-012, RLY-014, RLY-013; [ADR-0002](docs/adr/0002-estate-hub.md)).
  - A session is a serializable `SessionRecord`.
  - Presence is derived from the hub's live connection set, and only `lastSeen` is stored.
  - One timer serves every session's deadline.
  - Delivery wake-ups run single-flight.
  - A relay fault closes 1011 through `RelaySession.fault()`.
- **Hosted.** The Worker runs one hibernating Durable Object per estate, `RelayEstate`, on the WebSocket Hibernation
  API with one alarm.
  - The per-connection session objects and the presence object are gone.
  - The bindings are `ESTATE`, `MAILBOX` and `BLOBS`, and the migrations collapse to one `v1`. No deployment is
    known; F-8 checks `wrangler deployments list` before the first deploy.
  - Durable Object names and R2 keys come from `src/cloudflare/context.ts` (RLY-08). Mailbox objects are renamed
    `<context>/<kid>` (were `<kid>`).
  - An estate that cannot be read after a hibernation wake loses no event; the hub then admits nobody.
- **Portable.**
  - **One origin** for sessions and blob routes (RLY-017): `RELAY_ORIGIN` is normalised or refused, with exit 2.
    `http://` is allowed only on a loopback literal, served from a loopback-literal `RELAY_HOST`. When it is unset,
    the origin is the loopback host and the bound port.
  - **Changed:** a non-loopback `RELAY_HOST` without `RELAY_ORIGIN` now refuses to start (exit 2); it used to
    default to an http origin.
  - **Graceful stop** on SIGTERM, SIGINT or SIGHUP (RLY-010): every session is closed 1001, `lastSeen` is written,
    the SQLite stores are closed, and the process exits 0. One Ctrl-C through `npm run portable` is one press. An
    upgrade whose estate read is in flight when the stop begins is refused and terminated at the grace period.
  - An unparsable revision file is refused like any bad revision instead of taking the relay down; a socket that
    closes during its estate read never joins the hub.
- **Flow control and limits** (release iteration 1, rounds 5 to 8 of review). Visible to a client:
  - **At most 8 sessions per machine**, in both builds (sessions restored after a hosted wake count): the next `auth`
    gets `error rate-limited` and close 1013. Portable: `RELAY_MAX_SESSIONS_PER_MACHINE` (1 to 1000).
  - **Ids and msgIds over 128 code points are refused**, with `error unknown-type` and never echoed; so are an empty
    one, a recipient over 256 code points and a body that is not base64url. No frame the relay sends exceeds 1 MiB.
  - **Portable: mail is delivered at the pace the machine reads**, the socket is always read, and a machine that never
    reads what the relay sends is closed **1008** past 3 MiB or 4096 frames queued (logged `send-overflow`).
  - **Portable: a socket heartbeat.** Progress is only what the peer confirms: a frame it sends, or a pong whose
    8-byte payload matches a heartbeat ping the relay sent (never a write the relay makes, a drain, an unknown pong or
    a WebSocket ping from the peer). The relay pings each socket every 10 s (at most 64 awaiting pongs). A socket with
    nothing outstanding (no bytes in the process, at most 4 KiB unconfirmed) and no matched pong or frame for 30 s is
    terminated, logged `heartbeat-timeout`. A socket with bytes outstanding is left to the idle close, **5 minutes
    while bytes are outstanding** (90 s otherwise); a frozen peer is freed within it even while mail keeps arriving.
    The slowest reader that keeps its session reads about 9 to 10 KiB/s on Linux defaults (about 7 KiB/s on macOS),
    acks or not; a slower one is closed 1001 and keeps its mail. The hosted build has no heartbeat: a
    vanished peer holds its slot until the 90 s idle close.
  - **Portable: the relay answers a WebSocket ping itself, under the send caps** (ws's automatic pong is off): a
    machine that floods pings and never reads is closed 1008 instead of growing the relay's buffer without bound. A
    WebSocket ping is not activity: a session stays open by its frames.
  - **A `msgId` that is not well-formed text** (a lone surrogate) is refused `unknown-type`: stores collapsed it, so
    two msgIds became one dedup key and a body was silently dropped.
  - **A `msgId` with a control character** (NUL, a line break) is refused `unknown-type`: SQLite truncated it at a
    NUL, so `deliver` named another msgId than `accepted` had.
  - **A blob path that is not valid percent-encoding** (`GET /v1/blobs/%`) gets **400 `malformed`**, not a 500.
  - Portable: `CONNECT` gets 405; a request target a URL cannot parse gets 400; `RELAY_PORT`, `RELAY_HOST` and
    `RELAY_ORIGIN` spellings a URL reads differently (an empty query or fragment, an empty label, a trailing dot, port
    0, octal parts, a zone id, brackets) refuse to start with exit 2, and so does a listen that fails.
- **Changed: open sessions follow the latest estate read**, for sends and presence (each connection used to keep
  the read it opened with). A read never rolls back to an older revision.
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
  - Every session refused with `protocol-not-ready` until fabric-agent-contract DEC-0047 was accepted (it was, at #53
    `8060254`).
