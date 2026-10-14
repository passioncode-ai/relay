# Sessions and admission (RLY-02, RLY-03, RLY-06)

Ids: `RLY-0n` (two digits) are this repository's backlog rows (`docs/backlog.md`). `RLY-0nn` (three digits) are
findings in release iteration 1's inventory (Project Observatory `docs/runs/2026-10-12-release-iteration-1/`), and
letter-number ids such as A-4 are that iteration's nodes.

How this relay runs a `fabric-relay/0.1` session. The protocol is fabric-agent-contract's DEC-0047 (merged at
`8060254`), on top of DEC-0055's estate record. This page says how the code applies it; the contract's
[relay specification at the pinned commit `51719e4`](https://github.com/passioncode-ai/fabric-agent-contract/blob/51719e4/docs/specification/relay.md)
is the authority on every rule. Iteration node RP re-pins the relay to `464c45e` (fabric-agent-contract #70), and
this link moves with the pin.

## The contract, vendored

- `fabric-contract.lock.json` pins one contract commit.
- `scripts/vendor-contract.ts <checkout>` copies, byte for byte, the closure of the contract's `src/relay.ts` and
  `src/secret-envelope.ts` into `src/contract/`. It also copies the contract's vectors into `tests/vectors/`.
- The script records each file's SHA-256 in `src/contract/VENDORED.json`. `tests/contract.test.ts` refuses a drifted
  file or a manifest of another commit, and runs the vectors.
- The relay never re-implements a check the contract owns.
- **The estate-record schema validator is compiled ahead of time.** Ajv 8.17.1 generates standalone code, and esbuild
  bundles it into `src/contract/estate-record.validate.js`. The reason: Ajv compiles with `new Function`, which a
  Worker forbids. The bundled module has no `require` and loads the same way under Node and in workerd.
- **Moving the pin** is one change:
  1. update the lock;
  2. re-run the script;
  3. run `npm run check`.

## Admission

- **From a verified record only.** A relay admits only from an estate record it has verified (`src/core/admission.ts`,
  over the contract's `relayAdmissionSet`):
  - the relay holds the estate's first passkeys, pinned when it was set up for the estate;
  - each revision is applied only when it is valid against the bundled schema and the contract's
    `verifyEstateRecord` accepts it against the revision held (revision 1: against the pinned passkeys);
  - revisions are offered in order, and the first one refused stops the walk;
  - a refused revision changes nothing.
- **Fails closed.** With no verified record, or once the held revision's window has ended, the relay admits nobody
  (`not-admitted`, close 4403).
- **Where the estate is kept.** It is never in this repository:
  - hosted: R2 `estate/pinned.json` and `estate/revisions/<n>.json`;
  - portable: `RELAY_DATA_DIR/estate/pinned.json` and `revisions/<n>.json`.
- **When it is read.** The estate is read whenever a connection opens and, on the hosted relay, when the hub object
  wakes from hibernation holding nothing. Every open session of the estate hub (below) admits from what was read last.
  A read never rolls back to an older revision than the one held. A revision file that does not parse is refused by the
  contract like any other bad revision, so the revisions before it still hold. A read that fails is logged
  `estate-unreadable` and loses no event: the hub keeps what it held, which after a wake is nothing, and then admits
  nobody (fail closed). Presence follows that empty set: while no estate is held, a machine coming or going is not
  announced and a query answers nothing; `lastSeen` is still written, and answers again once a read succeeds. Re-checking open sessions when the set changes is iteration node A-4's.

## One session

`src/core/session.ts` runs the session the same way in both builds:

1. **`hello`** carries `{protocol, relay, nonce, time}`. The nonce is 32 random bytes, used once.
2. **`auth`** must arrive within 10 s. It is checked by the contract's `admit` against the admission set, keyed by
   `kid`.
3. **`welcome`** answers a successful `auth` with `{session, estateRevision, deltaHead, heartbeat: null}`.
   - `estateRevision` is the verified revision.
   - Until RLY-07 carries DEC-0054's revocation delta, `deltaHead` is `{sequence: 0, sha256: <SHA-256 of no bytes>}`.
4. **Refusals.** A failed `auth` is answered with a named `error`, then a close:
   - `unauthenticated`, `unsupported-alg`, `not-yet-valid`, `protocol-unsupported` and `replay` close with 4401;
   - `not-admitted` closes with 4403.
5. **After `welcome`:**
   - `ping` is answered with `pong`;
   - `send`, `deliver` and `ack` are store-and-forward (see [Messages](#messages));
   - `presence` and `presence-query` are [presence](#presence);
   - a known frame type not yet served (deltas and heartbeats: RLY-07) gets `error` `internal` "not served by this
     relay version yet";
   - an unknown type gets `unknown-type`, and the session stays open.
6. **Transport closes:**
   - a binary frame closes with 1003;
   - a frame over 1 MiB gets `too-large`, then 1009;
   - 90 s of silence closes with 1001 ("going away"); a portable relay that stops closes every session with the
     same 1001. A client reconnects; when the upgrade is answered 503, it waits for the `retry-after` seconds first;
   - a fault in the relay while handling a frame is logged as `session-fault`, answered `error` `internal`, and closes
     with 1011 (`RelaySession.fault`).

## The estate hub

Each build runs **one hub per estate** (`src/core/hub.ts`; why: [ADR-0002](../adr/0002-estate-hub.md)). It holds the
connection set and everything that spans connections:

- **Presence is derived from the set**, never stored: a machine is online while an admitted session in the set has its
  kid. Only `lastSeen` is kept.
- **One timer.** Each session says when it next needs attention (`nextDeadline()`: the 10 s auth deadline, then 90 s of
  silence); the hub arms the build's one timer at the earliest and closes exactly the sessions that are due.
- **Delivery wake-ups.** A message queued for a machine wakes every session it holds. One flush runs at a time per
  session; a wake during a flush runs one more, so a message is delivered once and never missed. A session is in the
  set before its first delivery, so nothing queued meanwhile is missed (RLY-013).
- **A session is a record.** `SessionRecord` holds a session's whole state and is handed to the transport after every
  change; `RelaySession.restore` continues from it.

The upgrade is accepted only for `GET /v1/connect` with `Upgrade: websocket` and the subprotocol `fabric-relay.v1`
(`upgradeRefusal`). A plain request gets 426, and a missing subprotocol gets 400.

## Messages

- **`send`.** It is checked by the contract's FAC-SEM-071 (`relay-rules.ts`): a `#sig` recipient, a `ttl` of 1 s to
  7 days, a body of at most 765 KiB decoded.
  - A body over the limit gets `too-large`.
  - Any other violation, or a missing `msgId`, `to` or `body`, gets `unknown-type`, naming the rule's path.
  - The recipient must be a machine the relay admits, else `unknown-recipient`.
  - If the recipient's mailbox already holds 1000 messages, the answer is `mailbox-full`. DEC-0047 leaves quotas
    undecided; 1000 is this relay's own limit.
  - On success the relay answers `accepted {msgId, seq}`. `seq` is monotonic per mailbox.
  - A repeat of the same `(from, msgId)` while it is still queued answers its first `seq` and is not delivered again.
- **`deliver`.** Every connection the recipient holds gets each unacknowledged message once, in `seq` order. A
  connection that opens later gets what waited for it. Where the transport reports a backlog (the portable build),
  delivery goes at the pace the machine reads (see Flow control); the Worker's hibernatable socket reports none, so
  there a flush sends every page at once, as before.
- **`ack {seq}`.** It deletes the message for every connection.
- **Expiry.** An expired message is deleted when it is met.
- **Where mail is kept.**
  - Hosted: one Durable Object per recipient (`MAILBOX`, SQLite storage), named `<context>/<kid>`. Once a message is
    stored it wakes the estate hub in the background (`ctx.waitUntil`), so the sender's `accepted` never waits on
    another machine's delivery; it keeps no list of sessions.
  - Portable: `RELAY_DATA_DIR/mailbox.sqlite` (owner-only).

## Presence

- **Who hears it.** The relay serves one estate, and it admits only machines listed in that estate's verified record.
  So every admitted machine has the same owner, and presence goes only to them.
  - A machine hears about the estate's other machines, never about itself.
  - A machine that has left the current verified set is neither announced nor answered: presence follows the same set
    as admission.
- **When.**
  - `presence {kid, state: online, lastSeen}` is sent when a machine's first connection is admitted.
  - `presence {kid, state: offline, lastSeen}` is sent when its last connection ends.
  - A second connection of a machine that is already online changes nothing anyone is told.
  - These pushes report changes that happen after this session's `welcome`. For the state at `welcome`, a node asks
    once it is admitted: one presence query for the kids it cares about (`presence-query` below). A machine that
    came online while this session was still authenticating is not pushed to it.
- **`lastSeen`** is when the relay last heard from the machine: a connection admitted, a frame, or a connection
  ended.
  - Frames move it at most once per 30 s (`TOUCH_INTERVAL_SECONDS`).
  - It never moves back.
- **`presence-query {kids}`** gets one `presence` frame for each asked kid of the estate that the relay has seen, in
  the order asked.
  - A kid outside the set, or one the relay never saw, gets no frame. The relay invents no time.
  - More than 256 kids, or `kids` that is not a list of kids, gets `unknown-type`.
  - A node that sends `presence` itself gets `unknown-type`.
- **The offline rule (Fabric ADR-0088).** A sender learns that its message was queued (`accepted {msgId, seq}`), and
  nothing after that.
  - The relay never tells a sender that a message was delivered, acknowledged or done.
  - Only the recipient's own signed message back reports an outcome.
  - `tests/presence.test.ts` sends to an offline machine, lets it connect, take the message and ack it, and checks
    that the sender heard only that it came online.
- **Where presence is kept.** Who is online is derived by the estate hub from its live connections, so a runtime that
  drops every socket at once leaves nothing stale.
  - Hosted: `lastSeen` is kept in the estate hub object's SQLite storage. A deploy restarts the object and drops every
    socket; the new object starts from the runtime's (empty) socket list, so nothing about connections is stale.
  - Portable: `lastSeen` is kept in `RELAY_DATA_DIR/presence.sqlite` (owner-only, `SqliteLastSeen`), so it survives a
    restart.

## Blobs

- **The wire form is the contract's.** `PUT`/`GET /v1/blobs/<digest>` carry `Fabric-Relay-Request`, whose wire form is
  annotated under DEC-0047 (fabric-agent-contract #60). The contract's `verifyBlobRequest` decides who may ask,
  against the same verified admission set as sessions, read on each request.
- **Storing a blob.**
  - The relay recomputes the digest on `PUT`: a mismatch gets 422 `digest-mismatch`.
  - It keeps the blob's recipient list.
  - It refuses a body over 32 MiB with 413.
  - A blob path that is not valid percent-encoding (`/v1/blobs/%`) is 400 `malformed`.
- **Serving a blob.** It re-checks the digest on `GET` before serving.
- **Deletion.** A blob is deleted once every stored recipient fetched it (counted per kid), or after 7 days, when it
  is next requested.
  - A `GET` for a blob the relay does not hold gets 403 `not-admitted`, the same answer as a machine that may not
    fetch it. The relay does not say whether a blob exists.
- **Where blobs are kept.**
  - Hosted: R2, the blob under its digest and its index under `blobindex/<digest>`.
  - Portable: `RELAY_DATA_DIR/blobs/sha256/` and `blobs/index/`.

## The two adapters

- **Hosted.** Every upgrade goes to the estate hub, one Durable Object per estate (`ESTATE`, `src/cloudflare/estate.ts`),
  named through `contextKey()` (a constant while one relay origin serves one context; never the estate id). It accepts
  the socket with the WebSocket Hibernation API, keeps each session's record in the socket's attachment, and runs one
  alarm at the earliest deadline. After a hibernation wake it rebuilds its set from the sockets the runtime kept. The
  relay origin signed into `relay-auth/1` is the request's origin.
- **Portable.** The `ws` package (8.22.0) upgrades the connection and selects `fabric-relay.v1`. The relay has **one
  origin**, the same for sessions and blob routes (`src/portable/origin.ts`, RLY-017):
  - `RELAY_ORIGIN` set: it must be a bare `https://` origin (behind a TLS terminator). It is normalised, so the host is
    lowercased and `:443` and a trailing `/` are dropped. A path, query, fragment, credentials or another scheme refuse
    to start (`refused-to-start`, exit 2). `http://` is accepted only on a loopback literal (`127.0.0.0/8`, `[::1]`),
    and only when `RELAY_HOST` is a loopback literal too; the name `localhost` is refused, since a name resolves where
    a literal cannot. Its host must mean what it says: an IPv4 address written as four decimal parts (a URL reads
    `127.010.0.1` as `127.8.0.1`, `0x7f.1` and `127.1` as `127.0.0.1`), no trailing dot, no empty label
    (`.relay.test`), and no port 0.
  - `RELAY_ORIGIN` unset: allowed only when `RELAY_HOST` is a loopback literal. The origin is then the URL parser's
    origin of `http://RELAY_HOST:<bound port>`, computed after listen, and logged as `origin-defaulted`; only a local
    machine can authenticate. It is canonical, not `RELAY_HOST` verbatim: `0:0:0:0:0:0:0:1` gives `http://[::1]:<port>`
    and `127.000.000.001` gives `http://127.0.0.1:<port>`; a spelling a URL reads as another address (`127.010.0.1`,
    whose parts are octal there) refuses to start. On any other host the relay refuses to start.
  - `RELAY_HOST` is a bare address or name a URL can carry, whether `RELAY_ORIGIN` is set or not. A bracketed one
    (`[::1]`), a zone id (`fe80::1%lo0`), a space, a port or a path, or an IPv4 address not written as four decimal
    parts refuses to start (`refused-to-start`, exit 2) rather than listening and then failing on each request.
  - `RELAY_PORT` is digits only, 0 to 65535 (`""`, `1e3` and `0x50` refuse to start). A listen that fails (the port
    taken, a host that does not resolve) is `refused-to-start` and exit 2 too, never a crash.
  - **Input it cannot read.** A request target Node's HTTP parser accepts but a URL does not (`//[`,
    `http://[/v1/connect`, `http://x:99999/`) gets 400 `bad-request` (logged `request-refused`), or a bare 400 on an
    upgrade (`upgrade-refused`); the target is parsed once, before anything else, and the relay stays up. Targets
    resolve against a fixed base, `http://relay.invalid`, never `RELAY_HOST`.
  - **Flow control** (`src/portable/server.ts`, the flush in `src/core/session.ts`). `ws` emits one message per turn
    of the event loop (`allowSynchronousEvents: false`), so a flooding machine cannot delay a signal or a timer
    (SIGTERM is handled within one frame's work). Then:
    - **Deliveries are paced by the machine's reading.** A flush reads the mailbox four messages at a time
      (`FLUSH_PAGE`) and sends only while less than 1 MiB is queued on the socket (`SEND_HIGH`); when the socket
      drains it goes on. What is not sent yet stays in the mailbox, durable. A reader at any speed gets its whole
      backlog, in `seq` order, and its acks are read meanwhile.
    - **The socket is always read**, so acks and pings arrive whatever the relay has queued to send. A socket drain
      counts as activity for the 90 s idle close: a slow reader that is draining is not idle.
    - **Replies to a machine that never reads are capped.** Past 16 MiB queued on its socket (`SEND_CAP`; deliveries
      alone cannot reach it) the session is logged `send-overflow`, closed 1008 through its own close (its messages
      stay queued) and the socket terminated 1 s later unless it closes first.
    - **At most 8 sessions per machine** (`RELAY_MAX_SESSIONS_PER_MACHINE`, 1 to 1000): the next `auth` is answered
      `error` `rate-limited` and closed 1013 (logged `session-limit`); a session that ends makes room.
    - **The bound** this gives: what the relay holds queued for one machine is at most the session limit times
      (`SEND_HIGH` plus one delivery frame of about 1 MiB): 8 x 2 MiB = 16 MiB. On top of it come the mailbox page a
      flush is sending from (four bodies) and copies the garbage collector has not reclaimed yet. Measured with
      `footprint`: 30 non-reading sessions of one machine with 11 MiB queued grew the relay by 41 to 44 MiB, up to
      75 MiB under load (727 MiB before this design).
    - Inbound: a socket with 64 frames waiting in its session is not read until they drain to 16; with the real stores
      a frame is handled in its own turn, so this seldom trips.
  - **CONNECT** is not served: it is answered 405 (`connect-refused`) and the socket is let go of.
  - **Stopping (RLY-010).** SIGTERM, SIGINT or SIGHUP (the terminal that started the relay closed) stops gracefully. New upgrades get 503, and HTTP answers carry
    `connection: close`. Every session is closed 1001 through the estate hub, so each machine's `lastSeen` is written.
    A socket still open after 5 s is terminated. Then the listener, the connections and both SQLite stores close (a
    connection still open then, an upgraded one included, is destroyed and counted in `forced`), and
    the relay logs `stopped {sessions, forced, ms}` and exits 0. Past a 10 s ceiling it logs `stop-timeout` and exits 1;
    a stop that fails logs `stop-failed` and exits 1. A second press (a different signal, or the same one more than
    1 s after the first) logs `stop-forced` and exits 1 at once; the same signal within 1 s is the same press
    (`npm run portable` forwards the terminal's SIGINT, so the relay sees one Ctrl-C twice) and is logged
    `signal-repeated`. A supervisor waits longer than the ceiling (systemd `TimeoutStopSec=20`, launchd
    `ExitTimeOut=20`).
    - A refused upgrade (404, 400, the 503 below) is answered and its socket destroyed once the answer is flushed (1 s
      at most), so a client that keeps its side of the connection open cannot hold the stop.
    - The 503 carries `retry-after: 5`. An upgrade that was already past that gate when the stop began (its estate
      read in flight) is waited for, then closed 1001, and terminated with the others at the grace period if it has not
      closed. A socket that closes while its estate is read never joins the hub.
    - A revision file that does not parse is refused like any other bad revision, so the revisions before it still
      hold; a read that fails as a whole (an unparsable `pinned.json`) is logged `estate-unreadable` and the hub keeps
      what it held.
    - `/healthz` keeps answering 200 while the relay stops, until iteration node A-6 makes health report it.

## Found on the way

The contract's reference verifiers passed a `KeyObject` inside `node:crypto`'s `verify` options. A Worker throws on
that.
- `verifyEs256` and `openEnvelope` threw outright.
- The ES256 passkey path of `webauthn.ts` turned the throw into `bad-signature`.
- Fixed upstream in fabric-agent-contract#59: the key is now passed as a JWK with `format: "jwk"`.
- `tests/worker-estate.test.ts` admits a machine in workerd from revisions signed by both test passkeys. With the old form
  restored, the ES256 case fails.
