# Sessions and admission (RLY-02, RLY-03, RLY-06)

Ids: `RLY-0n` (two digits) are this repository's backlog rows (`docs/backlog.md`). `RLY-0nn` (three digits) are
findings in release iteration 1's inventory (Project Observatory `docs/runs/2026-10-12-release-iteration-1/`), and
letter-number ids such as A-4 are that iteration's nodes.

How this relay runs a `fabric-relay/0.1` session. The protocol is fabric-agent-contract's DEC-0047 (merged at
`8060254`) as amended by DEC-0066, on top of DEC-0055's estate record. This page says how the code applies it; the
contract's
[relay specification at the pinned commit `bf3fd6b`](https://github.com/passioncode-ai/fabric-agent-contract/blob/bf3fd6b2a9387ee501ef635de4e26524c3ea2b4f/docs/specification/relay.md)
is the authority on every rule (iteration node RP moved the pin from `51719e4`). Where a DEC-0066 rule is not applied
yet, this page names the iteration node that owns it.

## The contract, vendored

- `fabric-contract.lock.json` pins one contract commit.
- `scripts/vendor-contract.ts <checkout>` copies, byte for byte, the closure of the contract's `src/relay.ts`,
  `src/secret-envelope.ts` and `src/relay-vectors.ts` (the shared-vector runner) into `src/contract/`. It also copies
  the contract's vectors into `tests/vectors/`.
- The script records each file's SHA-256 in `src/contract/VENDORED.json`. `tests/contract.test.ts` refuses a drifted
  file or a manifest of another commit, and runs **every case of the shared vectors** through the vendored runner
  (DEC-0066 "Shared vectors": `relayVectorResults`, `envelopeVectorResults`, `placementVectorResults`), one test per
  case group. The `admit` group runs a second time through `RelaySession` itself, so the session answers what `admit`
  answers.
- Tests sign through the contract's `signEs256` only (`tests/test-signer.ts`): it emits the low-S form a relay admits.
- The relay never re-implements a check the contract owns.
- **The schema validators are compiled ahead of time.** Ajv 8.17.1 generates standalone code, and esbuild bundles it
  into `src/contract/estate-record.validate.js` and `src/contract/relay-frame.validate.js` (the frame schema with the
  revocation-delta and heartbeat schemas it references). The reason: Ajv compiles with `new Function`, which a Worker
  forbids. The bundled modules have no `require` and load the same way under Node and in workerd.
- **A frame is validated against its own type's branch.** The frame module exports one validator per frame `type`
  (each `oneOf` branch has its own `type` const, which the script checks) plus `frame`, the whole schema, and fails
  fast. The whole schema under `allErrors` runs all sixteen branches to the end: about 200 µs for a ping with a
  128-code-point id against about 1 µs without the schema, which slowed a ping flood enough that the round-8 flow
  tests stopped reaching the byte cap within 30 s. `tests/frames.test.ts` checks that each type's validator answers
  what the whole schema answers.
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
- **Fails closed.** With no verified record, or once the held revision's window has ended, the relay admits nobody:
  every `auth` is refused `unauthenticated`, close 4401 (DEC-0066: before the signer is proven there is one answer).
- **One estate per origin.** `admit` compares the estate the machine signed with the held record's `estate`
  (`AuthContext.estate`), and nowhere else; a proof for another estate is `unauthenticated`. The relay never keys
  anything by the estate id: its Durable Object names and R2 keys come from `src/cloudflare/context.ts` (RLY-08).
- **The admission set** is the contract's: the held record's machines' `#sig` keys, minus revocations and minus every
  key that could never verify (an Ed25519 key, or one SEC 1 refuses), which `relayAdmissionSet` lists in `excluded`.
  Revocations from verified delta entries (`extraRevocations`) arrive with the delta (wave 4, H-1).
- **Where the estate is kept.** It is never in this repository:
  - hosted: R2 `estate/pinned.json` and `estate/revisions/<n>.json`;
  - portable: `RELAY_DATA_DIR/estate/pinned.json` and `revisions/<n>.json`.
- **When it is read.** The estate is read whenever a connection opens and, on the hosted relay, when the hub object
  wakes from hibernation holding nothing. Every open session of the estate hub (below) admits from what was read last.
  A read never rolls back to an older revision than the one held. A revision file that does not parse is refused by the
  contract like any other bad revision, so the revisions before it still hold. A read that fails is logged
  `estate-unreadable` and loses no event: the hub keeps what it held, which after a wake is nothing, and then admits
  nobody (fail closed). Presence follows that empty set: while no estate is held, a machine coming or going is not
  announced and a query names every kid `unknown`; `lastSeen` is still written, and answers again once a read succeeds.
  Re-checking open sessions when the set changes (DEC-0066: `not-admitted` or `expired`, close 4403, before any frame
  is sent or accepted for the session) is iteration node A-4's; until it lands an open session keeps its admission
  until it closes.

## One session

`src/core/session.ts` runs the session the same way in both builds:

1. **`hello`** carries `{protocol, relay, nonce, time}`. The nonce is 32 random bytes, used once.
2. **`auth`** must arrive within 10 s. It is checked by the contract's `admit` against the admission set, keyed by
   `kid`, and the held record's estate. The whole `auth` frame is `admit`'s to judge, schema included, in its own
   order and with its own codes: an `auth` with no `alg` is `unsupported-alg`, one whose `sig` is not a string
   `unauthenticated`, never `malformed`.
3. **`welcome`** answers a successful `auth` with `{session, estateRevision, deltaHead, heartbeat: null}` and no
   `limits` (optional; advertised with the limits of iteration node D-2).
   - `estateRevision` is the verified revision.
   - Until the relay carries DEC-0054's revocation delta (wave 4, H-1), `deltaHead` is the delta's head before any
     entry: `{sequence: 0, sha256: deltaGenesis(<the held record's estate>)}`.
4. **Refusals.** A failed `auth` is answered with an `error`, then a close, both from the contract's `closeCodeFor`:
   - `unauthenticated`, `unsupported-alg`, `not-yet-valid`, `protocol-unsupported` and `replay` close with 4401;
   - past the frame's own bytes and the nonce there is one answer, `unauthenticated` (DEC-0066): an unknown kid, a
     revoked one, a relay holding no record or an expired one, another estate, a bad or high-S signature;
   - the message is fixed per code; the reason (no record, expired, an unknown kid) goes to the log line
     `auth-refused` only;
   - 4403 is sent only to a session whose signer was proven (A-4's revalidation, not yet applied).
5. **After `welcome`** (`src/core/frames.ts` classifies each frame against the relay-frame schema, compiled ahead of
   time, and FAC-SEM-071):
   - every answer carries `replyTo`, the id of the frame it answers, and its own fresh `id`: an `error` answering a
     frame, `accepted`, `pong`, `presence-result`;
   - `ping` is answered with `pong {replyTo}`;
   - `send`, `deliver` and `ack` are store-and-forward (see [Messages](#messages));
   - `presence-query` is answered with one `presence-result` ([presence](#presence));
   - a type a node never sends (`hello`, `welcome`, `accepted`, `deliver`, `presence`, `presence-result`, `error`) or
     no type the protocol knows gets `unknown-type`;
   - a known type that fails the schema or FAC-SEM-071 gets `malformed` (a `send` with `ttl` 0, `kids` that is not a
     list);
   - unknown members are ignored;
   - a known frame type not yet served (`delta`, `heartbeat`, `delta-query`: wave 4, H-1 and H-2) gets `error`
     `internal` "not served by this relay version yet";
   - text that is not a `{v: 1, type, id}` frame, including an `id` that is empty or longer than 128 code points, gets
     `malformed` with no `replyTo`, so the id is never echoed;
   - every one of these leaves the session open (before `auth`, anything but `auth` is refused `unauthenticated`,
     4401).
6. **Transport closes:**
   - a binary frame closes with 1003;
   - a frame over 1 MiB gets `too-large`, then 1009;
   - 90 s of silence closes with 1001 ("going away"); in the portable build, while the relay has bytes outstanding to
     the machine (queued, or written and not confirmed read), the limit is 5 minutes (`IDLE_OUTSTANDING_MS`, see Flow
     control); a portable relay that stops closes every session with the
     same 1001. A client reconnects; when the upgrade is answered 503, it waits for the `retry-after` seconds first;
   - a fault in the relay while handling a frame is logged as `session-fault`, answered `error` `internal`, and closes
     with 1011 (`RelaySession.fault`).

## The estate hub

Each build runs **one hub per estate** (`src/core/hub.ts`; why: [ADR-0002](../adr/0002-estate-hub.md)). It holds the
connection set and everything that spans connections:

- **Presence is derived from the set**, never stored: a machine is online while an admitted session in the set has its
  kid. Only `lastSeen` is kept.
- **One scheduler timer.** Each session says when it next needs attention (`nextDeadline()`: the 10 s auth deadline,
  then 90 s of silence); the hub arms its one timer at the earliest and closes exactly the sessions that are due. The
  portable build's socket heartbeat (Flow control below) is a separate interval timer.
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
  - A body over the limit gets `too-large`, whatever else the frame breaks.
  - Any other violation of the schema or FAC-SEM-071, or a missing `msgId`, `to` or `body`, gets `malformed`, naming
    the path. So does a `msgId` with a control character or a lone surrogate (this relay's own rule: stores would
    truncate or collapse it).
  - The recipient must be a machine the relay admits, else `unknown-recipient`.
  - If the recipient's mailbox already holds 1000 messages, the answer is `mailbox-full`. DEC-0047 leaves quotas
    undecided; 1000 is this relay's own limit.
  - On success the relay answers `accepted {replyTo, msgId, seq}`. `seq` is monotonic per mailbox.
  - A repeat of the same `(from, msgId)` while it is still queued answers its first `seq` and is not delivered again.
    DEC-0066 extends this past the ack, with a tombstone until the `ttl`, and adds `rate-limited` with `retryAfter`
    and the advertised `welcome.limits`: iteration node D-2.
- **`deliver`.** Every connection the recipient holds gets each unacknowledged message once, in `seq` order. A
  connection that opens later gets what waited for it. Where the transport reports a backlog (the portable build),
  delivery goes at the pace the machine reads (see Flow control); the Worker's hibernatable socket reports none, so
  there a flush sends every page at once, 64 messages a page.
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
- **`presence-query {kids}`** gets one `presence-result {replyTo, presences, unknown}` (DEC-0066). Every asked kid
  appears exactly once, in the order first asked (a kid asked twice is answered once):
  - in `presences` as `{kid, state, lastSeen}` when it is in the current admission set and the relay has seen it;
  - in `unknown` otherwise. A kid outside the set (another owner's, a revoked one) and a kid never seen are alike, so
    nothing leaks across owners. The relay invents no time.
  - More than 256 kids, or `kids` that is not a list of kids, gets `malformed`.
  - A node that sends `presence` or `presence-result` itself gets `unknown-type`.
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
- **The order of checks** is DEC-0066's: authenticate, then authorize, then touch state, then answer
  (`src/core/blobs.ts`).
  1. The header's form, `alg`, the recipients and `iat` within 60 s (`verifyBlobRequest`): 400, 431, 401.
  2. A `PUT` declares its `Content-Length`, at most 32 MiB (`MAX_BLOB_BYTES`): else 411 `malformed` or 413
     `too-large`. This answer depends only on the request's own bytes, so it comes before the signer is proven; the
     portable server leaves a blob `PUT`'s length to this step rather than refusing it first.
  3. The signer's key in the current admission set and the signature under it (`verifyBlobRequest`): one answer, 401
     `unauthenticated`, for an unknown kid, a revoked one, a relay holding no record and a bad or high-S signature.
  4. A `PUT`: every recipient admitted (403 `unknown-recipient`); the body read through a counting reader, at most its
     declared length (413, and the portable server closes the connection after any refused `PUT`); the bytes hash to
     the digest (422 `digest-mismatch`, whatever the state).
  5. The state (`decideBlobAccess`). A `PUT`: not held, expired or done is stored, 201; the same recipient list again is
     200 and restores an object the store lost; another list is 409 `recipients-mismatch`, never merged. A `GET`: a
     live record, its object present, the signer a recipient, the signed list equal to the stored one letter for
     letter: 200. Anything else (not held, expired, not a recipient, another list, an object lost) is one 403
     `not-admitted`, never 404. The relay does not say whether a blob exists.
  - A blob path that is not valid percent-encoding (`/v1/blobs/%`) is 400 `malformed`.
- **Serving a blob.** It re-checks the digest on `GET` before serving.
- **Deletion.** A blob is deleted once every stored recipient fetched it (counted per kid), or after 7 days, when it
  is next requested.
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
    (`.relay.test`), and no port 0. Last, the normalised origin must match the contract's `RELAY_ORIGIN_PATTERN`
    (`isRelayOrigin`, DEC-0066), the rule a node applies to `hello.relay`: one the URL parser accepts and the contract
    refuses (a name over 253 characters) refuses to start.
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
      drains it goes on. What is not sent yet stays in the mailbox, durable. Its acks are read meanwhile, and the
      heartbeat never terminates a socket with bytes outstanding (below). **The floor:** while bytes are outstanding, a
      reader must confirm progress at least every 5 minutes: a frame of its own (an ack, a ping) or a pong to one of
      the relay's heartbeat pings, which it answers on its own (every client library does) once it has read the ping.
      Acks are not required. Between two points it can confirm, a reader may have to read up to `SEND_HIGH` (1 MiB)
      plus one largest frame (1 MiB) plus what the kernel's send and receive buffers hold, so the floor is about
      (`SEND_HIGH` + `MAX_FRAME_BYTES` + kernel buffers) / 5 min: about 9 to 10 KiB/s with Linux's default buffers
      (round 14 measured gaps of 1.9 to 2.7 MiB; about 7 KiB/s on macOS), a few KiB/s more with a large `tcp_rmem`.
      The gaps are that large for four reasons: a frame under 64 KiB gets no marker ping; a beat sends no ping while
      an earlier one is unwritten; `bufferedAmount` does not see the kernel's buffers; and markers stop once 64 pings
      await their pongs. A slower reader is idle-closed (1001) and its mail stays queued for its next session. Placing
      markers by bytes written (one every 64 KiB, whatever the frame size) would lower the floor; it is a wave-2
      backlog item (HANDOFF).
    - **The socket is always read**, so acks and pings arrive whatever the relay has queued to send. A socket drain
      resumes delivery but is not activity: it is the kernel taking the relay's writes, not the peer confirming them.
    - **Replies to a machine that never reads are capped.** A reply is small because what the relay echoes is held to
      the relay-frame schema: a frame's `id` (echoed as a `pong`'s id or an error's `replyTo`) and a `send`'s `msgId`
      (echoed in `accepted` and `deliver`) are 1 to 128 code points, a recipient 1 to 256, and a body base64url
      characters only. A frame with a longer or empty `id` is refused like any text that is not a fabric-relay/0.1 frame
      (`error malformed` with no `replyTo`; before `auth`, `unauthenticated` and 4401); a `send` with a bad `msgId`,
      recipient or body gets `error malformed`; neither echoes what it refused. So the largest frame the relay sends
      is a `deliver` of the largest body, under `MAX_FRAME_BYTES`. The caps are checked before each write: a write
      that would take the socket's queue past 3 MiB (`SEND_CAP` = `SEND_HIGH` plus two 1 MiB frames, just above what
      deliveries can reach) or past 4096 frames not yet handed to the kernel (`SEND_FRAMES_CAP`: each queued write
      costs a few hundred bytes beyond its payload) is not made — a pong to the peer's own WebSocket ping included —
      and the session is logged `send-overflow`, closed 1008
      through its own close (its messages stay queued) and the socket terminated 1 s later unless it closes first.
    - **At most 8 sessions per machine** (`RELAY_MAX_SESSIONS_PER_MACHINE`, 1 to 1000): the next `auth` is answered
      `error` `rate-limited` and closed 1013 (logged `session-limit`); a session that ends makes room. Sessions a
      hosted hub restored after a hibernation wake count too.
    - **Heartbeat** (portable). One rule decides what counts: **progress is only what the peer confirms** — a frame
      it sends, or a pong whose 8-byte payload is that of a heartbeat ping the relay sent and still awaits. A pong for
      a ping confirms the bytes written before it only if the peer read them; payloads are random, so a peer cannot
      answer a ping it has not read. A write the relay makes is never progress,
      whether or not the kernel took it; nor is a drain, nor an unsolicited or unknown pong, nor a WebSocket ping the
      peer sends: the relay answers that ping itself (ws's automatic pong is off) under the same send caps as every
      other frame, and it keeps no session open, which stays open by its frames.
      - The relay pings every socket each 10 s, never a second ping behind one not yet written, and never more than
        64 awaiting their pongs; and it sends a marker ping right behind each frame of 64 KiB or more, so a slow reader
        confirms each delivery as soon as it has read it.
      - It terminates a socket only when nothing is outstanding to it (`bufferedAmount` 0 and at most 4 KiB not yet
        confirmed, the control traffic such as `welcome`) and it has shown no life (a matched pong or a frame) for 3
        beats (`heartbeat-timeout`): a peer that vanished frees its slot within 30 to 40 s.
      - A socket with more outstanding is never terminated by the heartbeat; it is governed by the session's idle
        close, where its frames and the matched pongs that confirm new bytes are activity, with a limit of 5 minutes
        while bytes are outstanding (`idleOutstandingMs`) and 90 s otherwise. A frozen peer is freed within the 5
        minutes even while other machines keep sending to it; a client that answers pings but sends no frame, or that
        only sends WebSocket pings, is idle-closed at 90 s.
      - Clocks: the heartbeat runs on a monotonic clock, and a beat that fires late (a stalled loop) does not count its
        lateness as silence. Session deadlines (the auth deadline and the idle close) use the wall clock the relay is
        given (`ServeOptions.now`, the system's by default), so a wall clock stepped forward by 90 s or more closes the
        sessions that were quiet; a step back delays their idle close by as much. The hub's own timer runs its
        deadlines (`nextDeadline()`); the heartbeat is a separate interval timer, which also runs any deadline that is
        due.
    - **The Worker has no socket heartbeat.** Its hibernatable sockets are not pinged by the relay (a timer per
      socket would keep the object awake), so a peer that vanishes without a close holds its slot until the 90 s idle
      close. The Worker also reports no backlog, so its flush reads the mailbox 64 messages a page (a 1000-message
      backlog is 16 mailbox calls; F-8 revisits it against the hosted limits).
    - **The bound** this gives: what the relay holds queued for one session is at most `SEND_CAP`, 3 MiB, so for one
      machine at most 8 x 3 MiB = 24 MiB (`Served.flow().peakBuffered` reports the most any socket held). On top of it
      come the mailbox page a flush is sending from (four bodies), the inbound frames being parsed, and memory the
      allocator has not returned yet. Measured: 2 machines x 8 non-reading sessions flooding pings with 1000 KiB ids
      and sends with 1000 KiB msgIds queue under 64 KiB with no overflow (before the id and msgId limits every session
      overflowed, with up to 4 MiB queued); 30 non-reading sessions of one machine with 11 MiB of mail grew the
      footprint by 41 to 75 MiB (727 MiB before paced delivery and the session limit).
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
