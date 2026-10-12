# DEC-0047 draft — the relay protocol and the secret envelope (`fabric-relay/0.1`, `fabric-secret-envelope/1`)

> **A draft for review, not a decision.** The number is reserved in
> [fabric-agent-contract](https://github.com/passioncode-ai/fabric-agent-contract) (git CAS key
> `relay-protocol-20261012`). The contract owner lands the accepted text in that repository's `docs/DECISIONS.md`,
> together with the schemas, rules and vectors named below. Until then, this relay refuses every session.
> Written by Project Observatory, the relay's code owner, on 2026-10-12.

- **Date:** 2026-10-12 (draft)
- **Status:** Draft for the contract owner's review.
- **Amends:** nothing. This is a new protocol under the DEC-0016 extension policy. It uses DEC-0031 (devices),
  DEC-0039 and DEC-0045 (delegation, trust tiers, the small-order check) and DEC-0043 (canonical forms).
- **Designed together with** the organization architecture's "secure transport" set (contract board item
  `V4-SECURE-TRANSPORT`). The proposed split is in §8.

## Decision

### 1. Roles and what each may do

| Role | Who | May | May not |
|---|---|---|---|
| **relay** | the server (`passioncode-ai/relay`), hosted or self-hosted | admit a machine that proves its device key; queue and deliver opaque messages; store sealed envelopes and package blobs by digest; report when a machine was last seen; carry signed revocation deltas and heartbeats | read a message body or a secret; decide a trust tier; sign anything a node relies on; report a queued command as done; serve a signing page |
| **node** | a machine's agent host (the Observatory node) | connect out to the relay; send and receive messages; seal and open envelopes; apply deltas | trust the relay's word for anything a signature does not carry |
| **surface** | a remote surface of a person's tools (Fabric ADR-0088) | the same as a node, under its own device key | |

The relay is a router with a mailbox. **End-to-end signatures and seals carry all authority.** A compromised
relay can delay, drop or count messages; it cannot forge, read or replay one past the recipient's checks.

### 2. Transport

- One WebSocket per connection, over TLS 1.2 or newer (TLS 1.3 SHOULD), to `wss://<relay>/v1/connect`, with the
  subprotocol `fabric-relay.v1` in `Sec-WebSocket-Protocol`. A relay that receives no matching subprotocol
  refuses the upgrade.
- **No credential travels in the URL or in an HTTP header.** Authentication happens inside the connection (§3),
  so a proxy log or a fork's access log holds nothing a caller could reuse.
- Frames are UTF-8 JSON text frames. Each frame carries `{"v": 1, "type": <string>, "id": <string>}` plus that
  type's members.
- A frame is at most 1 MiB. A relay closes a connection that sends a larger frame (close code 1009) or a binary
  frame (close code 1003).
- Unknown members are ignored. An unknown `type` is answered with an `error` of code `unknown-type`, and the
  connection stays open.
- Blobs (sealed envelopes and package bytes) do not travel in frames. They travel over HTTPS by digest (§6).

### 3. Handshake: the machine proves its device key inside the connection

1. On open, the relay sends `hello` with these members:
   - `protocol`: `"fabric-relay/0.1"`;
   - `relay`: the relay's origin, e.g. `"https://relay.example"`;
   - `nonce`: 32 random bytes, base64url;
   - `time`: RFC 3339 UTC.
2. Within 10 seconds, the machine sends `auth` with:
   - `protocol`;
   - `estate`: the estate id, or the organization id for organization traffic;
   - `kid`: the device signing key's id;
   - `iat`: RFC 3339 UTC;
   - `sig`.

   `sig` is an ES256 signature (raw `r‖s`, 64 bytes, base64url) by the device signing key over the RFC 8785 bytes
   of the following object. RFC 8785 is the canonical form, per the DEC-0043 register.

   ```json
   {"type": "relay-auth/1", "relay": "<hello.relay>", "nonce": "<hello.nonce>",
    "estate": "<estate>", "kid": "<kid>", "iat": "<iat>"}
   ```
3. The relay admits the machine only when all of these hold:
   - the signature verifies under the public key that the **admission set** lists for `kid` (§3.1);
   - `relay` equals its own origin, so a signature made for one relay is refused by another;
   - `nonce` is the one it sent on this connection, and is used once;
   - `|iat − now| ≤ 60 s`.

   Then it answers `welcome` with:
   - `session`: an opaque id;
   - `estateRevision`: the latest estate revision it holds;
   - `deltaHead`: `{seq, hash}`;
   - `heartbeat`: the latest signed heartbeat it holds, or `null`.

   Otherwise it sends `error` with code `unauthenticated` or `not-admitted`, then closes with code 4401 or
   4403.
4. A machine authenticates once per connection. The relay attributes every frame on the connection to that
   `kid`, and to nothing the frame claims.

#### 3.1 The admission set

- **What it is.** The admission set is the set of device signing keys listed as machines in the latest estate
  record (`estate-record/1`, contract board `V4-ESTATE-RECORD`) or organization record the relay holds, minus
  those revoked by an applied delta.
- **What it is for.** It keeps strangers from filling mailboxes. **It is not authorization**: a recipient checks
  the sender itself (§5).
- **Until the record exists.** Until `estate-record/1` is accepted, a deployment configures its admission set
  out of band. This is the same posture DEC-0031 takes for trusted policy keys before OQ-0010.

#### 3.2 Keys

- **Device keys are P-256.** By the organization architecture's rule "algorithms by role", keys held by hardware
  (device keys, passkeys, organization roots) are P-256, held in the platform keystore (DEC-0031
  `platform-keystore`).
- **Two keys per machine.** A machine has two device keys, both non-exportable:
  - a **signing key** (ES256), used for `auth`, message signatures and envelope signatures;
  - a **key-agreement key** (ECDH P-256), used only to open envelopes.

  The estate record lists both, under kids `<machine>#sig` and `<machine>#kem`. **Never seal to a signing key,
  and never sign with a key-agreement key.**
- **Every public key is validated before use:**
  - a P-256 key by SEC 1 §3.2.2 public-key validation: not the point at infinity, coordinates in range, on the
    curve;
  - an Ed25519 key anywhere in the protocol (a delegation issuer under DEC-0039's EdDSA, for as long as it is
    admitted) by DEC-0045's small-order check (CT-29, `isSmallOrderKey`).

  A key that fails either check is refused as `bad-key`, and nothing is verified under it.

### 4. Messages: store and forward, never reported done by the relay

- **`send`**: `{to, msgId, body, ttl}`.
  - `to` is a recipient `kid` (`#sig`).
  - `msgId` is a UUID chosen by the sender.
  - `body` is an opaque base64url string, at most 768 KiB decoded.
  - `ttl` is in seconds, at most 7 days.

  The relay appends the message to the recipient's mailbox and answers `accepted` with `{msgId, seq}`. `seq` is
  monotonic per mailbox.

  It refuses with an `error`:
  - `unknown-recipient` when `to` is not in the admission set;
  - `too-large`;
  - `rate-limited`;
  - `mailbox-full`.

  The same `msgId` from the same sender within its `ttl` is accepted once; a repeat answers the first `seq`.
- **`deliver`**: `{from, msgId, seq, body, sentAt}`, to the recipient on every connection it holds, in `seq`
  order. `from` is the kid the relay authenticated on the sender's connection.
  - The recipient answers `ack` with `{seq}`. The relay deletes acknowledged messages and expired ones.
  - Delivery is at least once. A recipient deduplicates by `(from, msgId)`.
- **The body is end to end.** A body is a `fabric-relay-message/1`: an ES256 JWS (compact) by the sender's signing
  key over the RFC 8785 payload `{type, from, to, msgId, iat, payload}`, where `payload` is the application's own
  message (for example a Fabric typed command, ADR-0088).
  - The recipient refuses a body when its signed `from`, `to` or `msgId` differs from the frame's.
  - It also refuses a body whose `iat` is older than the message's `ttl`.
  - A body that must stay secret from the relay carries its payload as a `fabric-secret-envelope/1` (§6).
- **Presence**: `presence` frames, as `{kid, state: "online" | "offline", lastSeen}`.
  - The relay sends them to the machines of the same estate when a peer connects or disconnects.
  - A node may ask with `presence-query` `{kids}`.
- **The relay never says a command was done.** A queued message stays queued with its `seq`. Only the
  recipient's own signed receipt, a message back, reports an outcome. This keeps ADR-0088's offline rule: "queues
  commands, and never reports them done".
- **Keepalive.** `ping` and `pong`. A relay closes a connection silent for 90 s.

### 5. Trust tiers follow the signed sender, not the connection

- **Relay traffic is never T0.** T0 is work on one machine over loopback (DL-25) and never reaches the relay.
- **The tier is the recipient's decision**, taken from the message body's signature, never from the connection
  it arrived on:
  - **T1:** the signed `from` is a machine of the recipient's own estate, listed in the current estate record,
    not revoked by an applied delta, and with a signature that verifies. DL-26 applies: no token, approval or
    grant record is required of a T1 caller.
  - **T2:** anything else. This includes a message signed by an outsider but forwarded by a T1 machine's session.
    DL-8 applies: a delegation token per call, bound to the caller's key (DPoP, contract board `V4-DELEGATION`),
    and an approval per effect.
- **Organization mode.** Until device keys are hardware-attested, tokenless T1 calls and secret placement on
  personal machines enrolled in an organization are off, unless a person working alone accepts the risk. This is
  the organization architecture's rule; it lives in the "T1 by machine identity" rule of `V4-DELEGATION`, and
  this protocol only carries the sender's identity it relies on.
- **Guests.** A person outside the estate reaches a service through the relay's OAuth page, under a
  passkey-signed binding of their key thumbprint (organization architecture, path "someone outside"). That page
  is a later stage of this protocol and is not decided here.

### 6. The secret envelope (`fabric-secret-envelope/1`)

A secret moves to a machine only where a placed package declares it. It is sealed to that machine's
key-agreement key by the machine that holds the slot (its door), carried by the relay as a blob, and opened only
in the target's vault.

- **Seal:**
  - HPKE (RFC 9180), base mode;
  - suite `DHKEM(P-256, HKDF-SHA256)` (`0x0010`), `HKDF-SHA256` (`0x0001`), `AES-128-GCM` (`0x0001`);
  - recipient key: the target's `#kem` key.
- **Header**, the HPKE `aad`, as RFC 8785 bytes:
  - `type`: `"fabric-secret-envelope/1"`;
  - `suite`: `[16, 1, 1]`;
  - `recipient`: the target's `#kem` kid;
  - `sender`: the sealing machine's `#sig` kid;
  - `slot`: the credential's name, never its value;
  - `placement`: the estate revision that placed this secret on the target;
  - `iat`, `exp`: RFC 3339, `exp − iat ≤ 24 h`;
  - `enc`: the HPKE encapsulated key, base64url.
- **HPKE `info`:** the ASCII bytes `fabric-secret-envelope/1`.
- **Envelope:** `{header, ct, sig}`.
  - `ct` is the HPKE ciphertext, base64url.
  - `sig` is an ES256 signature by `sender` over the RFC 8785 bytes of `{header, ct}`.
  - The envelope's **digest** is `sha256:` followed by the hex SHA-256 of the RFC 8785 bytes of the whole
    envelope.
- **Open.** The target opens an envelope only when all of these hold:
  - `recipient` is its own `#kem` kid;
  - `sender` verifies, and is a machine that the current estate record lets hold `slot`;
  - `placement` is the current placement of `slot` on this machine, or a newer one;
  - `now < exp`;
  - both keys pass §3.2.

  A refusal names its reason and stores nothing.
- **Carriage.**
  - The sender uploads the envelope with `PUT /v1/blobs/<digest>`, carrying `Fabric-Relay-Request`: an ES256
    signature by the sender's `#sig` key over the RFC 8785 bytes of
    `{type: "relay-blob/1", relay, method, digest, recipients, iat}`.
  - That signature is single-purpose, and accepted within 60 s of `iat`; replaying it re-uploads the same
    bytes. It is not a bearer credential.
  - The relay recomputes the digest and refuses a mismatch.
  - A `GET` carries the same request signature by one of the `recipients`.
  - The sender then sends the digest to the target in a message.
  - The relay keeps a blob until every recipient fetched it, or until 7 days pass.

Package blobs travel the same way, with their own type and signatures (`fabric-package/1`, contract board
`V4-PACKAGE`). The relay only checks digests.

### 7. Revocation rides the relay; the relay can delay it, not forge it

- The relay carries two signed objects as they are, in `delta` and `heartbeat` frames, and never rewrites them:
  - the fast **revocation delta**: members, hubs, grants, devices, publisher keys, digests, `subject.erase`;
  - the daily **timestamp heartbeat**, which signs the delta's head `{seq, hash}`.

  Their content, signatures and the rule "a host that has not applied up to the heartbeat's head refuses the
  tokens that delta governs" are the adjacent decision's (§8).
- **On `welcome`** the relay sends its `deltaHead` and its latest heartbeat. A node behind the head asks with
  `delta-query` `{fromSeq}`, and the relay answers with the entries it holds.
- **On receipt** of a new delta or heartbeat, the relay sends it to every connected machine in the estate or
  organization it names.
- A relay that withholds a delta is detected by the heartbeat. Its head is signed by a key the relay does not
  hold, and a node that has seen a newer head refuses to act as though it had not. A relay cannot invent an
  entry, because each entry is signed.

### 8. The proposed split with the secure-transport set

| Decision | Carries |
|---|---|
| **DEC-0047** (this draft) | the relay's frames, the handshake, admission, messages and presence, the secret envelope, key separation and key validation, blob carriage, and how deltas and heartbeats travel |
| **an adjacent DEC** (to reserve) | the revocation delta and timestamp heartbeat as documents: their fields, signing keys, head hash, the 72-hour rule, extensions, and their vectors (the contract owner's review condition 4) |
| with `V4-DELEGATION` | the "T1 by machine identity" rule and its scope, DPoP for outside people |
| with their own items | the window lease and the signing challenge types: neither travels as a relay frame of its own |

### 9. Errors

`error` frames carry `{code, message}`. Codes are kebab-case, matching the contract's style:

| Code | Meaning |
|---|---|
| `protocol-unsupported` | |
| `unauthenticated` | |
| `not-admitted` | |
| `bad-key` | |
| `replay` | |
| `unknown-type` | |
| `unknown-recipient` | |
| `too-large` | |
| `rate-limited` | |
| `mailbox-full` | |
| `expired` | |
| `digest-mismatch` | |
| `internal` | |

`message` is one bounded line, without paths or values.

## Consequences (when accepted)

- **In the contract:**
  - schemas `relay-frame`, `relay-message`, `secret-envelope`, `relay-blob-request`;
  - rules reserved through `agent_sync.py reserve SEM`;
  - vectors in `fixtures/vectors/`:
    - the `relay-auth/1` signing input and its SHA-256;
    - an envelope sealed with a fixed ephemeral key (RFC 9180 style), with its open result;
    - P-256 keys that fail validation (the identity point, an off-curve point, a coordinate out of range);
    - an Ed25519 small-order key refused as `bad-key`.
- **In the relay:**
  - RLY-02 implements §§2–5 in both builds;
  - RLY-03 implements §6's carriage;
  - the vectors run in the relay's tests.
- **In the Observatory node:** the relay client, and the vault opening envelopes.
- **In Fabric:** ADR-0088 is amended to name this protocol, and its remote surfaces become clients.

## Not decided here

- The guest OAuth page and its binding ceremony.
- Hardware attestation formats (OQ-0010 a).
- Mailbox quotas per estate.
- Whether a self-hosted relay federates with the hosted one.

## Questions for the contract owner

1. **Key algorithm.** Review condition 2 names Ed25519 device keys. The organization architecture makes device
   keys P-256 (ES256), because platform keystores hold P-256. This draft therefore validates P-256 keys by SEC 1,
   and applies DEC-0045's small-order check to every Ed25519 key the protocol meets. Is that the reading you want?
2. **The split in §8:** one DEC-0047, or DEC-0047 plus an adjacent revocation decision?
3. **Admission before `estate-record/1`:** is a deployment-configured admission set acceptable as the interim, as
   DEC-0031 does for trusted policy keys before OQ-0010?
