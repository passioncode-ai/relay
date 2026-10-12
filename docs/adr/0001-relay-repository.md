# ADR-0001 — The relay: its own repository, one core with two builds, its protocol in the contract

- **Date:** 2026-10-12
- **Status:** accepted. The operator confirmed on 2026-10-12: own repository, Observatory as code owner, and the
  self-hosted relay stays.
- **Agreed by:**
  - Project Observatory: code owner.
  - Fabric: owner of ADR-0088, where the relay began.
  - The PassionCode.ai knowledge base: plans and roadmap.
  - The fabric-agent-contract owner: the protocol, DEC-0047.

## Context

- Fabric ADR-0088 decided that one relay carries every remote surface of a person's machines: desktop, headset,
  phone. The relay is an always-on endpoint the machines connect out to. It holds a projection cache and a command
  queue, and **no authority**: policy, journal and grants stay on the machine.
- The organization's agent network (roadmap RM-21) needs the same relay between a person's own machines, and later
  between colleagues.
- The knowledge base (plans, D1) settled where it runs:
  - by default, a PassionCode-hosted Cloudflare Worker;
  - for a customer that requires it, a relay they run themselves.
- Machines authenticate to the relay with their device key inside the WebSocket connection. Access-style login
  protects only people's web pages.

## Decision

1. **Own repository, `passioncode-ai/relay`**, rather than inside Fabric or Project Observatory:
   - it deploys on its own cadence with its own configuration;
   - several products are its clients;
   - the self-hosted build comes from exactly one place.
2. **Licence:** `AGPL-3.0-only OR LicenseRef-PassionCode-Commercial`. The relay and its protocol are an open
   component. Nothing here depends on a closed module.
3. **The protocol is fabric-agent-contract DEC-0047, not this code.** It covers:
   - frames;
   - device-key authentication inside the WebSocket;
   - the secret-envelope format;
   - trust tiers;
   - revocation, with vectors.

   No client depends on this server's code. Until DEC-0047 is accepted, the relay refuses every session with a
   not-ready refusal: an endpoint that accepted connections before machines could prove themselves would be an open
   relay. *(Superseded: DEC-0047 was accepted on 2026-10-12; see [Amendment 1](#amendment-1-2026-10-12).)*
4. **Owners:**
   - Project Observatory owns the server code: its node is a relay client that opens envelopes into its vault.
   - Fabric owns its remote surfaces' client side (ADR-0088).
   - Other products are clients.

### Two builds

The core (`src/core/`) uses only web-standard APIs: `Request`, `Response`, `crypto.subtle`. Two adapters route
every request through it and add no route of their own:

| Build | Where | Sessions | Blobs |
|---|---|---|---|
| Hosted (`src/cloudflare/`) | Cloudflare Worker, run by PassionCode.ai | Durable Objects (SQLite) | R2 |
| Portable (`src/portable/`) | one Node server, for self-hosting | (with DEC-0047) *(amended: in memory; mailboxes and `lastSeen` in SQLite)* | files under `RELAY_DATA_DIR`, owner-only |

Packaging the portable build as a single executable is a backlog item (RLY-04).

### What the relay holds

- It holds sessions, sealed envelopes and package blobs, the last two by the SHA-256 digest of their bytes.
- It recomputes the digest of every blob on write and on read. It refuses bytes that do not match their name, so a
  corrupted file or an edited bucket is refused, never served.
- It never holds plaintext content at rest. *(Superseded by [Amendment 1](#amendment-1-2026-10-12): message bodies
  are stored as sent.)*
- It makes no trust decision and serves no signing page.

### The security model DEC-0047 pins

- **Who connects:** a machine proves itself with its device key inside the WebSocket connection. No bearer token
  travels in a URL or in a header a proxy could log.
- **Envelopes:** a secret is sealed to the target machine's device key by the service that issued it, carried by
  the relay, and opened only in the target's vault.
- **Trust tiers:** relay traffic is cross-machine by definition.
  - A call between one owner's enrolled machines is T1.
  - A call from another person's machine is T2, under the full delegation model.
  - Work on a single machine (T0) never touches the relay.
  - The tier follows where the call came from, not the connection.
- **Revocation:** the revocation delta rides the relay. A machine that has not applied it up to the signed head
  refuses the tokens that delta governs. The relay can delay revocation but cannot forge it.
- **The contract owner's review conditions:**
  - everything signed or hashed uses RFC 8785 canonical form;
  - every Ed25519 key passes the small-order check, the envelope's target device keys included *(amended: every relay
    participant signs ES256; the small-order rule covers the Ed25519 keys elsewhere in the contract)*;
  - the revocation delta ships vectors.

## Consequences

- The org-index `repositories.json` gains a `relay` row. The roadmap's RM-21 names this repository.
- Fabric amends ADR-0088 to say where the relay lives: server `passioncode-ai/relay`, owner Project Observatory,
  protocol DEC-0047, Fabric a client.
- The next work is in [the backlog](../backlog.md). *(Amended: RLY-01 and RLY-02 are done.)*

## Amendment 1 (2026-10-12)

Release iteration 1's truth pass (relay RLY-018, RLY-019). The lines above that it supersedes are kept and marked.

1. **What the relay holds.** It holds signed message bodies it can read but cannot forge, blobs by digest, and
   secrets only as sealed envelopes; a secret is never in plaintext at the relay. A `send` body is opaque to the relay
   but is stored as sent (`src/cloudflare/mailbox.ts`, `src/portable/sqlite-mailbox.ts`); end-to-end confidentiality
   of a body is the sending machines' choice, by sealing it. This replaces "never holds plaintext content at rest".
2. **DEC-0047 was accepted** (fabric-agent-contract #53, `8060254`, 2026-10-12). The not-ready refusal is gone;
   sessions run as `docs/protocol/sessions.md` describes.
3. **Sessions.** Hosted: every session of an estate lives in one hibernating Durable Object, the estate hub
   ([ADR-0002](0002-estate-hub.md)). Portable: sessions in memory in one process hub; mailboxes and `lastSeen` in
   SQLite under `RELAY_DATA_DIR`.
4. **Keys.** Every relay participant signs ES256 (DEC-0047 *Why*: "ES256 only for the relay"); the small-order rule
   covers the Ed25519 keys elsewhere in the contract.
