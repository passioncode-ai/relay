# Relay backlog

The local board. Status is edited here only. The common workspace backlog aggregates it
through [backlog-sources.json](backlog-sources.json).

| ID | Item | Status | Evidence |
|---|---|---|---|
| RLY-00 | Walking skeleton: runtime-neutral core, Cloudflare and portable adapters, health, digest-verified blob stores, every session refused until DEC-0047 | done 2026-10-12 | `npm run check`: 17 tests, typecheck clean |
| RLY-01 | DEC-0047 draft in fabric-agent-contract: frames, device-key auth inside WSS, envelope format (RFC 8785), small-order check on every key, T1/T2 by call origin, revocation delta with vectors; designed together with the contract's v4 revocation delta, heartbeat and envelope | done 2026-10-12 | fabric-agent-contract#53 merged at `8060254` after three readings |
| RLY-02 | Handshake and session per the accepted DEC-0047: a Durable Object per session in the hosted build, SQLite in the portable build; vectors from the contract run in this repository's tests | done 2026-10-12 | relay#1; contract pinned at fabric-agent-contract `c00a0c3` (#59's merge); [sessions](protocol/sessions.md) |
| RLY-03 | Envelope and blob routes: put and get by digest for authenticated machines only, size limits, retention | open | needs RLY-02 |
| RLY-04 | Portable build as a single executable (Node single-executable application), with a reproducible-build check | open | |
| RLY-05 | Hosted deployment: Cloudflare account, route, R2 bucket, observability; the deploy workflow behind the release guard | open | needs RLY-02 |
| RLY-06 | Offline semantics from Fabric ADR-0088: "last seen" time, a queued command never reported done | open | needs RLY-02 |
