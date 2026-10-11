# Changelog

## Unreleased

- Walking skeleton (RLY-00):
  - a runtime-neutral core with two builds: a Cloudflare Worker with Durable Objects and R2, and a portable Node
    server;
  - `GET /healthz`;
  - blob stores that verify the SHA-256 digest of every blob on write and on read;
  - every session refused with `protocol-not-ready` until fabric-agent-contract DEC-0047 is accepted.
