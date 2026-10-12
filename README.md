# PassionCode Relay

PassionCode Relay carries sessions, sealed secret envelopes and package blobs between machines. The machines can belong to one person or to an organization. The relay holds no authority and no plaintext: every machine proves itself with its own device key, and every secret is sealed to the machine that will open it. The relay sees only digests and ciphertext.

It ships as two builds of one runtime-neutral core:
- **Hosted:** a Cloudflare Worker with Durable Objects and R2. PassionCode.ai runs it.
- **Portable:** one Node server for self-hosting.

Its wire protocol belongs to [fabric-agent-contract](https://github.com/passioncode-ai/fabric-agent-contract), not to this code: **DEC-0047** (`fabric-relay/0.1`), with the contract's reference code vendored at the commit [`fabric-contract.lock.json`](fabric-contract.lock.json) pins. A machine opens a session on `wss://<relay>/v1/connect` and is admitted only from a verified estate record (DEC-0055); how is in [docs/protocol/sessions.md](docs/protocol/sessions.md).

## Quick start for a new teammate

**Install.** Node 22.13 or newer, then `npm ci`.

**Configure.** The hosted build reads two bindings, `SESSIONS` (a Durable Object namespace) and `BLOBS` (an R2 bucket), from [`wrangler.jsonc`](wrangler.jsonc). It needs no keys. Deployment values (account, routes) are not kept in this repository. The portable build reads three environment variables:
- `RELAY_DATA_DIR` (required)
- `RELAY_HOST` (default `127.0.0.1`)
- `RELAY_PORT` (default `8787`)
- `RELAY_ORIGIN` (the public origin machines sign; default `http://RELAY_HOST:RELAY_PORT`, local machines only)

None of them is a secret. The estate the relay admits from (the pinned passkeys and the record's revisions) is kept
under `RELAY_DATA_DIR/estate/` in the portable build and under `estate/` in the R2 bucket in the hosted one.

**MCP.** None: the relay is not an MCP server. Fabric's remote surfaces reach it as a client (Fabric ADR-0088). `GET /healthz` proves it is up; a session proves admission works.

**Develop.**

| What | Command |
|---|---|
| The whole gate: types, then every test (the Worker runs in workerd, no network) | `npm run check` |
| The hosted build locally | `npm run dev` |
| The portable build | `RELAY_DATA_DIR=./relay-data npm run portable` |

How the parts fit, and why the code lives here, is in [docs/adr/0001-relay-repository.md](docs/adr/0001-relay-repository.md).

## License

Open source under the [GNU AGPL-3.0](LICENSE). A [commercial license](COMMERCIAL-LICENSE.md) is
available for use that does not meet the AGPL's terms — [passioncode.ai/business](https://passioncode.ai/business/).
