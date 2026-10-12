// The self-hosted relay's entry point. Configuration is environment only, and holds no secret:
//   RELAY_DATA_DIR  where blobs are kept (required; the relay never picks a folder for you)
//   RELAY_HOST      interface to listen on (default 127.0.0.1; put a TLS terminator in front for anything else)
//   RELAY_PORT      port (default 8787)
//   RELAY_ORIGIN    the public origin machines sign into relay-auth/1 (behind a TLS terminator: its https:// URL;
//                   default http://RELAY_HOST:RELAY_PORT, which only a local machine can reach)
// Queued messages are kept in RELAY_DATA_DIR/mailbox.sqlite (owner-only). The estate the relay admits from is kept under RELAY_DATA_DIR/estate/ (pinned.json, revisions/<n>.json); without it
// the relay admits nobody.
// Logs are one JSON object per line on stdout.

import type { AddressInfo } from "node:net";
import { serve } from "./server.ts";
import { FsBlobStore, FsEstateSource } from "./fs-store.ts";
import { SqliteMailbox } from "./sqlite-mailbox.ts";
import { join } from "node:path";
import { PROTOCOL, VERSION } from "../core/relay.ts";

const log = (event: Record<string, unknown>) => console.log(JSON.stringify({ at: new Date().toISOString(), ...event }));

const dataDir = process.env.RELAY_DATA_DIR;
if (!dataDir) {
  log({ event: "refused-to-start", reason: "RELAY_DATA_DIR is not set" });
  process.exit(2);
}
const host = process.env.RELAY_HOST ?? "127.0.0.1";
const port = Number(process.env.RELAY_PORT ?? 8787);
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  log({ event: "refused-to-start", reason: "RELAY_PORT is not a port number" });
  process.exit(2);
}

const origin = process.env.RELAY_ORIGIN;
if (!origin) log({ event: "origin-defaulted", reason: "RELAY_ORIGIN is not set: machines must sign the http:// address, so only a local machine can authenticate" });
const server = await serve({ runtime: "portable", blobs: new FsBlobStore(dataDir) }, { host, port, log, estate: new FsEstateSource(dataDir), mailbox: new SqliteMailbox(join(dataDir, "mailbox.sqlite")), ...(origin ? { origin } : {}) });
const address = server.address() as AddressInfo;
log({ event: "listening", host: address.address, port: address.port, version: VERSION, protocol: PROTOCOL });

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    log({ event: "stopping", signal });
    server.close(() => process.exit(0));
  });
}
