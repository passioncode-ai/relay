// The self-hosted relay's entry point. Configuration is environment only, and holds no secret:
//   RELAY_DATA_DIR  where blobs are kept (required; the relay never picks a folder for you)
//   RELAY_HOST      interface to listen on (default 127.0.0.1; put a TLS terminator in front for anything else)
//   RELAY_PORT      port (default 8787)
//   RELAY_ORIGIN    the public origin machines sign into relay-auth/1 (behind a TLS terminator: its https:// URL).
//                   Normalised (src/portable/origin.ts); a path, query, fragment, credentials or another scheme refuse
//                   to start (exit 2). http:// only on a loopback literal (127.0.0.0/8, [::1]; never "localhost").
//                   Unset: allowed only when RELAY_HOST is a loopback literal; the origin is then
//                   http://RELAY_HOST:<bound port>, which only a local machine can reach (logged origin-defaulted).
// Queued messages are kept in RELAY_DATA_DIR/mailbox.sqlite and each machine's last-seen time in
// RELAY_DATA_DIR/presence.sqlite (both owner-only). The estate the relay admits from is kept under RELAY_DATA_DIR/estate/ (pinned.json, revisions/<n>.json); without it
// the relay admits nobody.
// Logs are one JSON object per line on stdout.

import type { AddressInfo } from "node:net";
import { OriginRefused } from "./origin.ts";
import { serve, type Served } from "./server.ts";
import { FsBlobIndex, FsBlobStore, FsEstateSource } from "./fs-store.ts";
import { SqliteMailbox } from "./sqlite-mailbox.ts";
import { SqliteLastSeen } from "./sqlite-last-seen.ts";
import { join } from "node:path";
import { PROTOCOL, VERSION } from "../core/relay.ts";
import { jsonLog } from "../core/log.ts";

const log = jsonLog("portable");

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

let served: Served;
try {
  served = await serve({ runtime: "portable", blobs: new FsBlobStore(dataDir) }, { host, port, log, estate: new FsEstateSource(dataDir), mailbox: new SqliteMailbox(join(dataDir, "mailbox.sqlite")), lastSeen: new SqliteLastSeen(join(dataDir, "presence.sqlite")), blobIndex: new FsBlobIndex(dataDir), ...(process.env.RELAY_ORIGIN ? { origin: process.env.RELAY_ORIGIN } : {}) });
} catch (error) {
  if (!(error instanceof OriginRefused)) throw error;
  log({ event: "refused-to-start", reason: error.message });
  process.exit(2);
}
const server = served.server;
const address = server.address() as AddressInfo;
log({ event: "listening", host: address.address, port: address.port, origin: served.origin, version: VERSION, protocol: PROTOCOL });

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    log({ event: "stopping", signal });
    server.close(() => process.exit(0));
  });
}
