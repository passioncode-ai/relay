// The self-hosted relay's entry point. Configuration is environment only, and holds no secret:
//   RELAY_DATA_DIR  where blobs are kept (required; the relay never picks a folder for you)
//   RELAY_HOST      interface to listen on (default 127.0.0.1; put a TLS terminator in front for anything else). A bare
//                   address: a bracketed one ([::1]) refuses to start (exit 2).
//   RELAY_PORT      port (default 8787)
//   RELAY_ORIGIN    the public origin machines sign into relay-auth/1 (behind a TLS terminator: its https:// URL).
//                   Normalised (src/portable/origin.ts); a path, query, fragment, credentials or another scheme refuse
//                   to start (exit 2). http:// only on a loopback literal (127.0.0.0/8, [::1]; never "localhost"),
//                   and only when RELAY_HOST is a loopback literal too.
//                   Unset: allowed only when RELAY_HOST is a loopback literal; the origin is then
//                   the canonical http://RELAY_HOST:<bound port> (0:0:0:0:0:0:0:1 gives http://[::1]:<port>), which
//                   only a local machine can reach (logged origin-defaulted).
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

// SIGTERM, SIGINT or SIGHUP (the terminal that started the relay closed): a graceful stop (every session closed 1001, lastSeen written, stores closed), exit 0. Past the
// ceiling it exits 1 with stop-timeout; a stop that fails exits 1 with stop-failed. A second signal from the operator (a
// second Ctrl-C) exits 1 at once with stop-forced. The same signal again within REPEAT_MS of the first is not a second
// press: `npm run portable` forwards the terminal's SIGINT, so node sees one Ctrl-C twice. A supervisor must wait
// longer than the ceiling before it kills (systemd TimeoutStopSec=20, launchd ExitTimeOut=20).
const GRACE_MS = 5000;
const CEILING_MS = GRACE_MS + 5000;
const REPEAT_MS = 1000;
let first: { signal: string; at: number } | undefined;
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
  process.on(signal, () => {
    if (first) {
      if (first.signal === signal && Date.now() - first.at < REPEAT_MS) {
        log({ event: "signal-repeated", signal });
        return;
      }
      log({ event: "stop-forced", signal });
      process.exit(1);
    }
    first = { signal, at: Date.now() };
    log({ event: "stopping", signal });
    setTimeout(() => {
      log({ event: "stop-timeout", ms: CEILING_MS });
      process.exit(1);
    }, CEILING_MS).unref();
    served.stop({ graceMs: GRACE_MS }).then(() => process.exit(0), (error: unknown) => {
      log({ event: "stop-failed", error: (error as Error)?.name ?? "Error", message: String((error as Error)?.message ?? error).slice(0, 200) });
      process.exit(1);
    });
  });
}
