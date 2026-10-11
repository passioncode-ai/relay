// The self-hosted relay's entry point. Configuration is environment only, and holds no secret:
//   RELAY_DATA_DIR  where blobs are kept (required; the relay never picks a folder for you)
//   RELAY_HOST      interface to listen on (default 127.0.0.1; put a TLS terminator in front for anything else)
//   RELAY_PORT      port (default 8787)
// Logs are one JSON object per line on stdout.

import type { AddressInfo } from "node:net";
import { serve } from "./server.ts";
import { FsBlobStore } from "./fs-store.ts";
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

const server = await serve({ runtime: "portable", blobs: new FsBlobStore(dataDir) }, { host, port, log });
const address = server.address() as AddressInfo;
log({ event: "listening", host: address.address, port: address.port, version: VERSION, protocol: PROTOCOL });

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    log({ event: "stopping", signal });
    server.close(() => process.exit(0));
  });
}
