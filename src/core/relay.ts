// #region relay-core — docs: docs/adr/0001-relay-repository.md
// The runtime-neutral relay. Both builds route every request through `handle`: the Cloudflare Worker
// (hosted relay) and the portable server (self-hosted binary). Neither adapter adds a route.
//
// The wire protocol is fabric-agent-contract DEC-0047 (fabric-relay/0.1), pinned in fabric-contract.lock.json. A
// session opens only as a WebSocket upgrade on /v1/connect with the subprotocol fabric-relay.v1; each adapter hands the
// upgraded socket to the runtime-neutral RelaySession (session.ts), which admits a machine only from a verified estate
// record (admission.ts). `upgradeRefusal` is the one check both adapters run before upgrading.

import type { BlobStore } from "./digest.ts";
import { handleBlob, type BlobAccess } from "./blobs.ts";

export const SERVICE = "relay";
export const VERSION = "0.0.0";
export const PROTOCOL = { decision: "DEC-0047", state: "accepted", version: "fabric-relay/0.1" } as const;
export const CONNECT_PATH = "/v1/connect";
export const SUBPROTOCOL = "fabric-relay.v1";
export const BLOBS_PATH = "/v1/blobs/";

export type Runtime = "cloudflare" | "portable";

export interface RelayDeps {
  runtime: Runtime;
  blobs: BlobStore;
  /** The blob routes' admission, index and origin (RLY-03); without it /v1/blobs/ is not served. */
  blobAccess?: BlobAccess;
}

export type ErrorCode = "not-found" | "method-not-allowed" | "upgrade-required" | "protocol-unsupported" | "malformed";

export function errorResponse(status: number, code: ErrorCode, message: string): Response {
  return Response.json({ error: { code, message } }, { status, headers: { "cache-control": "no-store" } });
}

export function health(deps: RelayDeps): Response {
  return Response.json(
    {
      service: SERVICE,
      version: VERSION,
      runtime: deps.runtime,
      protocol: PROTOCOL,
      ready: true,
      degraded: [],
    },
    { headers: { "cache-control": "no-store" } },
  );
}

/**
 * Why a request to /v1/connect may not be upgraded, or null when it may: a GET with `Upgrade: websocket` that offers
 * the subprotocol fabric-relay.v1 (DEC-0047 item 3). No credential is read from the URL or a header.
 */
export function upgradeRefusal(request: Request): Response | null {
  if (request.method !== "GET") return errorResponse(405, "method-not-allowed", `${CONNECT_PATH} answers a GET upgrade`);
  if ((request.headers.get("upgrade") ?? "").toLowerCase() !== "websocket") {
    return errorResponse(426, "upgrade-required", `${CONNECT_PATH} is a WebSocket endpoint`);
  }
  const offered = (request.headers.get("sec-websocket-protocol") ?? "").split(",").map((value) => value.trim());
  if (!offered.includes(SUBPROTOCOL)) return errorResponse(400, "protocol-unsupported", `offer the subprotocol ${SUBPROTOCOL}`);
  return null;
}

export async function handle(request: Request, deps: RelayDeps): Promise<Response> {
  const { pathname } = new URL(request.url);
  if (pathname === "/healthz") {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return errorResponse(405, "method-not-allowed", "the health endpoint answers GET");
    }
    return health(deps);
  }
  if (pathname === CONNECT_PATH) {
    // Reached only by a request an adapter did not upgrade: say why it was not.
    return upgradeRefusal(request) ?? errorResponse(426, "upgrade-required", `${CONNECT_PATH} is a WebSocket endpoint`);
  }
  if (pathname.startsWith(BLOBS_PATH) && deps.blobAccess) {
    // A path that is not valid percent-encoding (`/v1/blobs/%`) is the client's error, never a fault of the relay.
    let name: string;
    try {
      name = decodeURIComponent(pathname.slice(BLOBS_PATH.length));
    } catch {
      return errorResponse(400, "malformed", "the blob path is not valid percent-encoding");
    }
    return handleBlob(request, name, deps.blobs, deps.blobAccess);
  }
  return errorResponse(404, "not-found", "no such route");
}
// #endregion relay-core
