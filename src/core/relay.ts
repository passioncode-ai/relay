// #region relay-core — docs: docs/adr/0001-relay-repository.md
// The runtime-neutral relay. Both builds route every request through `handle`: the Cloudflare Worker
// (hosted relay) and the portable server (self-hosted binary). Neither adapter adds a route.
//
// The wire protocol is fabric-agent-contract DEC-0047, still a draft. Until it is accepted the relay
// serves only its health and refuses every session with `protocol-not-ready`: an endpoint that accepted
// connections before machines can prove themselves would be an open relay.

import type { BlobStore } from "./digest.ts";

export const SERVICE = "relay";
export const VERSION = "0.0.0";
export const PROTOCOL = { decision: "DEC-0047", state: "draft" } as const;

export type Runtime = "cloudflare" | "portable";

export interface RelayDeps {
  runtime: Runtime;
  blobs: BlobStore;
}

export type ErrorCode = "not-found" | "method-not-allowed" | "protocol-not-ready";

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
      ready: false,
      degraded: [`protocol:${PROTOCOL.state}`],
    },
    { headers: { "cache-control": "no-store" } },
  );
}

export async function handle(request: Request, deps: RelayDeps): Promise<Response> {
  const { pathname } = new URL(request.url);
  if (pathname === "/healthz") {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return errorResponse(405, "method-not-allowed", "the health endpoint answers GET");
    }
    return health(deps);
  }
  if (pathname === "/v0/connect") {
    return errorResponse(
      501,
      "protocol-not-ready",
      `sessions open once ${PROTOCOL.decision} is accepted; the relay refuses every connection until then`,
    );
  }
  return errorResponse(404, "not-found", "no such route");
}
// #endregion relay-core
