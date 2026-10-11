// #region portable-server — docs: docs/adr/0001-relay-repository.md#two-builds
// The self-hosted relay: Node's HTTP server in front of the same runtime-neutral core the Worker uses.
// It converts each request to a web Request, and the core's Response back, and adds no route of its own.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { handle, type RelayDeps } from "../core/relay.ts";

const MAX_BODY_BYTES = 32 * 1024 * 1024;

function toRequest(message: IncomingMessage, origin: string): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(message.headers)) {
    if (Array.isArray(value)) for (const one of value) headers.append(name, one);
    else if (value !== undefined) headers.set(name, value);
  }
  const method = message.method ?? "GET";
  const hasBody = method !== "GET" && method !== "HEAD";
  return new Request(new URL(message.url ?? "/", origin), {
    method,
    headers,
    body: hasBody ? (Readable.toWeb(message) as ReadableStream<Uint8Array>) : undefined,
    // Node requires `duplex` for a streamed body; the web types do not declare it yet.
    ...(hasBody ? { duplex: "half" } : {}),
  } as RequestInit);
}

async function send(response: Response, reply: ServerResponse): Promise<void> {
  reply.statusCode = response.status;
  response.headers.forEach((value, name) => reply.setHeader(name, value));
  reply.end(Buffer.from(await response.arrayBuffer()));
}

export interface ServeOptions {
  host: string;
  port: number;
  log?: (event: Record<string, unknown>) => void;
}

export function serve(deps: RelayDeps, options: ServeOptions): Promise<Server> {
  const log = options.log ?? (() => {});
  const server = createServer(async (message, reply) => {
    const started = Date.now();
    const declared = Number(message.headers["content-length"] ?? 0);
    if (declared > MAX_BODY_BYTES) {
      reply.statusCode = 413;
      reply.setHeader("connection", "close");
      reply.setHeader("content-type", "application/json");
      reply.end(JSON.stringify({ error: { code: "too-large", message: `bodies are limited to ${MAX_BODY_BYTES} bytes` } }));
      return;
    }
    try {
      const response = await handle(toRequest(message, `http://${options.host}`), deps);
      await send(response, reply);
      log({ event: "request", method: message.method, path: new URL(message.url ?? "/", "http://x").pathname, status: response.status, ms: Date.now() - started });
    } catch (error) {
      log({ event: "request-failed", path: new URL(message.url ?? "/", "http://x").pathname, error: (error as Error).name });
      if (!reply.headersSent) {
        reply.statusCode = 500;
        reply.setHeader("content-type", "application/json");
      }
      reply.end(JSON.stringify({ error: { code: "internal", message: "the relay could not answer" } }));
    }
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, options.host, () => resolve(server));
  });
}
// #endregion portable-server
