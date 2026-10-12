// #region portable-server — docs: docs/adr/0001-relay-repository.md#two-builds
// The self-hosted relay: Node's HTTP server in front of the same runtime-neutral core the Worker uses.
// It converts each request to a web Request, and the core's Response back, and adds no route of its own.

import { randomBytes, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { WebSocketServer } from "ws";
import validateEstateRecord from "../contract/estate-record.validate.js";
import { loadAdmission, type EstateSource } from "../core/admission.ts";
import { CONNECT_PATH, handle, SUBPROTOCOL, upgradeRefusal, type RelayDeps } from "../core/relay.ts";
import { RelaySession } from "../core/session.ts";

/** How often a session checks its 10 s auth deadline and its 90 s idle close. */
const TICK_MS = 1000;
/** A frame over 1 MiB closes the connection (1009) in the session; `ws` stops reading at a little more. */
const MAX_PAYLOAD = 1_048_576 + 1;

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
  /** The public origin machines sign into relay-auth/1 (behind a TLS terminator, its https:// URL). */
  origin?: string;
  /** Where the estate the relay admits from is kept; without one the relay admits nobody. */
  estate?: EstateSource;
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
  const sockets = new WebSocketServer({ noServer: true, maxPayload: MAX_PAYLOAD, handleProtocols: (offered) => (offered.has(SUBPROTOCOL) ? SUBPROTOCOL : false) });
  server.on("upgrade", (message, socket, head) => {
    const request = toRequest(message, `http://${options.host}`);
    const refusal = new URL(request.url).pathname === CONNECT_PATH ? upgradeRefusal(request) : new Response(null, { status: 404 });
    if (refusal) {
      socket.end(`HTTP/1.1 ${refusal.status} ${refusal.status === 404 ? "Not Found" : "Refused"}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n`);
      log({ event: "upgrade-refused", status: refusal.status });
      return;
    }
    sockets.handleUpgrade(message, socket, head, async (ws) => {
      const empty = { pinned: async () => [], revisions: async () => [] };
      const { holder, refused } = await loadAdmission(options.estate ?? empty, (record) => validateEstateRecord(record), () => new Date());
      if (refused.length > 0) log({ event: "estate-revision-refused", refused });
      let timer: ReturnType<typeof setInterval> | undefined;
      const session = new RelaySession(
        {
          send: (text) => ws.send(text),
          close: (code, reason) => {
            if (timer) clearInterval(timer);
            ws.close(code, reason);
          },
        },
        {
          relay: options.origin ?? `http://${options.host}:${(server.address() as { port: number }).port}`,
          now: () => new Date(),
          nonce: () => randomBytes(32).toString("base64url"),
          sessionId: () => randomUUID(),
          admission: () => holder.current(),
          log,
        },
      );
      ws.on("message", (data, isBinary) => session.receive(isBinary ? new Uint8Array(data as Buffer) : (data as Buffer).toString("utf8")));
      ws.on("close", () => {
        if (timer) clearInterval(timer);
      });
      ws.on("error", (error) => log({ event: "socket-error", error: error.name }));
      session.open();
      timer = setInterval(() => session.tick(), TICK_MS);
    });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, options.host, () => resolve(server));
  });
}
// #endregion portable-server
