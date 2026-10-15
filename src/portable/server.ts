// #region portable-server — docs: docs/adr/0001-relay-repository.md#two-builds
// The self-hosted relay: Node's HTTP server in front of the same runtime-neutral core the Worker uses.
// It converts each request to a web Request, and the core's Response back, and adds no route of its own.

import { randomBytes, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { Readable } from "node:stream";
import { WebSocketServer } from "ws";
import validateEstateRecord from "../contract/estate-record.validate.js";
import type { WebSocket } from "ws";
import { AdmissionHolder, loadAdmission, type EstateSource } from "../core/admission.ts";
import { CONNECT_PATH, handle, SUBPROTOCOL, upgradeRefusal, type RelayDeps } from "../core/relay.ts";
import type { MailboxStore } from "../core/mailbox.ts";
import type { BlobIndex } from "../core/blobs.ts";
import { EstateHub } from "../core/hub.ts";
import { MAX_FRAME_BYTES } from "../contract/relay.ts";
import { OriginRefused, relayOrigin } from "./origin.ts";
import type { LastSeenStore } from "../core/presence.ts";
/** A frame over 1 MiB closes the connection (1009) in the session; `ws` stops reading at a little more. */
const MAX_PAYLOAD = 1_048_576 + 1;

const MAX_BODY_BYTES = 32 * 1024 * 1024;

/** How long a refused upgrade's socket may take to flush its answer before it is destroyed anyway. */
const REFUSAL_FLUSH_MS = 1000;

/**
 * Answers an upgrade the relay refuses and lets go of the socket. An upgraded socket has left the HTTP server's books
 * (`closeAllConnections()` does not see it), so a client that keeps its side open (half-open) would otherwise hold
 * `server.close()` for ever: the socket is destroyed once the answer is flushed, or after REFUSAL_FLUSH_MS at most.
 */
function refuseUpgrade(socket: Socket, response: string): void {
  const backstop = setTimeout(() => socket.destroy(), REFUSAL_FLUSH_MS);
  backstop.unref();
  socket.once("close", () => clearTimeout(backstop));
  socket.on("error", () => socket.destroy());
  socket.end(response, () => socket.destroy());
}

/**
 * The fixed base a request target is resolved against. Only the path and query of a request matter to the core; the
 * origin machines sign is `origin`, never this. A fixed name keeps a RELAY_HOST the URL parser cannot take (a zone id)
 * out of every request.
 */
const TARGET_BASE = "http://relay.invalid";

/**
 * Outbound flow control per connection (round 6; docs/protocol/sessions.md, "Flow control").
 * - Deliveries are paced: a session's flush sends mail only while `ws.bufferedAmount` is below SEND_HIGH, and goes on
 *   when the socket drains (`hub.drained`). What is not sent yet stays in the mailbox. So deliveries alone hold at most
 *   SEND_HIGH plus one delivery frame (a body of at most 765 KiB, about 1 MiB as a frame) per session.
 * - The socket is always read: acks and pings arrive whatever the relay has queued to send.
 * - SEND_CAP is just above what deliveries can reach (SEND_HIGH plus one delivery frame), so it bounds the rest:
 *   replies (pong, accepted, error, presence) to a machine that keeps sending and never reads. A reply is small (an id
 *   or msgId the relay echoes is at most 128 code points). Both caps are checked before each write: a write that would
 *   pass one is not made, the session is closed 1008 (`send-overflow`) and its socket terminated 1 s later. So one
 *   session holds at most SEND_CAP = 3 MiB queued, one machine (8 sessions) 24 MiB.
 * - SEND_FRAMES_CAP bounds the same thing counted in frames: each queued write costs the process a few hundred bytes
 *   beyond its payload, so 3 MiB of 50-byte pongs would cost far more than 3 MiB. Past 4096 frames not yet handed to
 *   the kernel, the session is closed the same way.
 */
const SEND_HIGH = 1024 * 1024;
const SEND_CAP = SEND_HIGH + 2 * MAX_FRAME_BYTES;
const SEND_FRAMES_CAP = 4096;
/**
 * Socket heartbeat (round 10 design, docs/protocol/sessions.md "Heartbeat"): every HEARTBEAT_MS (10 s) the relay pings
 * each session's socket (a WebSocket ping, which every client library answers) and so learns which writes the peer has
 * read: a pong confirms every byte written before its ping. The heartbeat terminates a socket only when nothing is
 * outstanding to it (nothing left in the process, `bufferedAmount` 0, and at most HEARTBEAT_IDLE_SLACK bytes written
 * and not confirmed by a pong) and it has shown no life (a pong, a frame, a drain) for HEARTBEAT_DEAD_BEATS beats: a
 * peer idle on our side that stopped answering, freed within 30 to 40 s (`heartbeat-timeout`). A socket with more
 * outstanding is never terminated by the heartbeat, whatever the kernel holds in front of a ping: it is governed by the
 * session's 90 s idle close, where its frames, its drains and the relay's write progress to it count as activity.
 * Time is monotonic (`performance.now()`), and a beat that fires late does not count its lateness as silence.
 */
const HEARTBEAT_MS = 10_000;
const HEARTBEAT_DEAD_BEATS = 3;
/** Control traffic (hello, welcome, a pong, presence) may sit unconfirmed and still let an idle peer be freed. */
const HEARTBEAT_IDLE_SLACK = 4 * 1024;
/** Close code for a machine that does not read what the relay sends it: a policy violation (RFC 6455 §7.4.1). */
const CLOSE_NOT_READING = 1008;
/**
 * Inbound protection: how many frames may wait in a session before the socket is not read, and when it is read again.
 * With the real stores a frame is handled within its own turn, so this seldom trips.
 */
const IN_FLIGHT_HIGH = 64;
const IN_FLIGHT_LOW = 16;

/**
 * The request target as a URL, or undefined when the URL parser refuses it. Node's HTTP parser accepts targets the URL
 * parser does not (`//[`, `http://[/v1/connect`, `http://x:99999/`); this is the only place a target is parsed.
 */
function parseTarget(message: IncomingMessage): URL | undefined {
  try {
    return new URL(message.url ?? "/", TARGET_BASE);
  } catch {
    return undefined;
  }
}

function toRequest(message: IncomingMessage, url: URL): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(message.headers)) {
    if (Array.isArray(value)) for (const one of value) headers.append(name, one);
    else if (value !== undefined) headers.set(name, value);
  }
  const method = message.method ?? "GET";
  const hasBody = method !== "GET" && method !== "HEAD";
  return new Request(url, {
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
  /**
   * The public origin machines sign into relay-auth/1 and relay-blob/1 (behind a TLS terminator, its https:// URL).
   * Normalised or refused by `relayOrigin` (origin.ts); unset, only a loopback literal host gets the http default.
   */
  origin?: string;
  /** Where the estate the relay admits from is kept; without one the relay admits nobody. */
  estate?: EstateSource;
  /** Each blob's recipients and fetches (RLY-03); with an estate, the blob routes are served. */
  blobIndex?: BlobIndex;
  /** Where queued messages are kept (RLY-03); without one, messages are answered "not served yet". */
  mailbox?: MailboxStore & { close?(): void };
  /** When each machine was last seen (RLY-06); without one, presence is answered "not served yet". */
  lastSeen?: LastSeenStore & { close?(): void };
  /**
   * How often each session's socket is pinged (default 10 s). One with nothing outstanding to it and no life for 3 beats
   * is terminated; one with bytes outstanding is left to the session's 90 s idle close.
   */
  heartbeatMs?: number;
  /** The wall clock sessions and their deadlines read (default the system's); tests pass a fake one. */
  now?: () => Date;
  /** Tuning: the reply caps per session (defaults SEND_CAP, 3 MiB, and SEND_FRAMES_CAP, 4096 frames). */
  sendCap?: number;
  sendFramesCap?: number;
  /** At most this many sessions per machine at once (default 8, `DEFAULT_MAX_SESSIONS_PER_MACHINE`); the next is refused 1013. */
  maxSessionsPerMachine?: number;
  log?: (event: Record<string, unknown>) => void;
}

export interface Served {
  server: Server;
  /** The one origin sessions and blob routes verify against, computed after listen. */
  origin: string;
  /**
   * A graceful stop (RLY-010): new upgrades get 503 and HTTP answers `connection: close`; every session is closed 1001
   * through the estate hub, so each machine's `lastSeen` is written; a socket still open after `graceMs` is
   * terminated; then the listener and every connection close (any socket still open, an upgraded one included, is
   * destroyed and counted in `forced`), and so do the mailbox and `lastSeen` stores (closing SQLite checkpoints its
   * WAL). Logs `stopped {sessions, forced, ms}`. A second call returns the first one's promise. A refused upgrade (404,
   * 400, 503) is answered and its socket destroyed, so a client that keeps its side open never holds the stop.
   */
  stop(options?: { graceMs?: number }): Promise<{ sessions: number; forced: number }>;
  /**
   * Flow-control diagnostics: the most the relay has held queued on any one socket at once (`ws.bufferedAmount` after a
   * write). It never exceeds the send cap (3 MiB); tests read it to show what is queued, which a process's footprint
   * (allocator retention) cannot. `pingsSent` and `pingsSkipped` count heartbeat pings, and the beats that sent none
   * because the previous ping to that socket was still unwritten.
   */
  flow(): { peakBuffered: number; pingsSent: number; pingsSkipped: number };
}

/**
 * The listener could not be opened (the port is taken or not allowed, the host does not resolve or is not this
 * machine's): `main.ts` turns it into `refused-to-start` and exit 2, like a refused origin.
 */
export class ListenRefused extends Error {
  override name = "ListenRefused";
}

/**
 * Starts the portable relay. Rejects with `OriginRefused` before listening when the origin rules refuse it, and with
 * `ListenRefused` when the listen fails.
 */
export async function serve(deps: RelayDeps, options: ServeOptions): Promise<Served> {
  const rule = relayOrigin(options.origin, options.host);
  if (!rule.ok) throw new OriginRefused(rule.reason);
  deps = { ...deps };
  // Set once the server listens: the bound port is part of a defaulted origin.
  let origin = "";
  const log = options.log ?? (() => {});
  let stopping: Promise<{ sessions: number; forced: number }> | undefined;
  const server = createServer(async (message, reply) => {
    const started = Date.now();
    if (stopping) reply.setHeader("connection", "close");
    const declared = Number(message.headers["content-length"] ?? 0);
    if (declared > MAX_BODY_BYTES) {
      reply.statusCode = 413;
      reply.setHeader("connection", "close");
      reply.setHeader("content-type", "application/json");
      reply.end(JSON.stringify({ error: { code: "too-large", message: `bodies are limited to ${MAX_BODY_BYTES} bytes` } }));
      return;
    }
    // The target is parsed once, before anything else; a target or header the web Request cannot carry is the client's
    // error (400), never a fault of the relay.
    const url = parseTarget(message);
    let request: Request | undefined;
    try {
      if (url) request = toRequest(message, url);
    } catch {
      request = undefined;
    }
    if (!url || !request) {
      reply.statusCode = 400;
      reply.setHeader("connection", "close");
      reply.setHeader("content-type", "application/json");
      reply.end(JSON.stringify({ error: { code: "bad-request", message: url ? "the request cannot be read" : "the request target is not a URL" } }));
      log({ event: "request-refused", status: 400, reason: url ? "request" : "target" });
      return;
    }
    try {
      const response = await handle(request, deps);
      await send(response, reply);
      log({ event: "request", method: message.method, path: url.pathname, status: response.status, ms: Date.now() - started });
    } catch (error) {
      log({ event: "request-failed", path: url.pathname, error: (error as Error).name });
      if (!reply.headersSent) {
        reply.statusCode = 500;
        reply.setHeader("content-type", "application/json");
      }
      reply.end(JSON.stringify({ error: { code: "internal", message: "the relay could not answer" } }));
    }
  });
  // One estate hub per server (docs/adr/0002-estate-hub.md): the connection set, presence derived from it, the admission
  // every session admits from, and one timer for every session's deadline.
  const empty: EstateSource = { pinned: async () => [], revisions: async () => [] };
  let holder = new AdmissionHolder({ pinned: [], schemaValid: () => false, now: () => new Date() });
  // Upgrades whose estate read is still in flight, and upgrades refused because the stop began during that read: a stop
  // waits for both up to its grace period, then terminates what is left.
  const pending = new Set<WebSocket>();
  const refusing = new Set<WebSocket>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const wallNow = options.now ?? (() => new Date());
  const hub: EstateHub<WebSocket> = new EstateHub<WebSocket>({
    now: wallNow,
    nonce: () => randomBytes(32).toString("base64url"),
    sessionId: () => randomUUID(),
    admission: () => holder.current(),
    ...(options.mailbox ? { mailbox: options.mailbox } : {}),
    ...(options.lastSeen ? { lastSeen: options.lastSeen } : {}),
    ...(options.maxSessionsPerMachine ? { maxSessionsPerMachine: options.maxSessionsPerMachine } : {}),
    arm: (at) => {
      clearTimeout(timer);
      timer = at === undefined ? undefined : setTimeout(() => void hub.onWake(), Math.max(0, at - wallNow().getTime()));
      timer?.unref();
    },
    log,
  });
  // Every TCP connection the server accepted, upgraded ones included: what is still open once the stop's grace period
  // has ended is destroyed, so no client can hold `server.close()`.
  const connections = new Set<Socket>();
  server.on("connection", (socket: Socket) => {
    connections.add(socket);
    socket.once("close", () => connections.delete(socket));
  });
  const sendCap = options.sendCap ?? SEND_CAP;
  const flow = { peakBuffered: 0, pingsSent: 0, pingsSkipped: 0 };
  const sendFramesCap = options.sendFramesCap ?? SEND_FRAMES_CAP;
  // The heartbeat (HEARTBEAT_MS; see the constant): per socket, when it last showed life, how many data bytes the relay
  // has written to it and how many of those a pong confirmed, the data position of each ping awaiting its pong, whether
  // the last ping is still unwritten (no second ping is queued behind it), and its write position, which counts as
  // activity for the idle close.
  const beatMs = options.heartbeatMs ?? HEARTBEAT_MS;
  const deadAfterMs = beatMs * HEARTBEAT_DEAD_BEATS;
  const clock = () => performance.now();
  type Beat = {
    lastLife: number; written: number; confirmed: number; pings: number[]; pingUnwritten: boolean;
    completed: number; inFlight: number; socket: Socket;
  };
  const alive = new Map<WebSocket, Beat>();
  const position = (socket: Socket) => ({
    completed: socket.bytesWritten - socket.writableLength,
    inFlight: Number((socket as unknown as { _handle?: { writeQueueSize?: number } })._handle?.writeQueueSize ?? 0),
  });
  let lastBeat = clock();
  const heartbeat = setInterval(() => {
    const now = clock();
    // A beat that fires late (a stalled loop, a machine that slept) credits its lateness: it is not the peers' silence.
    const late = now - lastBeat - beatMs;
    lastBeat = now;
    if (late > beatMs / 2) for (const state of alive.values()) state.lastLife += late;
    for (const [ws, state] of alive) {
      const at = position(state.socket);
      if (at.completed > state.completed || (at.completed === state.completed && at.inFlight < state.inFlight)) hub.progressed(ws);
      state.completed = at.completed;
      state.inFlight = at.inFlight;
      const idle = ws.bufferedAmount === 0 && state.written - state.confirmed <= HEARTBEAT_IDLE_SLACK;
      if (idle && now - state.lastLife > deadAfterMs) {
        log({ event: "heartbeat-timeout", silentMs: Math.round(now - state.lastLife) });
        alive.delete(ws);
        ws.terminate();
        continue;
      }
      if (state.pingUnwritten) { // the last ping is not even in the kernel yet: no second one behind it
        flow.pingsSkipped += 1;
        continue;
      }
      try {
        state.pingUnwritten = true;
        state.pings.push(state.written);
        if (state.pings.length > 64) state.pings.shift();
        flow.pingsSent += 1;
        ws.ping(undefined, undefined, () => { state.pingUnwritten = false; });
      } catch {
        // a socket already closing: its close event removes it
      }
    }
    // The hub's own timer covers its deadlines; a beat also runs what is due, so a late or skipped timer costs nothing.
    const due = hub.nextWake();
    if (due !== undefined && due <= wallNow().getTime()) void hub.onWake();
  }, beatMs);
  heartbeat.unref();
  // `allowSynchronousEvents: false`: `ws` emits one message per turn of the event loop, so a machine flooding frames
  // cannot keep the loop from a signal or a timer (a SIGTERM is handled within one frame's work).
  const sockets = new WebSocketServer({
    noServer: true, maxPayload: MAX_PAYLOAD, allowSynchronousEvents: false,
    handleProtocols: (offered) => (offered.has(SUBPROTOCOL) ? SUBPROTOCOL : false),
  });
  // CONNECT (a proxy tunnel) is not a method the relay serves: answered 405 and let go of, like a refused upgrade.
  server.on("connect", (_message, socket) => {
    refuseUpgrade(socket as Socket, "HTTP/1.1 405 Method Not Allowed\r\nconnection: close\r\nallow: GET, HEAD, PUT\r\ncontent-length: 0\r\n\r\n");
    log({ event: "connect-refused", status: 405 });
  });
  server.on("upgrade", (message, socket, head) => {
    if (stopping) {
      refuseUpgrade(socket as Socket, "HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\nretry-after: 5\r\ncontent-length: 0\r\n\r\n");
      log({ event: "upgrade-refused", status: 503 });
      return;
    }
    // Parsed once, before anything else: a listener that threw here would take the process down (uncaught).
    const url = parseTarget(message);
    let request: Request | undefined;
    try {
      if (url) request = toRequest(message, url);
    } catch {
      request = undefined;
    }
    if (!url || !request) {
      refuseUpgrade(socket as Socket, "HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
      log({ event: "upgrade-refused", status: 400, reason: url ? "request" : "target" });
      return;
    }
    const refusal = url.pathname === CONNECT_PATH ? upgradeRefusal(request) : new Response(null, { status: 404 });
    if (refusal) {
      refuseUpgrade(socket as Socket, `HTTP/1.1 ${refusal.status} ${refusal.status === 404 ? "Not Found" : "Refused"}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n`);
      log({ event: "upgrade-refused", status: refusal.status });
      return;
    }
    sockets.handleUpgrade(message, socket, head, async (ws) => {
      // Watched from the start: a socket that closes while its estate is read never joins the hub.
      pending.add(ws);
      let gone = false;
      ws.once("close", () => {
        gone = true;
        pending.delete(ws);
        refusing.delete(ws);
      });
      ws.on("error", (error) => log({ event: "socket-error", error: error.name }));
      // The estate is read again when a connection opens, and what verifies is what every session of the hub admits from.
      // A read that fails is logged and the hub keeps what it held; it never takes the relay down.
      try {
        const loaded = await loadAdmission(options.estate ?? empty, (record) => validateEstateRecord(record), () => new Date());
        if (loaded.refused.length > 0) log({ event: "estate-revision-refused", refused: loaded.refused });
        // A read never rolls open sessions back to an older revision than the one the hub holds.
        const held = Number(holder.revision?.revision ?? 0), read = Number(loaded.holder.revision?.revision ?? 0);
        if (read >= held) holder = loaded.holder;
        else log({ event: "estate-rollback-refused", held, read });
      } catch (error) {
        log({ event: "estate-unreadable", error: (error as Error)?.name ?? "Error", message: String((error as Error)?.message ?? error).slice(0, 200) });
      } finally {
        pending.delete(ws);
      }
      if (gone) return;
      if (stopping) {
        // The stop began while the estate was read: this socket is refused, and terminated at the grace period if it
        // has not closed by then.
        refusing.add(ws);
        ws.close(1001, "relay stopping");
        return;
      }
      // Flow control (SEND_HIGH, SEND_CAP, IN_FLIGHT_*; see the constants): deliveries paced by the send buffer and
      // resumed on drain, the socket always read, replies to a machine that never reads capped.
      let inFlight = 0;
      let overflowed = false;
      let unsent = 0; // frames handed to ws and not yet to the kernel
      let terminate: ReturnType<typeof setTimeout> | undefined;
      const lively = () => { const state = alive.get(ws); if (state) state.lastLife = clock(); };
      alive.set(ws, { lastLife: clock(), written: 0, confirmed: 0, pings: [], pingUnwritten: false, ...position(socket as Socket), socket: socket as Socket });
      ws.on("pong", () => {
        lively();
        const state = alive.get(ws);
        const confirmed = state?.pings.shift();
        if (state && confirmed !== undefined && confirmed > state.confirmed) state.confirmed = confirmed;
      });
      (socket as Socket).on("drain", () => {
        lively();
        void hub.drained(ws);
      });
      ws.on("message", (data, isBinary) => {
        lively();
        inFlight += 1;
        if (inFlight >= IN_FLIGHT_HIGH && !ws.isPaused) ws.pause();
        void hub.receive(ws, isBinary ? new Uint8Array(data as Buffer) : (data as Buffer).toString("utf8")).finally(() => {
          inFlight -= 1;
          if (inFlight <= IN_FLIGHT_LOW && ws.isPaused) ws.resume();
        });
      });
      ws.on("close", () => {
        clearTimeout(terminate);
        alive.delete(ws);
        hub.closed(ws);
      });
      hub.connect(ws, {
        send: (text) => {
          if (overflowed) return;
          // Checked before the write, so the queue never passes either cap: a session holds at most sendCap bytes.
          const queued = ws.bufferedAmount;
          const size = Buffer.byteLength(text);
          if (queued + size <= sendCap && unsent + 1 <= sendFramesCap) {
            unsent += 1;
            const state = alive.get(ws);
            if (state) state.written += size;
            ws.send(text, () => { unsent -= 1; });
            if (ws.bufferedAmount > flow.peakBuffered) flow.peakBuffered = ws.bufferedAmount;
            return;
          }
          overflowed = true;
          log({ event: "send-overflow", bufferedAmount: queued, frame: size, cap: sendCap, frames: unsent, framesCap: sendFramesCap });
          // Its session ends through its own close (lastSeen is written); the close frame cannot pass a socket that is not
          // read, so the socket is terminated shortly after unless it closes first.
          hub.session(ws)?.close(CLOSE_NOT_READING, "not reading what the relay sends");
          terminate = setTimeout(() => ws.terminate(), 1000);
          terminate.unref();
        },
        backlogged: () => ws.bufferedAmount >= SEND_HIGH,
        close: (code, reason) => ws.close(code, reason),
      }, origin);
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", (error: NodeJS.ErrnoException) => {
      sockets.close();
      clearInterval(heartbeat);
      reject(new ListenRefused(`cannot listen on ${options.host} port ${options.port}: ${error.code ?? error.name} ${String(error.message).slice(0, 200)}`));
    });
    server.listen(options.port, options.host, () => resolve());
  });
  origin = rule.at((server.address() as AddressInfo).port);
  if (rule.defaulted) log({ event: "origin-defaulted", origin, reason: "RELAY_ORIGIN is not set: only a local machine can authenticate" });
  // With an estate, the blob routes are served too, against the same origin as sessions: the same admission, read when
  // each request comes.
  if (options.estate && options.blobIndex && !deps.blobAccess) {
    const estate = options.estate;
    deps.blobAccess = {
      origin,
      index: options.blobIndex,
      admission: async () => (await loadAdmission(estate, (record) => validateEstateRecord(record), () => new Date())).holder.current(),
    };
  }
  const stop = async ({ graceMs = 5000 }: { graceMs?: number } = {}) => {
    const started = Date.now();
    const result = await hub.stop({ code: 1001, reason: "relay stopping", graceMs });
    // Upgrades still reading the estate, and those refused because the stop began meanwhile, get what is left of the
    // grace period, then are terminated with the rest.
    const left = graceMs - (Date.now() - started);
    if (pending.size + refusing.size > 0 && left > 0) {
      await new Promise<void>((resolve) => {
        const check = setInterval(() => { if (pending.size + refusing.size === 0) { clearInterval(check); clearTimeout(limit); resolve(); } }, 20);
        const limit = setTimeout(() => { clearInterval(check); resolve(); }, left);
      });
    }
    const unclosed = [...new Set([...result.unclosed, ...pending, ...refusing])];
    for (const ws of unclosed) ws.terminate();
    clearTimeout(timer);
    clearInterval(heartbeat);
    let lingering = 0;
    await new Promise<void>((resolve) => {
      sockets.close();
      server.close(() => resolve());
      server.closeAllConnections();
      // The grace period is over: a connection the HTTP server no longer tracks (an upgraded socket nobody closed) is
      // destroyed here rather than waited for.
      for (const socket of connections) {
        if (socket.destroyed) continue;
        lingering += 1;
        socket.destroy();
      }
    });
    if (lingering > 0) log({ event: "stop-destroyed", connections: lingering });
    for (const store of [options.mailbox, options.lastSeen]) {
      try {
        store?.close?.();
      } catch (error) {
        log({ event: "store-close-fault", error: (error as Error).name });
      }
    }
    const outcome = { sessions: result.sessions, forced: unclosed.length + lingering };
    log({ event: "stopped", ...outcome, ms: Date.now() - started });
    return outcome;
  };
  return { server, origin, stop: (stopOptions) => (stopping ??= stop(stopOptions)), flow: () => ({ ...flow }) };
}
// #endregion portable-server
