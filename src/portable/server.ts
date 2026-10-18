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
 * Socket heartbeat (round 13 design, docs/protocol/sessions.md "Heartbeat"). One rule decides what counts: **progress is
 * only what the peer confirms** — a frame it sends, or a pong whose 8-byte payload matches a ping the relay sent (a pong
 * confirms every byte written before its ping). A write the relay makes is never progress, whether or not the kernel
 * took it; nor is a drain, nor an unsolicited or unknown pong, nor a WebSocket ping the peer sends (answered, never
 * counted).
 * - Every HEARTBEAT_MS (10 s) each session's socket gets a ping with a random 8-byte payload, unless an earlier one is
 *   still unwritten or HEARTBEAT_MAX_PINGS are awaiting their pongs. A frame of HEARTBEAT_MARK_BYTES or more (a
 *   delivery) is also followed by a marker ping, so a slow reader confirms each delivery as soon as it has read it.
 * - The heartbeat terminates a socket only when nothing is outstanding to it (`bufferedAmount` 0 and at most
 *   HEARTBEAT_IDLE_SLACK bytes unconfirmed) and it has shown no life (a matched pong or a frame) for HEARTBEAT_DEAD_BEATS
 *   beats: a peer idle on our side that stopped answering, freed within 30 to 40 s (`heartbeat-timeout`).
 * - A socket with more outstanding is left to the session's idle close (5 minutes while bytes are outstanding, 90 s
 *   otherwise), where its frames and the matched pongs that confirm new bytes count as activity.
 * - Time is monotonic (`performance.now()`), and a beat that fires late does not count its lateness as silence.
 */
const HEARTBEAT_MS = 10_000;
const HEARTBEAT_DEAD_BEATS = 3;
/** Control traffic (hello, welcome, a pong, presence) may sit unconfirmed and still let an idle peer be freed. */
const HEARTBEAT_IDLE_SLACK = 4 * 1024;
/** The most heartbeat pings awaiting their pongs on one socket: past it the relay stops pinging until a pong returns. */
const HEARTBEAT_MAX_PINGS = 64;
/** A frame this large (a delivery) gets a marker ping right behind it (see `send`). */
const HEARTBEAT_MARK_BYTES = 64 * 1024;
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
  /** The idle limit while bytes are outstanding to a machine (default 5 minutes, IDLE_OUTSTANDING_MS). */
  idleOutstandingMs?: number;
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
   * (the previous ping to that socket still unwritten, or 64 awaiting pongs); `marks`, the marker pings sent behind
   * large frames. `received` counts frames read from every socket; `pausedForInFlight` is how many sockets the relay
   * has paused for in-flight frames right now, and `socketsPaused` how many sockets are not being read right now,
   * whoever paused them, and `sockets` each socket's byte counts and read state: together they say whether a socket
   * stopped being read.
   */
  flow(): { peakBuffered: number; pingsSent: number; pingsSkipped: number; marks: number; received: number; pausedForInFlight: number; socketsPaused: number; sockets: Array<Record<string, unknown>> };
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
    // A blob PUT's length is checked by handleBlob, after the request's own header (DEC-0066's order of checks, step 5):
    // an over-long PUT with a malformed header is 400, not 413. Every other body is refused here before it is read.
    const blobPath = (message.url ?? "").startsWith("/v1/blobs/");
    if (declared > MAX_BODY_BYTES && !blobPath) {
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
      // A refused PUT may leave its body unread or half read (a 413 stops reading): the connection is not reused.
      if (request.method === "PUT" && response.status >= 400) reply.setHeader("connection", "close");
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
    ...(options.idleOutstandingMs !== undefined ? { idleOutstandingMs: options.idleOutstandingMs } : {}),
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
  const flow = { peakBuffered: 0, pingsSent: 0, pingsSkipped: 0, marks: 0, received: 0 };
  const pausedForInFlight = new Set<WebSocket>();
  const sendFramesCap = options.sendFramesCap ?? SEND_FRAMES_CAP;
  // The heartbeat (HEARTBEAT_MS; see the constant): per socket, when it last showed life (a matched pong or a frame),
  // how many data bytes the relay has written to it and how many a matched pong confirmed, the pings awaiting their pongs
  // (random payload and the data position they confirm, in order), and how many are still unwritten.
  const beatMs = options.heartbeatMs ?? HEARTBEAT_MS;
  const deadAfterMs = beatMs * HEARTBEAT_DEAD_BEATS;
  const clock = () => performance.now();
  type Beat = { lastLife: number; written: number; confirmed: number; pings: Array<{ token: string; at: number }>; unwritten: number };
  const alive = new Map<WebSocket, Beat>();
  // A ping marks a position in the stream: every data byte written before it. Its 8-byte payload is random, so a peer
  // cannot answer a ping it has not read. `unwritten` counts pings handed to ws and not yet to the kernel.
  const sendPing = (ws: WebSocket, state: Beat) => {
    try {
      const payload = randomBytes(8);
      state.unwritten += 1;
      state.pings.push({ token: payload.toString("hex"), at: state.written });
      ws.ping(payload, undefined, () => { state.unwritten -= 1; });
    } catch {
      // a socket already closing: its close event removes it
    }
  };
  let lastBeat = clock();
  const heartbeat = setInterval(() => {
    const now = clock();
    // A beat that fires late (a stalled loop, a machine that slept) credits its lateness: it is not the peers' silence.
    const late = now - lastBeat - beatMs;
    lastBeat = now;
    if (late > beatMs / 2) for (const state of alive.values()) state.lastLife = Math.min(now, state.lastLife + late);
    for (const [ws, state] of alive) {
      const idle = ws.bufferedAmount === 0 && state.written - state.confirmed <= HEARTBEAT_IDLE_SLACK;
      if (idle && now - state.lastLife > deadAfterMs) {
        log({ event: "heartbeat-timeout", silentMs: Math.round(now - state.lastLife) });
        alive.delete(ws);
        ws.terminate();
        continue;
      }
      // No second ping behind an unwritten one, and none past HEARTBEAT_MAX_PINGS awaiting their pongs.
      if (state.unwritten > 0 || state.pings.length >= HEARTBEAT_MAX_PINGS) {
        flow.pingsSkipped += 1;
        continue;
      }
      flow.pingsSent += 1;
      sendPing(ws, state);
    }
    // The hub's own timer covers its deadlines; a beat also runs what is due, so a late or skipped timer costs nothing.
    const due = hub.nextWake();
    if (due !== undefined && due <= wallNow().getTime()) void hub.onWake();
  }, beatMs);
  heartbeat.unref();
  // `allowSynchronousEvents: false`: `ws` emits one message per turn of the event loop, so a machine flooding frames
  // cannot keep the loop from a signal or a timer (a SIGTERM is handled within one frame's work).
  // `autoPong: false`: the relay answers a peer's WebSocket ping itself, under the same send caps as every other frame,
  // so a peer that floods pings and never reads cannot queue pongs past them.
  const sockets = new WebSocketServer({
    noServer: true, maxPayload: MAX_PAYLOAD, allowSynchronousEvents: false, autoPong: false,
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
      alive.set(ws, { lastLife: clock(), written: 0, confirmed: 0, pings: [], unwritten: 0 });
      // A pong counts only when its payload is that of a ping the relay sent and still awaits. The payload is random, so
      // the peer cannot answer a ping it has not read: it has read every byte written before that ping. Pongs come back in order, so earlier pings are settled too.
      // An unsolicited or unknown pong is ignored.
      ws.on("pong", (data: Buffer) => {
        const state = alive.get(ws);
        if (!state || data.length !== 8) return;
        const token = data.toString("hex");
        const index = state.pings.findIndex((ping) => ping.token === token);
        if (index < 0) return;
        const confirmed = state.pings[index]!.at;
        state.pings.splice(0, index + 1);
        state.lastLife = clock();
        if (confirmed > state.confirmed) {
          state.confirmed = confirmed;
          hub.progressed(ws); // new bytes confirmed read: activity for the idle close
        }
      });
      // A peer's WebSocket ping is answered under the send caps, and is not activity: a session stays open by its frames.
      ws.on("ping", (data: Buffer) => {
        note(); // what is queued now, before this pong: shows anything answered outside the caps
        if (!admit(data.length + 2)) return;
        ws.pong(data, undefined, () => { unsent -= 1; });
        note();
      });
      // A drain means the kernel took what the relay wrote: never the peer's progress, only room to deliver more.
      (socket as Socket).on("drain", () => void hub.drained(ws));
      ws.on("message", (data, isBinary) => {
        lively();
        flow.received += 1;
        inFlight += 1;
        if (inFlight >= IN_FLIGHT_HIGH && !ws.isPaused) { ws.pause(); pausedForInFlight.add(ws); }
        void hub.receive(ws, isBinary ? new Uint8Array(data as Buffer) : (data as Buffer).toString("utf8")).finally(() => {
          inFlight -= 1;
          if (inFlight <= IN_FLIGHT_LOW && ws.isPaused) { ws.resume(); pausedForInFlight.delete(ws); }
        });
      });
      ws.on("close", () => {
        pausedForInFlight.delete(ws);
        clearTimeout(terminate);
        alive.delete(ws);
        hub.closed(ws);
      });
      // Every frame the relay queues for this peer (a session's frame, a pong to its ping) passes the caps first: a write
      // that would take the queue past either is not made, and the session is closed 1008 (`send-overflow`).
      function admit(size: number): boolean {
        if (overflowed) return false;
        const queued = ws.bufferedAmount;
        if (queued + size <= sendCap && unsent + 1 <= sendFramesCap) {
          unsent += 1;
          return true;
        }
        overflowed = true;
        log({ event: "send-overflow", bufferedAmount: queued, frame: size, cap: sendCap, frames: unsent, framesCap: sendFramesCap });
        // Its session ends through its own close (lastSeen is written); the close frame cannot pass a socket that is not
        // read, so the socket is terminated shortly after unless it closes first.
        const session = hub.session(ws);
        if (session) session.close(CLOSE_NOT_READING, "not reading what the relay sends");
        else ws.close(CLOSE_NOT_READING, "not reading what the relay sends");
        terminate = setTimeout(() => ws.terminate(), 1000);
        terminate.unref();
        return false;
      }
      const note = () => { if (ws.bufferedAmount > flow.peakBuffered) flow.peakBuffered = ws.bufferedAmount; };
      hub.connect(ws, {
        send: (text) => {
          const size = Buffer.byteLength(text);
          if (!admit(size)) return;
          const state = alive.get(ws);
          if (state) state.written += size;
          ws.send(text, () => { unsent -= 1; });
          note();
          // A large frame (a delivery) is followed by a marker ping, so the reader confirms it as soon as it has read it,
          // however many frames the relay wrote at once: confirmations come at the grain of one frame, never coarser.
          if (state && size >= HEARTBEAT_MARK_BYTES && state.pings.length < HEARTBEAT_MAX_PINGS) {
            flow.marks += 1;
            sendPing(ws, state);
          }
        },
        backlogged: () => ws.bufferedAmount >= SEND_HIGH,
        outstanding: () => {
          const state = alive.get(ws);
          return ws.bufferedAmount > 0 || (state !== undefined && state.written - state.confirmed > HEARTBEAT_IDLE_SLACK);
        },
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
  return { server, origin, stop: (stopOptions) => (stopping ??= stop(stopOptions)), flow: () => ({
    ...flow, pausedForInFlight: pausedForInFlight.size,
    socketsPaused: [...sockets.clients].filter((ws) => (ws as unknown as { _socket?: Socket })._socket?.isPaused?.()).length,
    sockets: [...sockets.clients].map((ws) => {
      const socket = (ws as unknown as { _socket?: Socket & { _handle?: { reading?: boolean } } })._socket;
      return { readyState: ws.readyState, bytesRead: socket?.bytesRead, bytesWritten: socket?.bytesWritten, writableLength: socket?.writableLength,
        readableFlowing: socket?.readableFlowing, readableLength: socket?.readableLength, reading: socket?._handle?.reading, destroyed: socket?.destroyed };
    }),
  }) };
}
// #endregion portable-server
