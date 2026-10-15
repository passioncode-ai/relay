// #region relay-session — docs: docs/protocol/sessions.md
// One relay connection, the same in both builds (the Worker's Durable Object and the portable server): `hello` with a
// fresh nonce, the machine's `auth` within 10 s checked by the contract's `admit` against the admission set, then
// `welcome` and the session's own frames. Every check of a signature or a key is the contract's (src/contract/); this
// module only sequences them and keeps the transport rules of DEC-0047 item 3.
//
// What it serves after `welcome`: `ping` → `pong`; with a mailbox, `send` → `accepted`, `deliver` to every connection the
// recipient holds, and `ack` (RLY-03); in an estate hub that keeps `lastSeen`, `presence` to the estate's other machines
// and `presence-query` (RLY-06). Blobs are HTTP routes, not frames. Deltas are RLY-07 and are answered `error`
// `internal` "not served yet" rather than dropped.
//
// A session's whole state is a `SessionRecord` (docs/adr/0002-estate-hub.md): the session hands it to `SessionIo.persist`
// after every change, and `RelaySession.restore` continues from it, so a runtime may drop the object between events (the
// Worker's WebSocket Hibernation) without the session noticing. Any per-session state a later change adds goes into the
// record, never into a map keyed by connection. Deadlines are not timers here: `nextDeadline()` says when the session
// next needs `tick()`, and the hub runs one timer for all of them.

import type { AdmissionResult } from "../contract/relay.ts";
import { relayRules } from "../contract/relay-rules.ts";
import { MAX_BODY_BYTES } from "../contract/relay.ts";
import { errorFields } from "./log.ts";
import type { MailboxStore } from "./mailbox.ts";
import { TOUCH_INTERVAL_SECONDS, type PresenceRecord } from "./presence.ts";
import {
  AUTH_DEADLINE_SECONDS, CLOSE_CODES, FRAME_TYPES, IDLE_CLOSE_SECONDS, MAX_FRAME_BYTES, RELAY_PROTOCOL, admit,
  type AuthFrame, type RelayErrorCode,
} from "../contract/relay.ts";

/** What the transport gives a session: send a text frame, close with a code, and keep the session's record. */
export interface SessionIo {
  send(text: string): void;
  /**
   * Whether the transport already holds as much as it should for this connection (the portable build: `ws`'s
   * `bufferedAmount` at or past its high-water mark). While it does, a flush sends no more deliveries; the transport
   * calls the hub's `drained(conn)` when it can take more, and the flush goes on from the mailbox. A transport without
   * a backlog signal (the Worker's hibernatable socket has none) omits it, and a flush sends every page at once.
   */
  backlogged?(): boolean;
  close(code: number, reason: string): void;
  /** Called with the session's record after every change (the Worker: `serializeAttachment`); optional. */
  persist?(record: SessionRecord): void;
}

/**
 * What a session asks of the estate hub it lives in (src/core/hub.ts). The hub, in turn, calls the session's
 * `presence`, `wake`, `tick`, `close` and `fault`.
 */
export interface SessionHub {
  /** The session was admitted. It is in the hub's set before its first delivery, so no queued message is missed. */
  joined(session: RelaySession): void;
  /** An admitted session ended. */
  left(session: RelaySession): void;
  /** A message was queued for `kid`. */
  queued(kid: string): void;
  /** Whether `kid` may hold one more admitted session (the hub's `maxSessionsPerMachine`); absent means always. */
  hasRoom?(kid: string): boolean;
  /** Presence (RLY-06), when the hub keeps `lastSeen`; without it presence frames are answered "not served yet". */
  presence?: {
    touch(kid: string, at: Date): void | Promise<void>;
    query(kids: readonly string[]): PresenceRecord[] | Promise<PresenceRecord[]>;
  };
}

/**
 * A session's whole state, serializable (a WebSocket attachment holds 16 KiB; a record is well under 1 KiB). `relay` is
 * the origin this connection's `hello` named, so a restored session checks `auth` against the same one.
 */
export interface SessionRecord {
  v: 1;
  phase: SessionState;
  kid?: string;
  relay: string;
  nonce: string;
  nonceUsed: boolean;
  openedAt: number;
  lastFrameAt: number;
  outbound: number;
  delivered: number;
  connection: string;
  lastTouch: number;
  revision?: number;
}

export interface SessionEnv {
  relay: string; // this relay's origin, signed into every relay-auth/1
  now: () => Date;
  nonce: () => string; // 32 random bytes, base64url
  sessionId: () => string;
  admission: () => AdmissionResult;
  /** The store of store-and-forward (RLY-03); without it messages are answered "not served yet". */
  mailbox?: MailboxStore;
  /** The estate hub this session lives in: delivery wake-ups and presence. */
  hub?: SessionHub;
  log?: (event: Record<string, unknown>) => void;
}

export type SessionState = "awaiting-auth" | "admitted" | "closed";

/**
 * Until RLY-07 carries DEC-0054's revocation delta, a relay has carried none: the head is sequence 0 over no bytes. It has
 * the check-in's `records.revocationDelta` shape, so a node can report it unchanged.
 */
export const EMPTY_DELTA_HEAD = { sequence: 0, sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" } as const;

const SERVED = ["hello", "auth", "welcome", "ping", "pong", "error"];
/**
 * How many mailbox entries a flush reads at a time. Where the transport reports a backlog (the portable build) a page
 * is small, so a session holds little more than it can send: 4. Where it cannot (the Worker's hibernatable socket), a
 * flush sends every page at once and each page is a call to the mailbox object, so a page is large: a 1000-message
 * backlog is 16 calls, well inside a Worker's subrequest limit (F-8 revisits it with the hosted limits).
 */
export const FLUSH_PAGE = 4;
export const FLUSH_PAGE_UNPACED = 64;
/**
 * The longest frame `id` and `msgId` (the relay-frame schema's maxLength, counted in code points as JSON Schema counts
 * them): a longer one is refused and never echoed, so nothing the relay sends back is larger than a frame it would send
 * itself, and no `deliver` can exceed MAX_FRAME_BYTES.
 */
export const MAX_ID_LENGTH = 128;
/** A string's length in code points, as JSON Schema's maxLength counts it (an emoji is one, not two UTF-16 units). */
const codePoints = (text: string) => { let n = 0; for (const _ of text) n += 1; return n; };
const BASE64URL = /^[A-Za-z0-9_-]+$/;
/** Close code for a session refused because its machine holds as many as it may: "try again later" (RFC 6455 §7.4.1). */
export const CLOSE_TRY_AGAIN_LATER = 1013;
const MAIL = ["send", "ack"];
/** The most kids one `presence-query` may name, and the longest kid (the relay-frame schema's limits). */
const MAX_QUERY_KIDS = 256;
const MAX_KID_LENGTH = 256;
/**
 * Whether `text` takes more than `limit` bytes as UTF-8, counted without encoding it: a frame near 1 MiB is not copied
 * just to be measured.
 */
function utf8Exceeds(text: string, limit: number): boolean {
  if (text.length > limit) return true; // every UTF-16 unit is at least one byte
  if (text.length * 3 <= limit) return false; // and at most three
  let bytes = 0;
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < text.length && (text.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      bytes += 4;
      i += 1;
    } else bytes += 3;
    if (bytes > limit) return true;
  }
  return false;
}
/** The decoded length of a base64url string, without decoding it (the core uses web-standard APIs only). */
const base64urlLength = (text: string) => Math.floor(text.replace(/=+$/, "").length * 3 / 4);
const isFrame = (value: unknown): value is { v: unknown; type: unknown; id: unknown } & Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

export class RelaySession {
  state: SessionState = "awaiting-auth";
  kid: string | undefined;
  private nonce = "";
  private nonceUsed = false;
  private openedAt = 0;
  private lastFrameAt = 0;
  private outbound = 0;
  private delivered = 0; // the highest seq this connection has been sent
  private connection = ""; // this connection's session id, as `welcome` names it
  private lastTouch = 0;
  private revision: number | undefined; // the estate revision this session was admitted at
  private relay: string;
  // In memory only: a runtime hibernates only while no event is in flight, so neither can hold anything then.
  private queue: Promise<void> = Promise.resolve();
  private flushing: Promise<void> | undefined;
  private again = false;

  constructor(private readonly io: SessionIo, private readonly env: SessionEnv) {
    this.relay = env.relay;
  }

  /** A session continued from its record: nothing is sent, and the hub is not told it joined (it never left). */
  static restore(io: SessionIo, env: SessionEnv, record: SessionRecord): RelaySession {
    if (record?.v !== 1) throw new TypeError("not a v1 session record");
    const session = new RelaySession(io, { ...env, relay: record.relay });
    session.state = record.phase;
    session.kid = record.kid;
    session.nonce = record.nonce;
    session.nonceUsed = record.nonceUsed;
    session.openedAt = record.openedAt;
    session.lastFrameAt = record.lastFrameAt;
    session.outbound = record.outbound;
    session.delivered = record.delivered;
    session.connection = record.connection;
    session.lastTouch = record.lastTouch;
    session.revision = record.revision;
    return session;
  }

  /** The session's whole state, as `restore` takes it. */
  snapshot(): SessionRecord {
    return {
      v: 1, phase: this.state, ...(this.kid !== undefined ? { kid: this.kid } : {}), relay: this.relay, nonce: this.nonce,
      nonceUsed: this.nonceUsed, openedAt: this.openedAt, lastFrameAt: this.lastFrameAt, outbound: this.outbound,
      delivered: this.delivered, connection: this.connection, lastTouch: this.lastTouch,
      ...(this.revision !== undefined ? { revision: this.revision } : {}),
    };
  }

  private changed(): void {
    this.io.persist?.(this.snapshot());
  }

  /** The connection is open: greet with this connection's nonce. */
  open(): void {
    this.nonce = this.env.nonce();
    this.openedAt = this.lastFrameAt = this.env.now().getTime();
    this.send({ type: "hello", protocol: RELAY_PROTOCOL, relay: this.relay, nonce: this.nonce, time: this.env.now().toISOString() });
  }

  /**
   * The first instant (epoch ms) at which `tick()` has something to do: past the 10 s auth deadline while awaiting
   * `auth`, past 90 s of silence once admitted (silence: no frame from the machine and no outbound progress, see
   * `progressed`); undefined once closed.
   */
  nextDeadline(): number | undefined {
    if (this.state === "closed") return undefined;
    if (this.state === "awaiting-auth") return this.openedAt + AUTH_DEADLINE_SECONDS * 1000 + 1;
    return this.lastFrameAt + IDLE_CLOSE_SECONDS * 1000 + 1;
  }

  /**
   * One frame from the machine. Frames are handled one after another, in arrival order; the promise settles when this
   * one is. A binary frame or one over 1 MiB closes the connection; text is a JSON frame.
   */
  receive(data: string | Uint8Array | ArrayBuffer): Promise<void> {
    const next = this.queue.then(() => this.handle(data)).finally(() => this.changed());
    this.queue = next.catch(() => undefined);
    return next;
  }

  private async handle(data: string | Uint8Array | ArrayBuffer): Promise<void> {
    if (this.state === "closed") return;
    if (typeof data !== "string") return this.close(CLOSE_CODES.binary, "binary frames are not part of fabric-relay/0.1");
    this.lastFrameAt = this.env.now().getTime();
    if (utf8Exceeds(data, MAX_FRAME_BYTES)) {
      this.error("too-large", `frames are at most ${MAX_FRAME_BYTES} bytes`);
      return this.close(CLOSE_CODES.tooLarge, "frame too large");
    }
    let frame: unknown;
    try {
      frame = JSON.parse(data);
    } catch {
      frame = undefined;
    }
    // An id the relay would echo (a pong's id, an error's replyTo) is held to the schema's length, so a reply is never
    // larger than a frame the relay itself would send.
    if (!isFrame(frame) || frame.v !== 1 || typeof frame.type !== "string" || typeof frame.id !== "string"
      || frame.id.length < 1 || codePoints(frame.id) > MAX_ID_LENGTH) {
      if (this.state === "awaiting-auth") return this.refuse("unauthenticated", "the first frame is a fabric-relay/0.1 auth frame");
      return this.error("unknown-type", "not a fabric-relay/0.1 frame");
    }
    if (frame.type === "auth") return this.authenticate(frame as unknown as AuthFrame);
    if (this.state === "awaiting-auth") return this.refuse("unauthenticated", "authenticate before any other frame");
    await this.touch();
    if (frame.type === "ping") return this.send({ type: "pong", id: frame.id });
    if (frame.type === "pong") return;
    if (MAIL.includes(frame.type) && this.env.mailbox) return frame.type === "send" ? this.send_(frame) : this.ack(frame);
    if (frame.type === "presence-query" && this.env.hub?.presence) return this.presenceQuery(frame);
    if (frame.type === "presence" && this.env.hub?.presence) return this.error("unknown-type", "presence is sent by the relay, not to it", frame.id);
    if ((FRAME_TYPES as readonly string[]).includes(frame.type) && !SERVED.includes(frame.type)) {
      return this.error("internal", `${frame.type} is not served by this relay version yet`, frame.id);
    }
    return this.error("unknown-type", `unknown frame type ${JSON.stringify(frame.type).slice(0, 64)}`, frame.id);
  }

  /** Called by the hub's one timer at `nextDeadline()`: the 10 s auth deadline and the 90 s idle close (DEC-0047 item 3). */
  tick(): void {
    if (this.state === "closed") return;
    const now = this.env.now().getTime();
    if (this.state === "awaiting-auth" && now - this.openedAt > AUTH_DEADLINE_SECONDS * 1000) {
      return this.refuse("unauthenticated", `no auth within ${AUTH_DEADLINE_SECONDS} s`);
    }
    if (now - this.lastFrameAt > IDLE_CLOSE_SECONDS * 1000) this.close(CLOSE_CODES.idle, `silent for ${IDLE_CLOSE_SECONDS} s`);
  }

  private async authenticate(frame: AuthFrame): Promise<void> {
    const admission = this.env.admission();
    const result = admit(frame, {
      relay: this.relay, nonce: this.nonce, nonceUsed: this.nonceUsed, now: this.env.now(),
      admittedKey: (kid) => (admission.ok ? admission.set.get(kid) : undefined),
    });
    this.nonceUsed = true;
    if (!result.ok) {
      this.env.log?.({ event: "auth-refused", code: result.code, admission: admission.ok ? "held" : admission.refusal });
      return this.refuse(result.code, admission.ok || result.code !== "not-admitted" ? result.code : `no verified estate record (${admission.refusal})`);
    }
    if (!admission.ok) return this.refuse("not-admitted", `no verified estate record (${admission.refusal})`); // unreachable: admit found no key
    if (this.env.hub?.hasRoom && !this.env.hub.hasRoom(result.kid)) {
      try {
        this.error("rate-limited", "this machine already holds as many relay sessions as it may; close one and try again");
      } finally {
        this.close(CLOSE_TRY_AGAIN_LATER, "too many sessions for this machine");
      }
      return;
    }
    this.state = "admitted";
    this.kid = result.kid;
    this.revision = admission.revision;
    this.env.log?.({ event: "admitted", kid: result.kid, revision: admission.revision });
    this.connection = this.env.sessionId();
    this.lastTouch = this.env.now().getTime();
    this.send({ type: "welcome", session: this.connection, estateRevision: admission.revision, deltaHead: EMPTY_DELTA_HEAD, heartbeat: null });
    // In the hub's set first, then the first delivery: a message queued in between wakes this session (RLY-013).
    this.env.hub?.joined(this);
    if (this.env.mailbox) void this.wake();
  }

  /** A frame arrived: `lastSeen` moves, at most once per TOUCH_INTERVAL_SECONDS. */
  private async touch(): Promise<void> {
    const presence = this.env.hub?.presence;
    if (!presence || this.state !== "admitted") return;
    const now = this.env.now();
    if (now.getTime() - this.lastTouch < TOUCH_INTERVAL_SECONDS * 1000) return;
    this.lastTouch = now.getTime();
    // A last-seen time that could not be written is logged; it never costs the machine its session.
    try {
      await presence.touch(this.kid as string, now);
    } catch (error) {
      this.env.log?.({ event: "presence-fault", ...errorFields(error) });
    }
  }

  /**
   * A change in another machine's presence, sent only while that machine is in the set the relay admits right now:
   * presence follows the verified set (DEC-0047 item 4), and every machine of that set is of this estate's owner.
   */
  presence(record: PresenceRecord): void {
    if (this.state !== "admitted" || record.kid === this.kid) return;
    const admission = this.env.admission();
    if (!admission.ok || !admission.set.has(record.kid)) return;
    this.send({ type: "presence", kid: record.kid, state: record.state, lastSeen: record.lastSeen });
  }

  /**
   * `presence-query {kids}`: one `presence` frame per kid of this estate's admitted set that the relay has seen. A kid
   * outside the set, or never seen, gets no frame: the relay says nothing about machines of another owner and invents
   * no time for one it never saw.
   */
  private async presenceQuery(frame: Record<string, unknown>): Promise<void> {
    const kids = frame.kids;
    if (!Array.isArray(kids) || kids.length > MAX_QUERY_KIDS || !kids.every((kid) => typeof kid === "string" && kid.length >= 1 && kid.length <= MAX_KID_LENGTH)) {
      return this.error("unknown-type", `not a valid presence-query frame (kids: 0 to ${MAX_QUERY_KIDS} kids)`, frame.id as string);
    }
    const admission = this.env.admission();
    const asked = admission.ok ? (kids as string[]).filter((kid) => admission.set.has(kid)) : [];
    for (const record of await this.env.hub!.presence!.query(asked)) {
      if (this.state !== "admitted") return;
      this.send({ type: "presence", kid: record.kid, state: record.state, lastSeen: record.lastSeen });
    }
  }

  /** `send`: FAC-SEM-071's limits, a recipient the relay admits, then the mailbox; `accepted` names the seq. */
  private async send_(frame: Record<string, unknown>): Promise<void> {
    const id = frame.id as string;
    const findings = relayRules("relay-frame", frame) ?? [];
    if (findings.some((f) => f.instancePath === "/body") && typeof frame.body === "string" && base64urlLength(frame.body) > MAX_BODY_BYTES) {
      return this.error("too-large", `a body is at most ${MAX_BODY_BYTES} bytes decoded`, id);
    }
    if (findings.length > 0 || typeof frame.msgId !== "string" || typeof frame.to !== "string" || typeof frame.body !== "string") {
      return this.error("unknown-type", `not a valid send frame (FAC-SEM-071 at ${findings.map((f) => f.instancePath).join(", ") || "msgId/to/body"})`, id);
    }
    // The schema's own limits on what the relay echoes or stores (relayRules checks FAC-SEM-071's, not these): a msgId
    // of 1 to 128 characters, a recipient of 1 to 256, a body of base64url characters. Neither is ever echoed.
    if (frame.msgId.length < 1 || codePoints(frame.msgId) > MAX_ID_LENGTH) {
      return this.error("unknown-type", `not a valid send frame (msgId: 1 to ${MAX_ID_LENGTH} characters)`, id);
    }
    // A control character (NUL above all) does not survive every store: SQLite's text read-back ends at a NUL, so the
    // deliver would name another msgId than the accepted did. Refused, never echoed.
    if (/[\u0000-\u001f\u007f]/.test(frame.msgId)) {
      return this.error("unknown-type", "not a valid send frame (msgId: no control characters)", id);
    }
    if (frame.to.length < 1 || codePoints(frame.to) > 256) return this.error("unknown-type", "not a valid send frame (to: 1 to 256 characters)", id);
    if (!BASE64URL.test(frame.body)) return this.error("unknown-type", "not a valid send frame (body: base64url characters only)", id);
    const admission = this.env.admission();
    if (!admission.ok || !admission.set.has(frame.to)) return this.error("unknown-recipient", "the recipient is not a machine this relay admits", id);
    const result = await this.env.mailbox!.append(frame.to, this.kid as string, frame.msgId, frame.body, frame.ttl as number, this.env.now());
    if ("full" in result) return this.error("mailbox-full", "the recipient's mailbox is full", id);
    this.send({ type: "accepted", replyTo: id, msgId: frame.msgId, seq: result.seq });
    if (!result.duplicate) this.env.hub?.queued(frame.to);
  }

  /** `ack {seq}`: the recipient's own message is deleted; anything else is ignored rather than answered. */
  private async ack(frame: Record<string, unknown>): Promise<void> {
    if (Number.isSafeInteger(frame.seq)) await this.env.mailbox!.ack(this.kid as string, frame.seq as number);
  }

  /**
   * Deliver what waits for this connection. One flush runs at a time; a wake that arrives during it runs one more flush
   * when it ends, so a message appended meanwhile is delivered once, never missed and never twice. A fault in delivery
   * closes the session through `fault`; the promise never rejects.
   */
  wake(): Promise<void> {
    if (this.flushing) {
      this.again = true;
      return this.flushing;
    }
    this.flushing = (async () => {
      try {
        do {
          this.again = false;
          await this.flush();
        } while (this.again && this.state === "admitted");
      } catch (error) {
        this.fault(error);
      } finally {
        this.flushing = undefined;
        this.changed();
      }
    })();
    return this.flushing;
  }

  /**
   * Every unacknowledged message this connection has not been sent yet, in seq order, read from the mailbox one page
   * (FLUSH_PAGE) at a time and sent only while the transport is not backlogged. What is not sent yet stays in the
   * mailbox, durable, not in a socket buffer; the transport's `drained` wakes the session to go on.
   */
  private async flush(): Promise<void> {
    if (this.state !== "admitted" || !this.env.mailbox) return;
    for (;;) {
      if (this.io.backlogged?.()) return;
      const page = this.io.backlogged ? FLUSH_PAGE : FLUSH_PAGE_UNPACED;
      const entries = await this.env.mailbox.pending(this.kid as string, this.env.now(), this.delivered, page);
      for (const entry of entries) {
        if (this.state !== "admitted") return;
        if (entry.seq <= this.delivered) continue;
        if (this.io.backlogged?.()) return;
        this.delivered = entry.seq;
        this.send({ type: "deliver", from: entry.from, msgId: entry.msgId, seq: entry.seq, body: entry.body, sentAt: entry.sentAt });
      }
      if (entries.length < page) return;
    }
  }

  /**
   * The transport took what the relay had queued for this connection (its socket drained): the machine is reading, so
   * this counts as activity for the 90 s idle close, the same as a frame from it.
   */
  progressed(): void {
    if (this.state !== "admitted") return;
    this.lastFrameAt = this.env.now().getTime();
    this.changed();
  }

  /** An error frame and, for an authentication failure, the close DEC-0047 item 3 names. */
  private refuse(code: RelayErrorCode, message: string): void {
    try {
      this.error(code, message);
    } finally {
      // A transport that cannot take the error frame is still closed with the refusal's own code.
      this.close(code === "not-admitted" ? CLOSE_CODES.notAdmitted : CLOSE_CODES.unauthenticated, code);
    }
  }

  private error(code: RelayErrorCode, message: string, id?: string): void {
    this.send({ type: "error", ...(id ? { replyTo: id } : {}), code, message: message.replace(/[\r\n]+/g, " ") });
  }

  private send(frame: Record<string, unknown>): void {
    this.outbound += 1;
    this.io.send(JSON.stringify({ v: 1, id: `r${this.outbound}`, ...frame }));
    this.changed();
  }

  /**
   * A fault in the relay while serving this session (S5): logged as `session-fault`, answered `error internal`, then
   * closed 1011. Adapters and the hub call it; it is never silent, never closes twice and never throws: a transport
   * whose `send` throws (a socket gone bad underneath) is still closed, and the failure is logged, not rethrown.
   */
  fault(error: unknown): void {
    this.env.log?.({ event: "session-fault", ...(this.kid ? { kid: this.kid } : {}), ...errorFields(error) });
    if (this.state === "closed") return;
    try {
      this.error("internal", "the relay could not handle this");
    } catch (sendError) {
      this.env.log?.({ event: "session-fault", ...(this.kid ? { kid: this.kid } : {}), stage: "error-frame", ...errorFields(sendError) });
    } finally {
      try {
        this.close(1011, "internal error");
      } catch (closeError) {
        this.env.log?.({ event: "session-fault", ...(this.kid ? { kid: this.kid } : {}), stage: "close", ...errorFields(closeError) });
      }
    }
  }

  /** The transport closed from the other side: stop delivering to this connection. */
  disconnected(): void {
    if (this.state === "closed") return;
    this.end();
  }

  /** Close with `code`: the transport closes, and an admitted session leaves the hub (so its `lastSeen` is written). */
  close(code: number, reason: string): void {
    if (this.state === "closed") return;
    this.end();
    this.io.close(code, reason);
  }

  /** Stops delivery to this connection and, for an admitted one, tells the hub it ended. */
  private end(): void {
    const admitted = this.state === "admitted";
    this.state = "closed";
    if (admitted) this.env.hub?.left(this);
    this.changed();
  }
}
// #endregion relay-session
