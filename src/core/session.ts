// #region relay-session — docs: docs/protocol/sessions.md
// One relay connection, the same in both builds (the Worker's Durable Object and the portable server): `hello` with a
// fresh nonce, the machine's `auth` within 10 s checked by the contract's `admit` against the admission set, then
// `welcome` and the session's own frames. Every check of a signature or a key is the contract's (src/contract/); this
// module only sequences them and keeps the transport rules of DEC-0047 item 3.
//
// What it serves after `welcome`: `ping` → `pong`; with a mailbox, `send` → `accepted`, `deliver` to every connection the
// recipient holds, and `ack` (RLY-03); with a presence store, `presence` to the estate's other machines and
// `presence-query` (RLY-06). Blobs are HTTP routes, not frames. Deltas wait for DEC-0054 and are answered `error`
// `internal` "not served yet" rather than dropped.

import type { AdmissionResult } from "../contract/relay.ts";
import { relayRules } from "../contract/relay-rules.ts";
import { MAX_BODY_BYTES } from "../contract/relay.ts";
import type { DeliveryHub, MailboxStore } from "./mailbox.ts";
import { TOUCH_INTERVAL_SECONDS, type PresenceRecord, type PresenceStore } from "./presence.ts";
import {
  AUTH_DEADLINE_SECONDS, CLOSE_CODES, FRAME_TYPES, IDLE_CLOSE_SECONDS, MAX_FRAME_BYTES, RELAY_PROTOCOL, admit,
  type AuthFrame, type RelayErrorCode,
} from "../contract/relay.ts";

/** What the transport gives a session: send a text frame, close with a code. */
export interface SessionIo {
  send(text: string): void;
  close(code: number, reason: string): void;
}

export interface SessionEnv {
  relay: string; // this relay's origin, signed into every relay-auth/1
  now: () => Date;
  nonce: () => string; // 32 random bytes, base64url
  sessionId: () => string;
  admission: () => AdmissionResult;
  /** The store and the hub of store-and-forward (RLY-03); without them messages are answered "not served yet". */
  mailbox?: MailboxStore;
  hub?: DeliveryHub;
  /** Who is online and when each machine was last seen (RLY-06); without it presence is answered "not served yet". */
  presence?: PresenceStore;
  log?: (event: Record<string, unknown>) => void;
}

export type SessionState = "awaiting-auth" | "admitted" | "closed";

/**
 * Until DEC-0054 defines the revocation delta, a relay has carried none: the head is sequence 0 over no bytes. It has
 * the check-in's `records.revocationDelta` shape, so a node can report it unchanged.
 */
export const EMPTY_DELTA_HEAD = { sequence: 0, sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" } as const;

const SERVED = ["hello", "auth", "welcome", "ping", "pong", "error"];
const MAIL = ["send", "ack"];
/** The most kids one `presence-query` may name, and the longest kid (the relay-frame schema's limits). */
const MAX_QUERY_KIDS = 256;
const MAX_KID_LENGTH = 256;
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
  private unsubscribe: (() => void) | undefined;
  private connection = ""; // this connection's session id, as `welcome` names it
  private unsubscribePresence: (() => void) | undefined;
  private lastTouch = 0;
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly io: SessionIo, private readonly env: SessionEnv) {}

  /** The connection is open: greet with this connection's nonce. */
  open(): void {
    this.nonce = this.env.nonce();
    this.openedAt = this.lastFrameAt = this.env.now().getTime();
    this.send({ type: "hello", protocol: RELAY_PROTOCOL, relay: this.env.relay, nonce: this.nonce, time: this.env.now().toISOString() });
  }

  /**
   * One frame from the machine. Frames are handled one after another, in arrival order; the promise settles when this
   * one is. A binary frame or one over 1 MiB closes the connection; text is a JSON frame.
   */
  receive(data: string | Uint8Array | ArrayBuffer): Promise<void> {
    const next = this.queue.then(() => this.handle(data));
    this.queue = next.catch(() => undefined);
    return next;
  }

  private async handle(data: string | Uint8Array | ArrayBuffer): Promise<void> {
    if (this.state === "closed") return;
    if (typeof data !== "string") return this.close(CLOSE_CODES.binary, "binary frames are not part of fabric-relay/0.1");
    this.lastFrameAt = this.env.now().getTime();
    if (new TextEncoder().encode(data).byteLength > MAX_FRAME_BYTES) {
      this.error("too-large", `frames are at most ${MAX_FRAME_BYTES} bytes`);
      return this.close(CLOSE_CODES.tooLarge, "frame too large");
    }
    let frame: unknown;
    try {
      frame = JSON.parse(data);
    } catch {
      frame = undefined;
    }
    if (!isFrame(frame) || frame.v !== 1 || typeof frame.type !== "string" || typeof frame.id !== "string") {
      if (this.state === "awaiting-auth") return this.refuse("unauthenticated", "the first frame is a fabric-relay/0.1 auth frame");
      return this.error("unknown-type", "not a fabric-relay/0.1 frame");
    }
    if (frame.type === "auth") return this.authenticate(frame as unknown as AuthFrame);
    if (this.state === "awaiting-auth") return this.refuse("unauthenticated", "authenticate before any other frame");
    await this.touch();
    if (frame.type === "ping") return this.send({ type: "pong", id: frame.id });
    if (frame.type === "pong") return;
    if (MAIL.includes(frame.type) && this.env.mailbox) return frame.type === "send" ? this.send_(frame) : this.ack(frame);
    if (frame.type === "presence-query" && this.env.presence) return this.presenceQuery(frame);
    if (frame.type === "presence" && this.env.presence) return this.error("unknown-type", "presence is sent by the relay, not to it", frame.id);
    if ((FRAME_TYPES as readonly string[]).includes(frame.type) && !SERVED.includes(frame.type)) {
      return this.error("internal", `${frame.type} is not served by this relay version yet`, frame.id);
    }
    return this.error("unknown-type", `unknown frame type ${JSON.stringify(frame.type).slice(0, 64)}`, frame.id);
  }

  /** Called by the adapter's timer: the 10 s auth deadline and the 90 s idle close (DEC-0047 item 3). */
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
      relay: this.env.relay, nonce: this.nonce, nonceUsed: this.nonceUsed, now: this.env.now(),
      admittedKey: (kid) => (admission.ok ? admission.set.get(kid) : undefined),
    });
    this.nonceUsed = true;
    if (!result.ok) {
      this.env.log?.({ event: "auth-refused", code: result.code, admission: admission.ok ? "held" : admission.refusal });
      return this.refuse(result.code, admission.ok || result.code !== "not-admitted" ? result.code : `no verified estate record (${admission.refusal})`);
    }
    if (!admission.ok) return this.refuse("not-admitted", `no verified estate record (${admission.refusal})`); // unreachable: admit found no key
    this.state = "admitted";
    this.kid = result.kid;
    this.env.log?.({ event: "admitted", kid: result.kid, revision: admission.revision });
    this.connection = this.env.sessionId();
    this.send({ type: "welcome", session: this.connection, estateRevision: admission.revision, deltaHead: EMPTY_DELTA_HEAD, heartbeat: null });
    if (this.env.mailbox) {
      this.unsubscribe = this.env.hub?.subscribe(result.kid, () => void this.flush());
      void this.flush();
    }
    if (this.env.presence) {
      // Subscribe before announcing, so a machine that connects at the same moment is not missed either way.
      this.unsubscribePresence = this.env.presence.subscribe(this.connection, (record) => this.presenceOut(record));
      this.lastTouch = this.env.now().getTime();
      await this.env.presence.connected(result.kid, this.connection, this.env.now());
    }
  }

  /** A frame arrived: `lastSeen` moves, at most once per TOUCH_INTERVAL_SECONDS. */
  private async touch(): Promise<void> {
    if (!this.env.presence || this.state !== "admitted") return;
    const now = this.env.now();
    if (now.getTime() - this.lastTouch < TOUCH_INTERVAL_SECONDS * 1000) return;
    this.lastTouch = now.getTime();
    // A last-seen time that could not be written is logged; it never costs the machine its session.
    await this.env.presence.touch(this.kid as string, now).catch((error: unknown) => this.presenceFault(error));
  }

  private presenceFault(error: unknown): void {
    this.env.log?.({ event: "presence-fault", error: (error as Error).name, message: String((error as Error).message).slice(0, 200) });
  }

  /**
   * A change in another machine's presence, sent only while that machine is in the set the relay admits right now:
   * presence follows the verified set (DEC-0047 item 4), and every machine of that set is of this estate's owner.
   */
  private presenceOut(record: PresenceRecord): void {
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
    for (const record of await this.env.presence!.query(asked)) {
      if (this.state !== "admitted") return;
      this.send({ type: "presence", kid: record.kid, state: record.state, lastSeen: record.lastSeen });
    }
  }

  /** `send`: FAC-SEM-071's limits, a recipient the relay admits, then the mailbox; `accepted` names the seq. */
  private async send_(frame: Record<string, unknown>): Promise<void> {
    const id = frame.id as string;
    const findings = relayRules("relay-frame", frame) ?? [];
    if (findings.some((f) => f.instancePath === "/body") && typeof frame.body === "string" && Buffer.from(frame.body, "base64url").length > MAX_BODY_BYTES) {
      return this.error("too-large", `a body is at most ${MAX_BODY_BYTES} bytes decoded`, id);
    }
    if (findings.length > 0 || typeof frame.msgId !== "string" || typeof frame.to !== "string" || typeof frame.body !== "string") {
      return this.error("unknown-type", `not a valid send frame (FAC-SEM-071 at ${findings.map((f) => f.instancePath).join(", ") || "msgId/to/body"})`, id);
    }
    const admission = this.env.admission();
    if (!admission.ok || !admission.set.has(frame.to)) return this.error("unknown-recipient", "the recipient is not a machine this relay admits", id);
    const result = await this.env.mailbox!.append(frame.to, this.kid as string, frame.msgId, frame.body, frame.ttl as number, this.env.now());
    if ("full" in result) return this.error("mailbox-full", "the recipient's mailbox is full", id);
    this.send({ type: "accepted", replyTo: id, msgId: frame.msgId, seq: result.seq });
    if (!result.duplicate) this.env.hub?.notify(frame.to);
  }

  /** `ack {seq}`: the recipient's own message is deleted; anything else is ignored rather than answered. */
  private async ack(frame: Record<string, unknown>): Promise<void> {
    if (Number.isSafeInteger(frame.seq)) await this.env.mailbox!.ack(this.kid as string, frame.seq as number);
  }

  /** Every unacknowledged message this connection has not been sent yet, in seq order. */
  private async flush(): Promise<void> {
    if (this.state !== "admitted" || !this.env.mailbox) return;
    const entries = await this.env.mailbox.pending(this.kid as string, this.env.now(), this.delivered);
    for (const entry of entries) {
      if (this.state !== "admitted" || entry.seq <= this.delivered) continue;
      this.delivered = entry.seq;
      this.send({ type: "deliver", from: entry.from, msgId: entry.msgId, seq: entry.seq, body: entry.body, sentAt: entry.sentAt });
    }
  }

  /** An error frame and, for an authentication failure, the close DEC-0047 item 3 names. */
  private refuse(code: RelayErrorCode, message: string): void {
    this.error(code, message);
    this.close(code === "not-admitted" ? CLOSE_CODES.notAdmitted : CLOSE_CODES.unauthenticated, code);
  }

  private error(code: RelayErrorCode, message: string, id?: string): void {
    this.send({ type: "error", ...(id ? { replyTo: id } : {}), code, message: message.replace(/[\r\n]+/g, " ") });
  }

  private send(frame: Record<string, unknown>): void {
    this.outbound += 1;
    this.io.send(JSON.stringify({ v: 1, id: `r${this.outbound}`, ...frame }));
  }

  /** The transport closed from the other side: stop delivering to this connection. */
  disconnected(): void {
    if (this.state === "closed") return;
    this.end();
  }

  private close(code: number, reason: string): void {
    if (this.state === "closed") return;
    this.end();
    this.io.close(code, reason);
  }

  /** Stops delivery to this connection and, for an admitted one, tells the presence store it ended. */
  private end(): void {
    const admitted = this.state === "admitted";
    this.state = "closed";
    this.unsubscribe?.();
    this.unsubscribePresence?.();
    if (admitted && this.env.presence) {
      this.env.presence.disconnected(this.kid as string, this.connection, this.env.now()).catch((error: unknown) => this.presenceFault(error));
    }
  }
}
// #endregion relay-session
