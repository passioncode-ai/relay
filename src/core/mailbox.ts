// #region relay-mailbox — docs: docs/protocol/sessions.md#messages
// Store-and-forward for `fabric-relay/0.1` messages (DEC-0047 item 5): `send` appends to the recipient's mailbox and is
// answered `accepted {msgId, seq}`; every connection the recipient holds gets `deliver` in `seq` order; `ack {seq}`
// deletes. Delivery is at least once and a recipient deduplicates by (from, msgId). The relay never reads a body and
// never reports a command done: a queued message stays queued until it is acknowledged or its `ttl` passes.

/** One queued message. `body` is opaque base64url, end to end between the two machines. */
export interface MailEntry {
  to: string;
  from: string;
  msgId: string;
  seq: number;
  body: string;
  sentAt: string;
  expiresAt: number; // epoch ms: sentAt + ttl
}

export type AppendResult = { seq: number; duplicate: boolean } | { full: true };

/**
 * A mailbox store per recipient. Implementations: `MemoryMailbox` (tests, one process), SQLite in the portable build
 * and in a Worker's Durable Object. Every method is per recipient kid; `seq` is monotonic per mailbox.
 */
export interface MailboxStore {
  /** Appends, or answers the first `seq` of the same (from, msgId) still in the mailbox; refuses past the limit. */
  append(to: string, from: string, msgId: string, body: string, ttlSeconds: number, now: Date): Promise<AppendResult>;
  /** Unacknowledged, unexpired messages after `afterSeq`, in `seq` order. Expired ones are deleted on the way. */
  pending(to: string, now: Date, afterSeq?: number): Promise<MailEntry[]>;
  /** Deletes one acknowledged message; false when the mailbox holds no such `seq`. */
  ack(to: string, seq: number): Promise<boolean>;
}

/**
 * How many messages one mailbox holds before `send` is refused `mailbox-full`. DEC-0047 leaves quotas undecided ("Not
 * decided here: mailbox quotas"); this is the relay's own limit until the contract sets one.
 */
export const MAILBOX_LIMIT = 1000;

export class MemoryMailbox implements MailboxStore {
  readonly #boxes = new Map<string, { next: number; entries: MailEntry[] }>();

  #box(to: string) {
    let box = this.#boxes.get(to);
    if (!box) this.#boxes.set(to, (box = { next: 1, entries: [] }));
    return box;
  }

  async append(to: string, from: string, msgId: string, body: string, ttlSeconds: number, now: Date): Promise<AppendResult> {
    const box = this.#box(to);
    box.entries = box.entries.filter((entry) => entry.expiresAt > now.getTime());
    const same = box.entries.find((entry) => entry.from === from && entry.msgId === msgId);
    if (same) return { seq: same.seq, duplicate: true };
    if (box.entries.length >= MAILBOX_LIMIT) return { full: true };
    const entry: MailEntry = { to, from, msgId, seq: box.next++, body, sentAt: now.toISOString(), expiresAt: now.getTime() + ttlSeconds * 1000 };
    box.entries.push(entry);
    return { seq: entry.seq, duplicate: false };
  }

  async pending(to: string, now: Date, afterSeq = 0): Promise<MailEntry[]> {
    const box = this.#box(to);
    box.entries = box.entries.filter((entry) => entry.expiresAt > now.getTime());
    return box.entries.filter((entry) => entry.seq > afterSeq).map((entry) => ({ ...entry }));
  }

  async ack(to: string, seq: number): Promise<boolean> {
    const box = this.#box(to);
    const before = box.entries.length;
    box.entries = box.entries.filter((entry) => entry.seq !== seq);
    return box.entries.length < before;
  }
}

// #endregion relay-mailbox
