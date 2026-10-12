// Store-and-forward (RLY-03, DEC-0047 item 5): the mailbox store, and two admitted machines exchanging a message through
// sessions that share a store and a hub. Every frame the relay sends is valid against the contract's relay-frame schema.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { test } from "node:test";
import { relayAuthSigningInput, type AdmissionResult } from "../src/contract/relay.ts";
import { MAILBOX_LIMIT, MemoryHub, MemoryMailbox } from "../src/core/mailbox.ts";
import { RelaySession } from "../src/core/session.ts";
import { SqliteMailbox } from "../src/portable/sqlite-mailbox.ts";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { after } from "node:test";
import type { MailboxStore } from "../src/core/mailbox.ts";

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const sqliteFile = () => { const d = mkdtempSync(path.join(tmpdir(), "relay-mail-")); dirs.push(d); return path.join(d, "data", "mailbox.sqlite"); };
const stores: Array<[string, () => MailboxStore]> = [["memory", () => new MemoryMailbox()], ["sqlite", () => new SqliteMailbox(sqliteFile())]];

const root = path.resolve(import.meta.dirname, "..");
const require = createRequire(import.meta.url);
const ajv = new (require("ajv/dist/2020").default)({ allErrors: true, strict: false });
require("ajv-formats").default(ajv);
const frameValid = ajv.compile(JSON.parse(readFileSync(path.join(root, "src/contract/schemas/relay-frame.schema.json"), "utf8")));

const T0 = new Date("2026-10-12T12:00:00Z");

for (const [name, make] of stores) test(`${name}: the store numbers per mailbox, answers a repeat with its first seq, drops what expired, refuses past the limit`, async () => {
  const box = make();
  assert.deepEqual(await box.append("b#sig", "a#sig", "m1", "AA", 60, T0), { seq: 1, duplicate: false });
  assert.deepEqual(await box.append("b#sig", "a#sig", "m1", "AA", 60, T0), { seq: 1, duplicate: true });
  assert.deepEqual(await box.append("b#sig", "c#sig", "m1", "AA", 60, T0), { seq: 2, duplicate: false }); // another sender
  assert.deepEqual(await box.append("x#sig", "a#sig", "m1", "AA", 60, T0), { seq: 1, duplicate: false }); // another mailbox
  assert.deepEqual((await box.pending("b#sig", T0)).map((e) => e.seq), [1, 2]);
  assert.deepEqual((await box.pending("b#sig", T0, 1)).map((e) => e.seq), [2]);
  assert.equal(await box.ack("b#sig", 1), true);
  assert.equal(await box.ack("b#sig", 1), false);
  const later = new Date(T0.getTime() + 61_000);
  assert.deepEqual(await box.pending("b#sig", later), []);
  assert.deepEqual(await box.append("b#sig", "a#sig", "m1", "AA", 60, later), { seq: 3, duplicate: false }); // the repeat window passed
  const full = make();
  for (let i = 0; i < MAILBOX_LIMIT; i++) await full.append("b#sig", "a#sig", `m${i}`, "AA", 60, T0);
  assert.deepEqual(await full.append("b#sig", "a#sig", "one-more", "AA", 60, T0), { full: true });
});

function machine(kid: string) {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { kid, privateKey: pair.privateKey, jwk: pair.publicKey.export({ format: "jwk" }) as Record<string, string> };
}
const A = machine("urn:fabric:machine:a#sig"), B = machine("urn:fabric:machine:b#sig");
const admission = (): AdmissionResult => ({ ok: true, held: {}, revision: 1, set: new Map([[A.kid, A.jwk], [B.kid, B.jwk]]) as unknown as Map<string, Uint8Array> });

function connect(m: ReturnType<typeof machine>, mailbox: MemoryMailbox, hub: MemoryHub, nonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8") {
  const sent: Array<Record<string, any>> = [];
  const session = new RelaySession({ send: (t) => sent.push(JSON.parse(t)), close: () => {} }, {
    relay: "https://relay.example", now: () => T0, nonce: () => nonce, sessionId: () => `s-${m.kid}`, admission, mailbox, hub,
  });
  session.open();
  const iat = T0.toISOString().replace(/\.\d{3}Z$/, "Z");
  const fields = { relay: "https://relay.example", nonce, estate: "e", kid: m.kid, iat };
  const sig = sign("sha256", Buffer.from(relayAuthSigningInput(fields)), { key: m.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  const auth = JSON.stringify({ v: 1, type: "auth", id: "a", protocol: "fabric-relay/0.1", alg: "ES256", ...fields, sig });
  return { session, sent, auth, frame: (f: Record<string, unknown>) => session.receive(JSON.stringify({ v: 1, ...f })) };
}
const settle = () => new Promise((resolve) => setImmediate(resolve));

test("a message from A reaches B: accepted with its seq, delivered once to each of B's connections, deleted on ack", async () => {
  const mailbox = new MemoryMailbox(), hub = new MemoryHub();
  const a = connect(A, mailbox, hub), b1 = connect(B, mailbox, hub), b2 = connect(B, mailbox, hub);
  for (const c of [a, b1, b2]) await c.session.receive(c.auth);
  await a.frame({ type: "send", id: "s1", to: B.kid, msgId: "m-1", body: "eyJoaSI6MX0", ttl: 3600 });
  await settle();
  assert.deepEqual(a.sent.at(-1), { v: 1, id: a.sent.at(-1)!.id, type: "accepted", replyTo: "s1", msgId: "m-1", seq: 1 });
  for (const b of [b1, b2]) {
    const deliver = b.sent.filter((f) => f.type === "deliver");
    assert.equal(deliver.length, 1);
    assert.deepEqual([deliver[0]!.from, deliver[0]!.msgId, deliver[0]!.seq, deliver[0]!.body], [A.kid, "m-1", 1, "eyJoaSI6MX0"]);
  }
  await a.frame({ type: "send", id: "s2", to: B.kid, msgId: "m-1", body: "eyJoaSI6MX0", ttl: 3600 }); // the same message again
  await settle();
  assert.equal(a.sent.at(-1)!.seq, 1);
  assert.equal(b1.sent.filter((f) => f.type === "deliver").length, 1); // not delivered twice
  await b1.frame({ type: "ack", id: "k1", seq: 1 });
  assert.deepEqual(await mailbox.pending(B.kid, T0), []);
  const late = connect(B, mailbox, hub);
  await late.session.receive(late.auth);
  await settle();
  assert.equal(late.sent.filter((f) => f.type === "deliver").length, 0); // acknowledged: gone for every connection
  for (const c of [a, b1, b2, late]) for (const f of c.sent) assert.ok(frameValid(f), `${f.type}: ${JSON.stringify(frameValid.errors)}`);
});

test("a machine that connects later gets what waited for it; one that disconnected gets nothing more", async () => {
  const mailbox = new MemoryMailbox(), hub = new MemoryHub();
  const a = connect(A, mailbox, hub);
  await a.session.receive(a.auth);
  await a.frame({ type: "send", id: "s1", to: B.kid, msgId: "m-1", body: "AA", ttl: 60 });
  const b = connect(B, mailbox, hub);
  await b.session.receive(b.auth);
  await settle();
  assert.deepEqual(b.sent.filter((f) => f.type === "deliver").map((f) => f.seq), [1]);
  b.session.disconnected();
  await a.frame({ type: "send", id: "s2", to: B.kid, msgId: "m-2", body: "AA", ttl: 60 });
  await settle();
  assert.equal(b.sent.filter((f) => f.type === "deliver").length, 1);
});

test("send is refused by name: a stranger recipient, a body over the limit, FAC-SEM-071's limits; nothing is queued", async () => {
  const mailbox = new MemoryMailbox(), hub = new MemoryHub();
  const a = connect(A, mailbox, hub);
  await a.session.receive(a.auth);
  const cases: Array<[Record<string, unknown>, string]> = [
    [{ to: "urn:fabric:machine:stranger#sig", msgId: "m", body: "AA", ttl: 60 }, "unknown-recipient"],
    [{ to: B.kid, msgId: "m", body: Buffer.alloc(783_361).toString("base64url"), ttl: 60 }, "too-large"],
    [{ to: B.kid, msgId: "m", body: "AA", ttl: 0 }, "unknown-type"],
    [{ to: B.kid, msgId: "m", body: "AA", ttl: 604_801 }, "unknown-type"],
    [{ to: "urn:fabric:machine:b#kem", msgId: "m", body: "AA", ttl: 60 }, "unknown-type"],
    [{ to: B.kid, body: "AA", ttl: 60 }, "unknown-type"],
  ];
  for (const [frame, code] of cases) {
    await a.frame({ type: "send", id: "s", ...frame });
    assert.equal(a.sent.at(-1)!.code, code, JSON.stringify(frame).slice(0, 80));
    assert.equal(a.sent.at(-1)!.replyTo, "s");
  }
  assert.deepEqual(await mailbox.pending(B.kid, T0), []);
});

test("without a mailbox, send and ack are refused as not served yet", async () => {
  const sent: Array<Record<string, any>> = [];
  const nonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
  const session = new RelaySession({ send: (t) => sent.push(JSON.parse(t)), close: () => {} },
    { relay: "https://relay.example", now: () => T0, nonce: () => nonce, sessionId: () => "s", admission });
  session.open();
  await session.receive(connect(A, new MemoryMailbox(), new MemoryHub(), nonce).auth);
  await session.receive(JSON.stringify({ v: 1, type: "send", id: "s1", to: B.kid, msgId: "m", body: "AA", ttl: 60 }));
  assert.deepEqual([sent.at(-1)!.code, sent.at(-1)!.replyTo], ["internal", "s1"]);
});

test("two wake-ups at once deliver a message to a connection once, not twice", async () => {
  const mailbox = new MemoryMailbox(), hub = new MemoryHub();
  const b = connect(B, mailbox, hub);
  await b.session.receive(b.auth);
  await settle();
  await mailbox.append(B.kid, A.kid, "m-1", "AA", 60, T0);
  hub.notify(B.kid);
  hub.notify(B.kid);
  await settle();
  await settle();
  assert.deepEqual(b.sent.filter((f) => f.type === "deliver").map((f) => f.seq), [1]);
});

test("sqlite: queued messages and their numbering survive a restart, in an owner-only file", async () => {
  const file = sqliteFile();
  const first = new SqliteMailbox(file);
  await first.append(B.kid, A.kid, "m-1", "AA", 3600, T0);
  first.close();
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(statSync(path.dirname(file)).mode & 0o777, 0o700);
  const second = new SqliteMailbox(file);
  assert.deepEqual((await second.pending(B.kid, T0)).map((e) => [e.seq, e.from, e.msgId]), [[1, A.kid, "m-1"]]);
  assert.deepEqual(await second.append(B.kid, A.kid, "m-2", "AA", 3600, T0), { seq: 2, duplicate: false });
  second.close();
});
