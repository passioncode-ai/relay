// Presence and "last seen" (RLY-06; DEC-0047, Messages: Presence; Fabric ADR-0088's offline rule): the store in both
// builds' forms, then sessions of the estate's machines seeing each other come and go, the query, the verified-set
// filter, and the offline rule — a sender learns that its message was queued, and never that it was done.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { relayAuthSigningInput, type AdmissionResult } from "../src/contract/relay.ts";
import { MemoryHub, MemoryMailbox } from "../src/core/mailbox.ts";
import { MemoryPresence, TOUCH_INTERVAL_SECONDS, type PresenceRecord, type PresenceStore } from "../src/core/presence.ts";
import { RelaySession } from "../src/core/session.ts";
import { SqlitePresence } from "../src/portable/sqlite-presence.ts";

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const sqliteFile = () => { const d = mkdtempSync(path.join(tmpdir(), "relay-presence-")); dirs.push(d); return path.join(d, "data", "presence.sqlite"); };
const stores: Array<[string, () => PresenceStore]> = [["memory", () => new MemoryPresence()], ["sqlite", () => new SqlitePresence(sqliteFile())]];

const require = createRequire(import.meta.url);
const ajv = new (require("ajv/dist/2020").default)({ allErrors: true, strict: false });
require("ajv-formats").default(ajv);
const frameValid = ajv.compile(JSON.parse(readFileSync(path.resolve(import.meta.dirname, "../src/contract/schemas/relay-frame.schema.json"), "utf8")));

const T0 = new Date("2026-10-12T12:00:00.000Z");
const at = (seconds: number) => new Date(T0.getTime() + seconds * 1000);

for (const [name, make] of stores) test(`${name}: online on a machine's first connection, offline on its last, lastSeen only forward, never-seen left out`, async () => {
  const store = make();
  const heard: PresenceRecord[] = [];
  const stop = store.subscribe("watcher", (record) => heard.push(record));
  await store.connected("a#sig", "c1", at(0));
  await store.connected("a#sig", "c2", at(5)); // a second connection: still online, nothing new to say
  assert.deepEqual(heard, [{ kid: "a#sig", state: "online", lastSeen: at(0).toISOString() }]);
  await store.touch("a#sig", at(40));
  await store.disconnected("a#sig", "c1", at(50));
  assert.equal(heard.length, 1);
  await store.disconnected("a#sig", "c2", at(60));
  assert.deepEqual(heard.at(-1), { kid: "a#sig", state: "offline", lastSeen: at(60).toISOString() });
  await store.disconnected("a#sig", "c2", at(70)); // already gone: no second offline, no time moved
  await store.touch("a#sig", at(10)); // a late report never moves the time back
  assert.equal(heard.length, 2);
  assert.deepEqual(await store.query(["never#sig", "a#sig", "a#sig"]), [{ kid: "a#sig", state: "offline", lastSeen: at(60).toISOString() }]);
  stop();
  await store.connected("a#sig", "c3", at(80));
  assert.equal(heard.length, 2); // unsubscribed
});

test("sqlite: lastSeen survives a restart, in an owner-only file; who is connected does not", async () => {
  const file = sqliteFile();
  const first = new SqlitePresence(file);
  await first.connected("a#sig", "c1", at(0));
  await first.touch("a#sig", at(45));
  first.close();
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(statSync(path.dirname(file)).mode & 0o777, 0o700);
  const second = new SqlitePresence(file);
  assert.deepEqual(await second.query(["a#sig"]), [{ kid: "a#sig", state: "offline", lastSeen: at(45).toISOString() }]);
  second.close();
});

function machine(kid: string) {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { kid, privateKey: pair.privateKey, jwk: pair.publicKey.export({ format: "jwk" }) as Record<string, string> };
}
const A = machine("urn:fabric:machine:a#sig"), B = machine("urn:fabric:machine:b#sig"), C = machine("urn:fabric:machine:c#sig");

function estateRelay() {
  let now = T0;
  let admitted = [A, B, C];
  const presence = new MemoryPresence(), mailbox = new MemoryMailbox(), hub = new MemoryHub();
  const admission = (): AdmissionResult => ({ ok: true, held: {}, revision: 1, set: new Map(admitted.map((m) => [m.kid, m.jwk])) as unknown as Map<string, Uint8Array> });
  let sessions = 0;
  const connect = async (m: ReturnType<typeof machine>) => {
    const sent: Array<Record<string, any>> = [];
    const nonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const session = new RelaySession({ send: (t) => sent.push(JSON.parse(t)), close: () => {} }, {
      relay: "https://relay.example", now: () => now, nonce: () => nonce, sessionId: () => `s${++sessions}`, admission, mailbox, hub, presence,
    });
    session.open();
    const iat = now.toISOString().replace(/\.\d{3}Z$/, "Z");
    const fields = { relay: "https://relay.example", nonce, estate: "e", kid: m.kid, iat };
    const sig = sign("sha256", Buffer.from(relayAuthSigningInput(fields)), { key: m.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    await session.receive(JSON.stringify({ v: 1, type: "auth", id: "a", protocol: "fabric-relay/0.1", alg: "ES256", ...fields, sig }));
    assert.ok(sent.some((f) => f.type === "welcome"), JSON.stringify(sent.at(-1)));
    const frame = (f: Record<string, unknown>) => session.receive(JSON.stringify({ v: 1, ...f }));
    const presenceOf = () => sent.filter((f) => f.type === "presence").map((f) => [f.kid, f.state, f.lastSeen]);
    return { session, sent, frame, presenceOf };
  };
  return { presence, connect, advance: (s: number) => { now = new Date(now.getTime() + s * 1000); }, revoke: (kid: string) => { admitted = admitted.filter((m) => m.kid !== kid); } };
}

test("a machine of the estate sees another come online and go offline, with when it was last seen; never its own", async () => {
  const r = estateRelay();
  const b = await r.connect(B);
  r.advance(10);
  const a1 = await r.connect(A);
  const a2 = await r.connect(A); // a second connection of A: B hears nothing more
  assert.deepEqual(b.presenceOf(), [[A.kid, "online", at(10).toISOString()]]);
  r.advance(20);
  a1.session.disconnected();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(b.presenceOf().length, 1); // A still holds a connection
  r.advance(5);
  a2.session.disconnected();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(b.presenceOf().at(-1), [A.kid, "offline", at(35).toISOString()]);
  assert.deepEqual(a1.presenceOf(), [], "a machine is not told about itself");
  for (const c of [a1, a2, b]) for (const f of c.sent) assert.ok(frameValid(f), `${f.type}: ${JSON.stringify(frameValid.errors)}`);
});

test("presence-query answers each kid of the estate the relay has seen; a stranger and a machine never seen get nothing", async () => {
  const r = estateRelay();
  const a = await r.connect(A);
  r.advance(3);
  const b = await r.connect(B);
  a.sent.length = 0;
  await b.frame({ type: "presence-query", id: "q1", kids: [A.kid, "urn:fabric:machine:stranger#sig", C.kid, B.kid] });
  assert.deepEqual(b.presenceOf(), [[A.kid, "online", T0.toISOString()], [B.kid, "online", at(3).toISOString()]]);
  await b.frame({ type: "presence-query", id: "q2", kids: "everyone" });
  assert.deepEqual([b.sent.at(-1)!.type, b.sent.at(-1)!.code, b.sent.at(-1)!.replyTo], ["error", "unknown-type", "q2"]);
  await b.frame({ type: "presence-query", id: "q3", kids: Array.from({ length: 257 }, (_, i) => `k${i}#sig`) });
  assert.equal(b.sent.at(-1)!.code, "unknown-type");
  await b.frame({ type: "presence", id: "p1", kid: A.kid, state: "offline", lastSeen: T0.toISOString() });
  assert.deepEqual([b.sent.at(-1)!.code, b.sent.at(-1)!.replyTo], ["unknown-type", "p1"]); // a node does not announce presence
  for (const f of b.sent) assert.ok(frameValid(f), `${f.type}: ${JSON.stringify(frameValid.errors)}`);
});

test("presence follows the verified set: a machine no longer admitted is neither announced nor answered", async () => {
  const r = estateRelay();
  const b = await r.connect(B);
  const a = await r.connect(A);
  r.revoke(A.kid);
  a.session.disconnected();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(b.presenceOf(), [[A.kid, "online", T0.toISOString()]]); // the offline after revocation is not sent
  await b.frame({ type: "presence-query", id: "q", kids: [A.kid] });
  assert.equal(b.presenceOf().length, 1);
});

test("lastSeen moves with a machine's frames, at most once per touch interval", async () => {
  const r = estateRelay();
  const a = await r.connect(A);
  r.advance(TOUCH_INTERVAL_SECONDS - 1);
  await a.frame({ type: "ping", id: "p1" });
  assert.deepEqual(await r.presence.query([A.kid]), [{ kid: A.kid, state: "online", lastSeen: T0.toISOString() }]);
  r.advance(1);
  await a.frame({ type: "ping", id: "p2" });
  assert.deepEqual(await r.presence.query([A.kid]), [{ kid: A.kid, state: "online", lastSeen: at(TOUCH_INTERVAL_SECONDS).toISOString() }]);
});

test("the offline rule: a sender learns its message was queued, never that it was delivered or done", async () => {
  const r = estateRelay();
  const a = await r.connect(A);
  await a.frame({ type: "send", id: "s1", to: B.kid, msgId: "cmd-1", body: "eyJydW4iOiJ4In0", ttl: 3600 });
  assert.deepEqual([a.sent.at(-1)!.type, a.sent.at(-1)!.seq], ["accepted", 1]); // B is offline: queued, nothing more
  r.advance(60);
  const b = await r.connect(B);
  await new Promise((resolve) => setImmediate(resolve));
  const deliver = b.sent.find((f) => f.type === "deliver")!;
  await b.frame({ type: "ack", id: "k1", seq: deliver.seq });
  await new Promise((resolve) => setImmediate(resolve));
  // After `accepted`, A hears only that B came online; nothing about the message, its delivery or its ack.
  const after = a.sent.slice(a.sent.findIndex((f) => f.type === "accepted") + 1);
  assert.deepEqual(after.map((f) => [f.type, f.kid]), [["presence", B.kid]]);
  assert.ok(!JSON.stringify(after).includes("cmd-1"));
});
