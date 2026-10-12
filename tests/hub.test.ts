// The estate hub (RLY-012, RLY-014; docs/adr/0002-estate-hub.md): one per estate in both builds. It holds the
// connection set, derives presence from it, keeps one scheduler for every session's deadline, wakes a machine's
// sessions when a message is queued for it, and stops every session at once.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { test } from "node:test";
import { relayAuthSigningInput, type AdmissionResult } from "../src/contract/relay.ts";
import { EstateHub } from "../src/core/hub.ts";
import { MemoryMailbox, type MailboxStore } from "../src/core/mailbox.ts";
import { MemoryLastSeen } from "../src/core/presence.ts";
import type { SessionIo } from "../src/core/session.ts";

const require = createRequire(import.meta.url);
const ajv = new (require("ajv/dist/2020").default)({ allErrors: true, strict: false });
require("ajv-formats").default(ajv);
const frameValid = ajv.compile(JSON.parse(readFileSync(path.resolve(import.meta.dirname, "../src/contract/schemas/relay-frame.schema.json"), "utf8")));

const T0 = Date.parse("2026-10-12T12:00:00.000Z");
const NONCE = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const ORIGIN = "https://relay.example";

function machine(kid: string) {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { kid, privateKey: pair.privateKey, jwk: pair.publicKey.export({ format: "jwk" }) as Record<string, string> };
}
const A = machine("urn:fabric:machine:a#sig"), B = machine("urn:fabric:machine:b#sig");
const admission = (): AdmissionResult => ({ ok: true, held: {}, revision: 1, set: new Map([[A.kid, A.jwk], [B.kid, B.jwk]]) as unknown as Map<string, Uint8Array> });

function rig(options: { mailbox?: MailboxStore } = {}) {
  let now = T0;
  const armed: Array<number | undefined> = [];
  const log: Array<Record<string, unknown>> = [];
  const lastSeen = new MemoryLastSeen();
  let ids = 0;
  const hub = new EstateHub<object>({
    now: () => new Date(now), nonce: () => NONCE, sessionId: () => `s${++ids}`, admission, lastSeen,
    mailbox: options.mailbox ?? new MemoryMailbox(), arm: (at) => armed.push(at), log: (e) => log.push(e),
  });
  const open = () => {
    const conn = {};
    const sent: Array<Record<string, any>> = [];
    const closed: number[] = [];
    const io: SessionIo = { send: (t) => sent.push(JSON.parse(t)), close: (code) => closed.push(code) };
    hub.connect(conn, io, ORIGIN);
    const frame = (f: Record<string, unknown>) => hub.receive(conn, JSON.stringify({ v: 1, ...f }));
    const auth = async (m: ReturnType<typeof machine>) => {
      const iat = new Date(now).toISOString().replace(/\.\d{3}Z$/, "Z");
      const fields = { relay: ORIGIN, nonce: NONCE, estate: "e", kid: m.kid, iat };
      const sig = sign("sha256", Buffer.from(relayAuthSigningInput(fields)), { key: m.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
      await hub.receive(conn, JSON.stringify({ v: 1, type: "auth", id: "a", protocol: "fabric-relay/0.1", alg: "ES256", ...fields, sig }));
      assert.ok(sent.some((f) => f.type === "welcome"), JSON.stringify(sent.at(-1)));
    };
    const presenceOf = () => sent.filter((f) => f.type === "presence").map((f) => [f.kid, f.state]);
    return { conn, sent, closed, frame, auth, presenceOf, gone: () => hub.closed(conn) };
  };
  return { hub, open, armed, log, lastSeen, at: (ms: number) => { now = T0 + ms; }, settle: () => new Promise((resolve) => setImmediate(resolve)) };
}

test("hub.nextWake() is the earliest session deadline, the adapter's one timer is armed with it, and onWake closes exactly the due session", async () => {
  const r = rig();
  const silent = r.open();
  assert.equal(r.hub.nextWake(), T0 + 10_001);
  r.at(5000);
  const a = r.open();
  await a.auth(A);
  assert.equal(r.hub.nextWake(), T0 + 10_001, "the unauthenticated session is due first");
  assert.equal(r.armed.at(-1), T0 + 10_001);
  r.at(10_001);
  r.hub.onWake();
  assert.deepEqual([silent.closed, silent.sent.at(-1)!.code, a.closed], [[4401], "unauthenticated", []]);
  assert.equal(r.hub.nextWake(), T0 + 5000 + 90_001);
  assert.equal(r.armed.at(-1), T0 + 5000 + 90_001);
  r.at(5000 + 90_001);
  r.hub.onWake();
  assert.deepEqual(a.closed, [1001]);
  assert.equal(r.hub.nextWake(), undefined);
  assert.equal(r.armed.at(-1), undefined, "nothing is due: the timer is cleared");
});

test("presence is derived from the connection set: a second connection says nothing, the last one going says offline, in event order", async () => {
  const r = rig();
  const b = r.open();
  await b.auth(B);
  r.at(10_000);
  const a1 = r.open(), a2 = r.open();
  await a1.auth(A);
  await a2.auth(A);
  assert.deepEqual(b.presenceOf(), [[A.kid, "online"]]);
  r.at(20_000);
  a1.gone();
  assert.deepEqual(b.presenceOf(), [[A.kid, "online"]], "A still holds a connection");
  r.at(30_000);
  a2.gone();
  assert.deepEqual(b.presenceOf(), [[A.kid, "online"], [A.kid, "offline"]]);
  assert.equal(b.sent.filter((f) => f.type === "presence").at(-1)!.lastSeen, new Date(T0 + 30_000).toISOString());
  assert.equal(r.lastSeen.get(A.kid), new Date(T0 + 30_000).toISOString());
  assert.deepEqual(a1.presenceOf(), [], "a machine is not told about itself");
  for (const f of b.sent) assert.ok(frameValid(f), `${f.type}: ${JSON.stringify(frameValid.errors)}`);
  // A connection that comes and goes at once reaches B as online then offline, never the other way round.
  const a3 = r.open();
  await a3.auth(A);
  a3.gone();
  assert.deepEqual(b.presenceOf().slice(-2), [[A.kid, "online"], [A.kid, "offline"]]);
});

test("a hub restarted with no sockets holds no connection: a machine that reconnects is announced online again", async () => {
  const first = rig();
  const b0 = first.open();
  await b0.auth(B);
  const a0 = first.open();
  await a0.auth(A);
  // A deploy: every socket is gone and nothing was told. The new hub starts from the runtime's (empty) socket list.
  const r = rig();
  const b = r.open();
  await b.auth(B);
  const a = r.open();
  await a.auth(A);
  assert.deepEqual(b.presenceOf(), [[A.kid, "online"]]);
});

test("a session restored from its record (a hibernation wake) is in the set without being announced again", async () => {
  const r = rig();
  const b = r.open();
  await b.auth(B);
  const a = r.open();
  await a.auth(A);
  const record = r.hub.session(a.conn)!.snapshot();
  const r2 = rig();
  const sent: Array<Record<string, any>> = [];
  const b2 = r2.open();
  await b2.auth(B);
  r2.hub.restore(a.conn, { send: (t) => sent.push(JSON.parse(t)), close: () => {} }, record);
  assert.deepEqual(b2.presenceOf(), [], "restoring is not coming online");
  await b2.frame({ type: "presence-query", id: "q", kids: [A.kid] });
  assert.deepEqual(b2.presenceOf(), [], "a kid the restarted store never saw has no lastSeen to report");
  r2.hub.closed(a.conn);
  assert.deepEqual(b2.presenceOf(), [[A.kid, "offline"]], "its connection ending is going offline");
});

test("a wake that arrives during a flush delivers the message appended during that flush exactly once", async () => {
  const inner = new MemoryMailbox();
  let hold: (() => void) | undefined;
  const mailbox: MailboxStore = {
    append: (...args) => inner.append(...args),
    ack: (...args) => inner.ack(...args),
    pending: async (...args) => {
      const out = await inner.pending(...args);
      if (hold === undefined) await new Promise<void>((resolve) => { hold = resolve; });
      return out;
    },
  };
  const r = rig({ mailbox });
  const b = r.open();
  const authed = b.auth(B);
  await r.settle();
  await inner.append(B.kid, A.kid, "m-1", "AA", 60, new Date(T0));
  const first = r.hub.wake(B.kid); // a flush is in flight, held inside pending()
  await inner.append(B.kid, A.kid, "m-2", "AA", 60, new Date(T0));
  const second = r.hub.wake(B.kid); // arrives during that flush
  hold!();
  await Promise.all([authed, first, second]);
  await r.settle();
  assert.deepEqual(b.sent.filter((f) => f.type === "deliver").map((f) => f.msgId), ["m-1", "m-2"]);
});

test("a message queued for a machine wakes every session it holds, through the hub", async () => {
  const r = rig();
  const a = r.open(), b1 = r.open(), b2 = r.open();
  await a.auth(A);
  await b1.auth(B);
  await b2.auth(B);
  await a.frame({ type: "send", id: "s1", to: B.kid, msgId: "m-1", body: "AA", ttl: 60 });
  await r.settle();
  for (const b of [b1, b2]) assert.deepEqual(b.sent.filter((f) => f.type === "deliver").map((f) => f.seq), [1]);
});

test("a fault while handling a frame is answered error internal and closes 1011 through the session", async () => {
  const failing: MailboxStore = { ...new MemoryMailbox(), append: async () => { throw new Error("store down"); }, pending: async () => [], ack: async () => false };
  const r = rig({ mailbox: failing });
  const a = r.open();
  await a.auth(A);
  await a.frame({ type: "send", id: "s1", to: B.kid, msgId: "m-1", body: "AA", ttl: 60 });
  assert.deepEqual([a.sent.at(-1)!.code, a.closed], ["internal", [1011]]);
  assert.ok(r.log.some((e) => e.event === "session-fault" && e.message === "store down"));
});

test("stop() closes every session 1001, records lastSeen, announces nothing, and reports a transport that never closed", async () => {
  const r = rig();
  const a = r.open(), b = r.open(), silent = r.open();
  await a.auth(A);
  await b.auth(B);
  r.at(40_000);
  const before = b.sent.length;
  const stopping = r.hub.stop({ graceMs: 50 });
  assert.deepEqual([a.closed, b.closed, silent.closed], [[1001], [1001], [1001]]);
  assert.equal(b.sent.length, before, "no presence is sent while the relay stops");
  assert.equal(r.lastSeen.get(A.kid), new Date(T0 + 40_000).toISOString());
  a.gone();
  b.gone();
  const result = await stopping;
  assert.deepEqual([result.sessions, result.unclosed], [3, [silent.conn]]);
  const late = r.open();
  assert.deepEqual(late.closed, [1001], "a connection after stop is closed at once");
});
