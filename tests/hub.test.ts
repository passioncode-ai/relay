// The estate hub (RLY-012, RLY-014; docs/adr/0002-estate-hub.md): one per estate in both builds. It holds the
// connection set, derives presence from it, keeps one scheduler for every session's deadline, wakes a machine's
// sessions when a message is queued for it, and stops every session at once.
import assert from "node:assert/strict";
import { test } from "node:test";
import { frameValid } from "./frame-schema.ts";
import { MAX_BODY_BYTES, MAX_FRAME_BYTES, type AdmissionResult } from "../src/contract/relay.ts";
import { EstateHub, REFRESH_RETRY_MS, type HubDeps } from "../src/core/hub.ts";
import { MemoryMailbox, type MailboxStore } from "../src/core/mailbox.ts";
import { MemoryLastSeen } from "../src/core/presence.ts";
import { IDLE_OUTSTANDING_MS, type SessionIo } from "../src/core/session.ts";
import { admittedSet, authFrame, machine, type TestMachine } from "./test-signer.ts";


const T0 = Date.parse("2026-10-12T12:00:00.000Z");
const NONCE = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const ORIGIN = "https://relay.example";

const A = machine("urn:fabric:machine:a#sig"), B = machine("urn:fabric:machine:b#sig");
const admission = (): AdmissionResult => admittedSet([A, B]);

function rig(options: { mailbox?: MailboxStore; refresh?: HubDeps["refresh"]; maxSessionsPerMachine?: number } = {}) {
  let now = T0;
  const armed: Array<number | undefined> = [];
  const log: Array<Record<string, unknown>> = [];
  const lastSeen = new MemoryLastSeen();
  let ids = 0;
  const hub = new EstateHub<object>({
    now: () => new Date(now), nonce: () => NONCE, sessionId: () => `s${++ids}`, admission, lastSeen,
    mailbox: options.mailbox ?? new MemoryMailbox(), arm: (at) => armed.push(at), log: (e) => log.push(e),
    ...(options.refresh ? { refresh: options.refresh } : {}),
    ...(options.maxSessionsPerMachine ? { maxSessionsPerMachine: options.maxSessionsPerMachine } : {}),
  });
  const open = (transport: { backlogged?: () => boolean; outstanding?: () => boolean } = {}) => {
    const conn = {};
    const sent: Array<Record<string, any>> = [];
    const closed: number[] = [];
    let dead = false; // a socket gone bad underneath: every send throws, as `ws` does on a destroyed socket
    const io: SessionIo = {
      send: (t) => {
        if (dead) throw new Error("socket is gone");
        sent.push(JSON.parse(t));
      },
      close: (code) => closed.push(code),
      ...(transport.backlogged ? { backlogged: transport.backlogged } : {}),
      ...(transport.outstanding ? { outstanding: transport.outstanding } : {}),
    };
    hub.connect(conn, io, ORIGIN);
    const frame = (f: Record<string, unknown>) => hub.receive(conn, JSON.stringify({ v: 1, ...f }));
    const auth = async (m: TestMachine) => {
      await hub.receive(conn, JSON.stringify(authFrame(m, { relay: ORIGIN, nonce: NONCE, at: now, id: "a" })));
      assert.ok(sent.some((f) => f.type === "welcome"), JSON.stringify(sent.at(-1)));
    };
    const presenceOf = () => sent.filter((f) => f.type === "presence").map((f) => [f.kid, f.state]);
    return { conn, sent, closed, frame, auth, presenceOf, gone: () => hub.closed(conn), kill: () => { dead = true; } };
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
  await r.hub.onWake();
  assert.deepEqual([silent.closed, silent.sent.at(-1)!.code, a.closed], [[4401], "unauthenticated", []]);
  assert.equal(r.hub.nextWake(), T0 + 5000 + 90_001);
  assert.equal(r.armed.at(-1), T0 + 5000 + 90_001);
  r.at(5000 + 90_001);
  await r.hub.onWake();
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

test("a machine that idles out while its transport never reports the close goes offline for the others", async () => {
  const r = rig();
  const b = r.open();
  await b.auth(B);
  const a = r.open();
  await a.auth(A);
  r.at(80_000);
  await b.frame({ type: "ping", id: "keep-b" }); // B keeps talking; A falls silent
  r.at(90_001);
  await r.hub.onWake();
  assert.deepEqual(a.closed, [1001]); // A's transport is told to close, and never reports back
  assert.deepEqual(b.presenceOf(), [[A.kid, "online"], [A.kid, "offline"]]);
  assert.equal(r.hub.size, 2, "A's transport is still in the set; its closed session is not online");
});

test("lastSeen never moves back, even when the clock does", async () => {
  const r = rig();
  const b = r.open();
  await b.auth(B);
  r.at(100_000);
  const a = r.open();
  await a.auth(A);
  r.at(50_000); // the clock steps back
  a.gone();
  const offline = b.sent.filter((f) => f.type === "presence").at(-1)!;
  assert.deepEqual([offline.state, offline.lastSeen], ["offline", new Date(T0 + 100_000).toISOString()]);
  assert.equal(r.lastSeen.get(A.kid), new Date(T0 + 100_000).toISOString());
});

test("an admission refresh that rejects is logged refresh-fault, and the next wake moves forward instead of spinning", async () => {
  let runs = 0;
  const r = rig({ refresh: { deadline: () => T0 + 1000, run: async () => { runs += 1; throw new Error("estate unreadable"); } } });
  assert.equal(r.hub.nextWake(), T0 + 1000);
  r.at(1000);
  await r.hub.onWake();
  assert.equal(runs, 1);
  assert.ok(r.log.some((e) => e.event === "refresh-fault" && e.message === "estate unreadable"));
  assert.equal(r.hub.nextWake(), T0 + 1000 + REFRESH_RETRY_MS);
  assert.equal(r.armed.at(-1), T0 + 1000 + REFRESH_RETRY_MS);
  await r.hub.onWake(); // too early for a retry
  assert.equal(runs, 1);
  r.at(1000 + REFRESH_RETRY_MS);
  await r.hub.onWake();
  assert.equal(runs, 2);
});

test("an admission refresh runs once at a time: a timer that fires while one runs does not start another", async () => {
  let runs = 0;
  let finish: (() => void) | undefined;
  const r = rig({ refresh: { deadline: () => T0 + 1000, run: () => { runs += 1; return new Promise<void>((resolve) => { finish = resolve; }); } } });
  const a = r.open();
  r.at(1000);
  const first = r.hub.onWake(); // the refresh is due and starts
  assert.equal(runs, 1);
  await a.frame({ type: "ping", id: "p" }); // an event arms the timer while the refresh runs
  assert.notEqual(r.armed.at(-1), T0 + 1000, "the running refresh's deadline is not armed again");
  await r.hub.onWake(); // the timer fires anyway
  assert.equal(runs, 1, "no second refresh while one runs");
  finish!();
  await first;
  assert.equal(runs, 1);
});

// Fault isolation (round 3): a transport whose `send` throws costs only its own session.

test("a socket whose send throws is faulted alone when another machine authenticates: the newcomer is welcomed", async () => {
  const r = rig();
  const a = r.open();
  await a.auth(A);
  a.kill();
  const b = r.open();
  await b.auth(B); // asserts B got its welcome; before the fix A's throw rejected B's auth and faulted B
  assert.deepEqual(b.closed, [], "B keeps its session");
  assert.deepEqual(a.closed, [1011], "A's session is faulted and closed even though its error frame could not be sent");
  assert.ok(r.log.some((e) => e.event === "session-fault" && e.kid === A.kid && e.message === "socket is gone"));
  assert.ok(!r.log.some((e) => e.event === "session-fault" && e.kid === B.kid));
  assert.deepEqual(b.presenceOf(), [[A.kid, "offline"]], "A's fault takes it offline for B");
  await b.frame({ type: "ping", id: "p" });
  assert.equal(b.sent.at(-1)!.type, "pong");
});

test("a mailbox wake that reaches a socket whose send throws closes that session and never rejects", async () => {
  const r = rig();
  const a = r.open(), b = r.open();
  await a.auth(A);
  await b.auth(B);
  a.kill();
  await b.frame({ type: "send", id: "s1", to: A.kid, msgId: "m-1", body: "AA", ttl: 60 });
  assert.ok(b.sent.some((f) => f.type === "accepted"), "B's message is stored");
  await r.settle();
  await r.hub.wake(A.kid); // resolves: the dead socket's fault is contained in its session
  assert.deepEqual(a.closed, [1011]);
  assert.deepEqual(b.closed, []);
  assert.ok(r.log.some((e) => e.event === "session-fault" && e.kid === A.kid));
});

test("the timer firing over a socket whose send throws closes that session, never rejects, and re-arms for the others", async () => {
  const r = rig();
  const b = r.open();
  await b.auth(B);
  const silent = r.open();
  silent.kill();
  r.at(10_001);
  await r.hub.onWake(); // the auth deadline refuses `silent`: its error frame throws
  assert.deepEqual(silent.closed, [4401], "the refusal still closes with its own code");
  assert.deepEqual(b.closed, []);
  assert.equal(r.armed.at(-1), T0 + 90_001, "the timer is armed again for B's idle deadline");
  // An admitted socket gone bad whose idle close announces it offline to another bad socket: still contained.
  const r2 = rig();
  const x = r2.open(), y = r2.open();
  await x.auth(A);
  await y.auth(B);
  r2.at(80_000);
  await y.frame({ type: "ping", id: "keep-y" }); // y stays fresh, x falls silent
  y.kill();
  r2.at(90_001);
  await r2.hub.onWake(); // x idles out; its offline frame to y throws
  assert.deepEqual([x.closed, y.closed], [[1001], [1011]]);
  assert.equal(r2.hub.nextWake(), undefined);
});

test("two concurrent stop() calls share one wait: both resolve when the transports report their close", async () => {
  const r = rig();
  const a = r.open(), b = r.open();
  await a.auth(A);
  await b.auth(B);
  const started = Date.now();
  const first = r.hub.stop({ graceMs: 10_000 });
  const second = r.hub.stop({ graceMs: 10_000 });
  a.gone();
  b.gone();
  const [one, two] = await Promise.all([first, second]);
  assert.ok(Date.now() - started < 1000, `both resolved in ${Date.now() - started} ms, not at the grace period`);
  assert.deepEqual([one.sessions, one.unclosed, two.sessions, two.unclosed], [2, [], 2, []]);
});

test("an admission refresh that succeeds without moving its deadline backs off instead of spinning the timer", async () => {
  let runs = 0;
  const r = rig({ refresh: { deadline: () => T0 + 1000, run: async () => { runs += 1; } } });
  r.at(1000);
  await r.hub.onWake();
  assert.equal(runs, 1);
  assert.equal(r.hub.nextWake(), T0 + 1000 + REFRESH_RETRY_MS, "a deadline still due after a run is not armed again at once");
  assert.equal(r.armed.at(-1), T0 + 1000 + REFRESH_RETRY_MS);
  assert.ok(r.log.some((e) => e.event === "refresh-stalled"));
  await r.hub.onWake();
  assert.equal(runs, 1, "no second run before the back-off");
  // A refresh that does move its deadline forward is armed at that deadline, with no back-off.
  let deadline = T0 + 20_000;
  const moving = rig({ refresh: { deadline: () => deadline, run: async () => { deadline += 60_000; } } });
  moving.at(20_000);
  await moving.hub.onWake();
  assert.equal(moving.hub.nextWake(), T0 + 80_000);
});

// Round 6: delivery is paced by the transport, outbound progress is liveness, and one machine holds a bounded number of
// sessions.

test("a flush stops while the transport is backlogged and goes on when it drains: every message once, in order", async () => {
  const mailbox = new MemoryMailbox();
  for (let n = 1; n <= 5; n += 1) await mailbox.append(A.kid, B.kid, `m-${n}`, "AA", 60, new Date(T0));
  const r = rig({ mailbox });
  let released = false;
  const delivered = () => a.sent.filter((f) => f.type === "deliver").map((f) => f.msgId);
  // The transport is full once two deliveries are queued in it, until it drains.
  const a = r.open({ backlogged: () => !released && delivered().length >= 2 });
  await a.auth(A);
  await r.settle();
  assert.deepEqual(delivered(), ["m-1", "m-2"], "nothing more while the transport is backlogged");
  released = true;
  await r.hub.drained(a.conn);
  await r.settle();
  assert.deepEqual(delivered(), ["m-1", "m-2", "m-3", "m-4", "m-5"]);
});

test("a flush pages the mailbox: it never asks for more than one page at a time", async () => {
  const inner = new MemoryMailbox();
  for (let n = 1; n <= 40; n += 1) await inner.append(A.kid, B.kid, `m-${n}`, "AA", 60, new Date(T0));
  const limits: Array<number | undefined> = [];
  const mailbox: MailboxStore = {
    append: (...args) => inner.append(...args),
    ack: (...args) => inner.ack(...args),
    pending: (to, now, after, limit) => { limits.push(limit); return inner.pending(to, now, after, limit); },
  };
  const r = rig({ mailbox });
  const a = r.open({ backlogged: () => false }); // a transport that reports its backlog: the small page
  await a.auth(A);
  await r.settle();
  assert.equal(a.sent.filter((f) => f.type === "deliver").length, 40);
  assert.ok(limits.length >= 2 && limits.every((l) => l !== undefined && l <= 4), JSON.stringify(limits));
});

test("only what the machine confirms is activity: a drain resumes delivery but keeps no session open; progressed does", async () => {
  const r = rig();
  const drained = r.open({ backlogged: () => true });
  const confirmed = r.open({ backlogged: () => true });
  await drained.auth(A);
  await confirmed.auth(B);
  r.at(80_000);
  await r.hub.drained(drained.conn); // the kernel took the relay's writes: not the peer confirming anything
  r.hub.progressed(confirmed.conn); // a pong matching one of the relay's pings: the peer read more
  r.at(90_001);
  await r.hub.onWake();
  assert.deepEqual([drained.closed, confirmed.closed], [[1001], []]);
  assert.equal(r.hub.session(confirmed.conn)!.nextDeadline(), T0 + 80_000 + 90_001);
});

test("one machine holds at most maxSessionsPerMachine sessions: the next is refused rate-limited and closed 1013", async () => {
  const r = rig({ maxSessionsPerMachine: 2 });
  const a1 = r.open(), a2 = r.open(), a3 = r.open(), b = r.open();
  await a1.auth(A);
  await a2.auth(A);
  await r.hub.receive(a3.conn, JSON.stringify(authFrame(A, { relay: ORIGIN, nonce: NONCE, at: T0, id: "a" })));
  assert.deepEqual([a3.sent.at(-1)!.type, a3.sent.at(-1)!.code, a3.closed], ["error", "rate-limited", [1013]]);
  assert.ok(r.log.some((e) => e.event === "session-limit" && e.kid === A.kid && e.limit === 2));
  await b.auth(B); // another machine is not counted against A
  a1.gone();
  const a4 = r.open();
  await a4.auth(A); // room again
  for (const f of a3.sent) assert.ok(frameValid(f), `${f.type}: ${JSON.stringify(frameValid.errors)}`);
});

// Round 7: an id the relay would echo is held to the schema's 128 characters, and the flush page fits the transport.

test("an id over 128 characters is refused malformed like any text that is not a fabric-relay/0.1 frame, and is never echoed", async () => {
  const r = rig();
  const a = r.open();
  await a.auth(A);
  const long = "i".repeat(129);
  for (const frame of [{ type: "ping", id: long }, { type: "send", id: long, to: B.kid, msgId: "m-1", body: "AA", ttl: 60 }, { type: "presence-query", id: long, kids: [B.kid] }, { type: "nope", id: long }, { type: "ping", id: "" }]) {
    const before = a.sent.length;
    await a.frame(frame);
    const replies = a.sent.slice(before);
    assert.deepEqual(replies.map((f) => [f.type, f.code, f.replyTo]), [["error", "malformed", undefined]], JSON.stringify(frame).slice(0, 80));
    assert.ok(!JSON.stringify(replies).includes(long), "the long id is not echoed");
  }
  assert.deepEqual(a.closed, [], "the session stays open, as for any frame that is not fabric-relay/0.1");
  await a.frame({ type: "ping", id: "i".repeat(128) });
  assert.deepEqual([a.sent.at(-1)!.type, a.sent.at(-1)!.replyTo.length], ["pong", 128], "128 characters is still an id");
  // Before auth, an over-long id is a first frame that is not an auth frame: refused unauthenticated, 4401.
  const b = r.open();
  await b.frame({ type: "auth", id: long });
  assert.deepEqual([b.sent.at(-1)!.code, b.closed], ["unauthenticated", [4401]]);
  assert.ok(!JSON.stringify(b.sent).includes(long));
  for (const f of [...a.sent, ...b.sent]) assert.ok(frameValid(f), `${f.type}: ${JSON.stringify(frameValid.errors)}`);
});

test("the flush page fits the transport: 4 where it reports a backlog, 64 where it cannot (the Worker)", async () => {
  for (const [backlog, page] of [[true, 4], [false, 64]] as const) {
    const inner = new MemoryMailbox();
    for (let n = 1; n <= 70; n += 1) await inner.append(A.kid, B.kid, `m-${n}`, "AA", 60, new Date(T0));
    const limits: Array<number | undefined> = [];
    const mailbox: MailboxStore = {
      append: (...args) => inner.append(...args),
      ack: (...args) => inner.ack(...args),
      pending: (to, now, after, limit) => { limits.push(limit); return inner.pending(to, now, after, limit); },
    };
    const r = rig({ mailbox });
    const a = r.open(backlog ? { backlogged: () => false } : {});
    await a.auth(A);
    await r.settle();
    assert.equal(a.sent.filter((f) => f.type === "deliver").length, 70);
    assert.ok(limits.every((l) => l === page), `${backlog}: ${JSON.stringify(limits)}`);
    assert.equal(limits.length, Math.ceil(70 / page) + (70 % page === 0 ? 1 : 0), `${backlog}: ${limits.length} mailbox calls`);
  }
});

// Round 8: msgId and body held to the schema, ids counted in code points, and no relay frame larger than a frame.

test("a send whose msgId is empty or over 128 code points, or whose body is not base64url, is refused malformed and never echoed", async () => {
  const r = rig();
  const a = r.open();
  await a.auth(A);
  const long = "m".repeat(129);
  for (const frame of [
    { type: "send", id: "s1", to: B.kid, msgId: long, body: "AA", ttl: 60 },
    { type: "send", id: "s2", to: B.kid, msgId: "", body: "AA", ttl: 60 },
    { type: "send", id: "s3", to: B.kid, msgId: "m-3", body: "not base64url!", ttl: 60 },
  ]) {
    const before = a.sent.length;
    await a.frame(frame);
    const replies = a.sent.slice(before);
    assert.deepEqual(replies.map((f) => [f.type, f.code, f.replyTo]), [["error", "malformed", frame.id]], JSON.stringify(frame).slice(0, 80));
    assert.ok(!JSON.stringify(replies).includes(long), "the long msgId is not echoed");
  }
  // 128 code points of a four-byte character is a valid msgId (and id): JSON Schema counts code points, not UTF-16 units.
  const emoji = "\u{1F600}".repeat(128);
  await a.frame({ type: "send", id: "\u{1F600}".repeat(100), to: B.kid, msgId: emoji, body: "AA", ttl: 60 });
  assert.deepEqual([a.sent.at(-1)!.type, a.sent.at(-1)!.msgId], ["accepted", emoji]);
  for (const f of a.sent) assert.ok(frameValid(f), `${f.type}: ${JSON.stringify(frameValid.errors)}`);
});

test("no frame the relay sends exceeds MAX_FRAME_BYTES: the largest send it accepts is delivered in one frame of at most 1 MiB", async () => {
  const r = rig();
  const a = r.open(), b = r.open();
  await a.auth(A);
  await b.auth(B);
  const bytes = (f: Record<string, unknown>) => Buffer.byteLength(JSON.stringify(f));
  // A send frame filled to the frame limit with its msgId: refused (msgId over 128), so its deliver, which carries more
  // than the send did, can never pass the limit.
  const body = "A".repeat(1000);
  const shell = { v: 1, type: "send", id: "big", to: B.kid, msgId: "", body, ttl: 60 };
  const msgId = "m".repeat(MAX_FRAME_BYTES - Buffer.byteLength(JSON.stringify(shell)) - 8);
  await a.frame({ type: "send", id: "big", to: B.kid, msgId, body, ttl: 60 });
  assert.deepEqual([a.sent.at(-1)!.type, a.sent.at(-1)!.code], ["error", "malformed"]);
  // The largest send the relay accepts: the largest body and a 128-code-point msgId of four-byte characters.
  const maxBody = "A".repeat(Math.floor((MAX_BODY_BYTES * 4) / 3));
  await a.frame({ type: "send", id: "max", to: B.kid, msgId: "\u{1F600}".repeat(128), body: maxBody, ttl: 60 });
  assert.equal(a.sent.at(-1)!.type, "accepted", JSON.stringify(a.sent.at(-1)).slice(0, 200));
  await r.settle();
  const deliver = b.sent.find((f) => f.type === "deliver" && f.body === maxBody)!;
  assert.ok(deliver, "delivered");
  assert.ok(bytes(deliver) <= MAX_FRAME_BYTES, `deliver is ${bytes(deliver)} bytes`);
  for (const f of [...a.sent, ...b.sent]) assert.ok(bytes(f) <= MAX_FRAME_BYTES, `${f.type} is ${bytes(f)} bytes`);
});

test("a send whose recipient is over 256 code points is refused malformed and never echoed", async () => {
  const r = rig();
  const a = r.open();
  await a.auth(A);
  // A machine's #sig key id, so FAC-SEM-071's own rule passes and only the length is wrong; the schema allows 256.
  const long = "k".repeat(253) + "#sig";
  for (const to of [long, "\u{1F600}".repeat(253) + "#sig"]) {
    const before = a.sent.length;
    await a.frame({ type: "send", id: "s1", to, msgId: "m-1", body: "AA", ttl: 60 });
    const replies = a.sent.slice(before);
    assert.deepEqual(replies.map((f) => [f.type, f.code]), [["error", "malformed"]], `to of ${to.length}`);
    assert.ok(!JSON.stringify(replies).includes(long), "the long recipient is not echoed");
  }
  // 256 code points (four-byte characters included) is a valid recipient: it is refused only as one the relay does not admit.
  await a.frame({ type: "send", id: "s2", to: "\u{1F600}".repeat(252) + "#sig", msgId: "m-2", body: "AA", ttl: 60 });
  assert.equal(a.sent.at(-1)!.code, "unknown-recipient");
});

test("a send whose msgId holds a control character (NUL) is refused malformed: no store truncates what accepted named", async () => {
  const r = rig();
  const a = r.open();
  await a.auth(A);
  for (const msgId of ["a\u0000b", "a\nb", "a\u007fb"]) {
    await a.frame({ type: "send", id: "s1", to: B.kid, msgId, body: "AA", ttl: 60 });
    assert.deepEqual([a.sent.at(-1)!.type, a.sent.at(-1)!.code], ["error", "malformed"], JSON.stringify(msgId));
  }
});

// Round 12.

test("a session with bytes outstanding to its machine is idle-closed after IDLE_OUTSTANDING_MS (5 min), not 90 s", async () => {
  const r = rig();
  let outstanding = true;
  const a = r.open({ outstanding: () => outstanding });
  const b = r.open();
  await a.auth(A);
  await b.auth(B);
  assert.equal(r.hub.session(a.conn)!.nextDeadline(), T0 + IDLE_OUTSTANDING_MS + 1);
  r.at(90_001);
  await r.hub.onWake();
  assert.deepEqual([a.closed, b.closed], [[], [1001]], "outstanding bytes: not idle yet; nothing outstanding: idle at 90 s");
  r.at(IDLE_OUTSTANDING_MS + 1);
  await r.hub.onWake();
  assert.deepEqual(a.closed, [1001], "a frozen peer is still freed within the bound");
  // Once nothing is outstanding, 90 s of silence is idle again.
  const c = r.open({ outstanding: () => outstanding });
  await c.auth(A);
  outstanding = false;
  r.at(IDLE_OUTSTANDING_MS + 1 + 90_001);
  await r.hub.onWake();
  assert.deepEqual(c.closed, [1001]);
});

test("progressedAll re-arms the hub's timer exactly once for many sessions, and not at all for none or unknown ones", async () => {
  const r = rig();
  const [a, b, c] = [r.open(), r.open(), r.open()];
  // Admitted at 0, 10 and 20 s: each one progressed in turn moves the earliest deadline, so arming per session would
  // arm three times.
  await a.auth(A);
  r.at(10_000);
  await b.auth(B);
  r.at(20_000);
  await c.auth(A);
  assert.equal(r.armed.at(-1), T0 + 90_001);
  r.at(30_000);
  const before = r.armed.length;
  r.hub.progressedAll([a.conn, b.conn, c.conn]);
  assert.equal(r.armed.length - before, 1, `${r.armed.length - before} arms`);
  assert.equal(r.armed.at(-1), T0 + 30_000 + 90_001, "armed at the new earliest deadline");
  const after = r.armed.length;
  r.hub.progressedAll([]);
  r.hub.progressedAll([{}, {}]);
  assert.equal(r.armed.length, after, "nothing progressed: no arm");
});

test("a msgId that is not well-formed UTF-16 (a lone surrogate) is refused malformed", async () => {
  const r = rig();
  const a = r.open();
  await a.auth(A);
  for (const msgId of ["a\uD800b", "\uDC00", "x\uD83D"]) {
    await a.frame({ type: "send", id: "s1", to: B.kid, msgId, body: "AA", ttl: 60 });
    assert.deepEqual([a.sent.at(-1)!.type, a.sent.at(-1)!.code], ["error", "malformed"], JSON.stringify(msgId));
  }
  await a.frame({ type: "send", id: "s2", to: B.kid, msgId: "\u{1F600}", body: "AA", ttl: 60 });
  assert.equal(a.sent.at(-1)!.type, "accepted", "a well-formed pair is a msgId");
});
