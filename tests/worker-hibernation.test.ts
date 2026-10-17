// The estate hub across a hibernation (RLY-014, ADR-0002), in workerd: Miniflare evicts the hub object with its
// sockets kept (`webSockets: "hibernate"`), so the next event reaches a new object that rebuilds its set from the
// sockets' attachments. Nothing in memory survives; what continues must have come from a session's record.
//
// Not tested here: the rebuild's answer to a socket with no record (error internal, then 1011). Every socket the hub
// accepts gets its record when `hello` is sent, before the 101 returns, so no socket without one can be made to
// hibernate from outside the Worker.
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import type { Miniflare } from "miniflare";
import { estate } from "./estate-fixture.ts";
import { authFrame as auth, placeEstate, session, startLoggedWorker } from "./worker-harness.ts";

let mf: Miniflare;
let events: (name: string) => Array<Record<string, any>>;
before(async () => { ({ mf, events } = await startLoggedWorker()); });
after(async () => { await mf?.dispose(); });

/** Evicts the estate hub object; its hibernatable sockets stay open. */
const hibernate = () => mf.unsafeEvictDurableObject("", "RelayEstate", { name: "estate", webSockets: "hibernate" });

test("a hibernation between frames: the session continues from its socket's attachment", async () => {
  const e = estate(new Date(), "ES256");
  const remove = await placeEstate(mf, e);
  const a = await session(mf);
  await a.until(() => a.frames.length >= 1);
  a.ws.send(auth(e.machine, a.frames[0]!.nonce));
  await a.until(() => a.frames.some((f) => f.type === "welcome"));
  await hibernate();
  a.ws.send(JSON.stringify({ v: 1, type: "ping", id: "p1" }));
  await a.until(() => a.frames.some((f) => f.type === "pong"));
  a.ws.send(JSON.stringify({ v: 1, type: "teleport", id: "t1" }));
  await a.until(() => a.frames.some((f) => f.type === "error"));
  // hello r1, welcome r2, the pong r3 (answering p1): the counter went on from the record, and the session is still
  // admitted, not refused.
  assert.deepEqual(a.frames.map((f) => [f.type, f.id, f.replyTo]), [["hello", "r1", undefined], ["welcome", "r2", undefined], ["pong", "r3", "p1"], ["error", "r4", "t1"]]);
  assert.equal(a.frames.at(-1)!.code, "unknown-type");
  await hibernate();
  a.ws.send(auth(e.machine, a.frames[0]!.nonce));
  await a.until(() => a.closed() !== undefined || a.frames.at(-1)!.code === "replay");
  assert.equal(a.frames.at(-1)!.code, "replay", "the nonce used before the hibernation is still used");
  await remove();
});

test("an estate that cannot be read after a wake loses no event: the alarm refuses, a ping is answered, a close is announced", async () => {
  const e = estate(new Date(), "ES256");
  const remove = await placeEstate(mf, e);
  const b = await session(mf);
  await b.until(() => b.frames.length >= 1);
  b.ws.send(auth(e.second, b.frames[0]!.nonce));
  await b.until(() => b.frames.some((f) => f.type === "welcome"));
  const a = await session(mf);
  await a.until(() => a.frames.length >= 1);
  a.ws.send(auth(e.machine, a.frames[0]!.nonce));
  await b.until(() => b.frames.some((f) => f.type === "presence" && f.kid === e.machine.kid && f.state === "online"));
  const silent = await session(mf);
  await silent.until(() => silent.frames.length >= 1);
  const opened = Date.now();
  const bucket = await mf.getR2Bucket("BLOBS");
  await bucket.put("estate/revisions/2.json", "{not json");
  await hibernate();
  a.ws.send(JSON.stringify({ v: 1, type: "ping", id: "p1" }));
  await a.until(() => a.frames.some((f) => f.type === "pong") || (a.frames.at(-1)!.code === "internal"));
  assert.equal(a.frames.at(-1)!.type, "pong", JSON.stringify(a.frames.at(-1)));
  a.ws.close(1000, "done");
  await b.until(() => b.frames.some((f) => f.type === "presence" && f.kid === e.machine.kid && f.state === "offline"));
  await silent.until(() => silent.frames.some((f) => f.type === "error"), 15_000);
  assert.equal(silent.frames.at(-1)!.code, "unauthenticated");
  assert.ok(Date.now() - opened < 14_000, `refused after ${Date.now() - opened} ms`);
  b.ws.close(1000, "done");
  await bucket.delete("estate/revisions/2.json");
  await remove();
});

test("an estate read that fails after a wake loses no event; presence is withheld until a read succeeds, and lastSeen is kept", async () => {
  const e = estate(new Date(), "ES256");
  const remove = await placeEstate(mf, e);
  const b = await session(mf);
  await b.until(() => b.frames.length >= 1);
  b.ws.send(auth(e.second, b.frames[0]!.nonce));
  await b.until(() => b.frames.some((f) => f.type === "welcome"));
  const a = await session(mf);
  await a.until(() => a.frames.length >= 1);
  a.ws.send(auth(e.machine, a.frames[0]!.nonce));
  await b.until(() => b.frames.some((f) => f.type === "presence" && f.kid === e.machine.kid && f.state === "online"));
  const silent = await session(mf);
  await silent.until(() => silent.frames.length >= 1);
  const opened = Date.now();
  const bucket = await mf.getR2Bucket("BLOBS");
  await bucket.put("estate/pinned.json", "{not json"); // the whole read throws, not one revision
  const unreadableBefore = events("estate-unreadable").length;
  await hibernate();
  // A frame still reaches its session.
  a.ws.send(JSON.stringify({ v: 1, type: "ping", id: "p1" }));
  await a.until(() => a.frames.some((f) => f.type === "pong"));
  assert.ok(events("estate-unreadable").length > unreadableBefore, "the failed read is logged");
  // A close still ends the session; with no estate held the relay admits nobody, so nobody is told.
  const closedAt = Date.now();
  a.ws.close(1000, "done");
  await new Promise((resolve) => setTimeout(resolve, 500));
  assert.ok(!b.frames.some((f) => f.type === "presence" && f.kid === e.machine.kid && f.state === "offline"), "presence is withheld");
  // The alarm still ticks.
  await silent.until(() => silent.frames.some((f) => f.type === "error"), 15_000);
  assert.equal(silent.frames.at(-1)!.code, "unauthenticated");
  assert.ok(Date.now() - opened < 14_000, `refused after ${Date.now() - opened} ms`);
  // Once the estate reads again (a new connection reads it), the lastSeen written while it could not be read answers.
  await placeEstate(mf, e);
  const reader = await session(mf);
  await reader.until(() => reader.frames.length >= 1);
  b.ws.send(JSON.stringify({ v: 1, type: "presence-query", id: "q1", kids: [e.machine.kid] }));
  await b.until(() => b.frames.some((f) => f.type === "presence-result"));
  const answered = b.frames.find((f) => f.type === "presence-result")!.presences.find((p: Record<string, string>) => p.kid === e.machine.kid);
  assert.equal(answered.state, "offline");
  assert.ok(Date.parse(answered.lastSeen) >= closedAt - 1000, `lastSeen ${answered.lastSeen} is the close`);
  for (const c of [b, reader]) c.ws.close(1000, "done");
  await remove();
});

test("round 8: sessions restored after a wake count against the 8-session limit: the ninth after a hibernation is refused 1013", async () => {
  const e = estate(new Date(), "ES256");
  const remove = await placeEstate(mf, e);
  const open = async () => {
    const s = await session(mf);
    await s.until(() => s.frames.length >= 1);
    s.ws.send(auth(e.machine, s.frames[0]!.nonce));
    await s.until(() => s.frames.some((f) => f.type === "welcome" || f.type === "error"));
    return s;
  };
  const sessions = [];
  for (let n = 0; n < 8; n += 1) sessions.push(await open());
  assert.ok(sessions.every((s) => s.frames.some((f) => f.type === "welcome")));
  await hibernate();
  const ninth = await open();
  await ninth.until(() => ninth.closed() !== undefined);
  assert.deepEqual([ninth.frames.at(-1)!.type, ninth.frames.at(-1)!.code, ninth.closed()], ["error", "rate-limited", 1013]);
  for (const s of sessions) s.ws.close(1000, "done");
  await remove();
});
