// The hosted build's store-and-forward: sessions and the per-recipient mailbox objects, in workerd
// (tests/worker-harness.ts).
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import type { Miniflare } from "miniflare";
import { estate } from "./estate-fixture.ts";
import { authFrame as auth, placeEstate, session, startWorker } from "./worker-harness.ts";

let mf: Miniflare;
before(async () => { mf = await startWorker(); });
after(async () => { await mf?.dispose(); });

test("two machines of the record exchange a message through the Worker: send, accepted, deliver, ack", async () => {
  const e = estate(new Date(), "ES256");
  const remove = await placeEstate(mf, e);
  const a = await session(mf), b = await session(mf);
  await a.until(() => a.frames.length >= 1);
  await b.until(() => b.frames.length >= 1);
  a.ws.send(auth(e.machine, a.frames[0]!.nonce));
  b.ws.send(auth(e.second, b.frames[0]!.nonce));
  await a.until(() => a.frames.some((f) => f.type === "welcome"));
  await b.until(() => b.frames.some((f) => f.type === "welcome"));
  a.ws.send(JSON.stringify({ v: 1, type: "send", id: "s1", to: e.second.kid, msgId: "m-1", body: "eyJoaSI6MX0", ttl: 600 }));
  await a.until(() => a.frames.some((f) => f.type === "accepted"));
  assert.equal(a.frames.find((f) => f.type === "accepted")!.seq, 1);
  await b.until(() => b.frames.some((f) => f.type === "deliver"));
  const deliver = b.frames.find((f) => f.type === "deliver")!;
  assert.deepEqual([deliver.from, deliver.msgId, deliver.seq, deliver.body], [e.machine.kid, "m-1", 1, "eyJoaSI6MX0"]);
  b.ws.send(JSON.stringify({ v: 1, type: "ack", id: "k1", seq: 1 }));
  // A later connection of B finds nothing waiting: the ack deleted it in the mailbox object.
  await new Promise((resolve) => setTimeout(resolve, 200));
  const again = await session(mf);
  await again.until(() => again.frames.length >= 1);
  again.ws.send(auth(e.second, again.frames[0]!.nonce));
  await again.until(() => again.frames.some((f) => f.type === "welcome"));
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(again.frames.filter((f) => f.type === "deliver").length, 0);
  for (const c of [a, b, again]) c.ws.close(1000, "done");
  await remove();
});

test("a message queued for a machine that is offline is delivered when it connects; one queued while it is online wakes the hub", async () => {
  const e = estate(new Date(), "ES256");
  const remove = await placeEstate(mf, e);
  const a = await session(mf);
  await a.until(() => a.frames.length >= 1);
  a.ws.send(auth(e.machine, a.frames[0]!.nonce));
  await a.until(() => a.frames.some((f) => f.type === "welcome"));
  a.ws.send(JSON.stringify({ v: 1, type: "send", id: "s1", to: e.second.kid, msgId: "offline-1", body: "AA", ttl: 600 }));
  await a.until(() => a.frames.some((f) => f.type === "accepted"));
  const b = await session(mf);
  await b.until(() => b.frames.length >= 1);
  b.ws.send(auth(e.second, b.frames[0]!.nonce));
  await b.until(() => b.frames.some((f) => f.type === "deliver" && f.msgId === "offline-1"));
  a.ws.send(JSON.stringify({ v: 1, type: "send", id: "s2", to: e.second.kid, msgId: "online-1", body: "AA", ttl: 600 }));
  await b.until(() => b.frames.some((f) => f.type === "deliver" && f.msgId === "online-1"));
  assert.deepEqual(b.frames.filter((f) => f.type === "deliver").map((f) => f.msgId), ["offline-1", "online-1"]);
  for (const c of [a, b]) c.ws.close(1000, "done");
  await remove();
});

test("structural: a mailbox wakes the hub in the background (ctx.waitUntil), so a sender's accepted never waits on another machine's delivery", async () => {
  // Measured: a hub that is slow or failing cannot be produced from outside the Worker without a test hook, so the
  // seam is checked in the source; with the wake awaited instead, this test fails.
  const { readFileSync } = await import("node:fs");
  const source = readFileSync("src/cloudflare/mailbox.ts", "utf8");
  const append = source.slice(source.indexOf("async append("), source.indexOf("async pending("));
  assert.match(append, /this\.ctx\.waitUntil\(this\.env\.ESTATE\.get\(/);
  assert.doesNotMatch(append, /await this\.env\.ESTATE/);
});

test("round 7: a backlog of 70 messages crosses a flush page in the Worker: each delivered once, in seq order", async () => {
  const e = estate(new Date(), "ES256");
  const remove = await placeEstate(mf, e);
  const a = await session(mf);
  await a.until(() => a.frames.length >= 1);
  a.ws.send(auth(e.machine, a.frames[0]!.nonce));
  await a.until(() => a.frames.some((f) => f.type === "welcome"));
  for (let n = 1; n <= 70; n += 1) a.ws.send(JSON.stringify({ v: 1, type: "send", id: `s${n}`, to: e.second.kid, msgId: `page-${n}`, body: "AA", ttl: 600 }));
  await a.until(() => a.frames.filter((f) => f.type === "accepted").length === 70, 15_000);
  const b = await session(mf);
  await b.until(() => b.frames.length >= 1);
  b.ws.send(auth(e.second, b.frames[0]!.nonce));
  // The Worker is shared by this file's tests and the second machine's mailbox may still hold their messages: count ours.
  const ours = () => b.frames.filter((f) => f.type === "deliver" && String(f.msgId).startsWith("page-"));
  await b.until(() => ours().length >= 70, 15_000);
  await new Promise((resolve) => setTimeout(resolve, 300));
  const delivered = ours();
  assert.deepEqual(delivered.map((f) => f.msgId), Array.from({ length: 70 }, (_, n) => `page-${n + 1}`));
  assert.deepEqual(delivered.map((f) => f.seq), [...delivered.map((f) => f.seq)].sort((x, y) => x - y));
  for (const c of [a, b]) c.ws.close(1000, "done");
  await remove();
});

test("round 7: in the Worker one machine holds at most 8 sessions: the ninth gets rate-limited and 1013, and a slot frees on close", async () => {
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
  const ninth = await open();
  await ninth.until(() => ninth.closed() !== undefined);
  assert.deepEqual([ninth.frames.at(-1)!.type, ninth.frames.at(-1)!.code, ninth.closed()], ["error", "rate-limited", 1013]);
  sessions[0]!.ws.close(1000, "done");
  await new Promise((resolve) => setTimeout(resolve, 300));
  const again = await open();
  assert.ok(again.frames.some((f) => f.type === "welcome"), JSON.stringify(again.frames));
  for (const s of [...sessions.slice(1), again]) s.ws.close(1000, "done");
  await remove();
});
