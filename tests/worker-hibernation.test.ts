// The estate hub across a hibernation (RLY-014, ADR-0002), in workerd: Miniflare evicts the hub object with its
// sockets kept (`webSockets: "hibernate"`), so the next event reaches a new object that rebuilds its set from the
// sockets' attachments. Nothing in memory survives; what continues must have come from a session's record.
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import type { Miniflare } from "miniflare";
import { estate } from "./estate-fixture.ts";
import { authFrame as auth, placeEstate, session, startWorker } from "./worker-harness.ts";

let mf: Miniflare;
before(async () => { mf = await startWorker(); });
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
  // hello r1, welcome r2, the pong r3 (sent under the ping's id): the counter went on from the record, and the session
  // is still admitted, not refused.
  assert.deepEqual(a.frames.map((f) => [f.type, f.id]), [["hello", "r1"], ["welcome", "r2"], ["pong", "p1"], ["error", "r4"]]);
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
