// The hosted build's presence, in workerd (tests/worker-harness.ts).
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import type { Miniflare } from "miniflare";
import { estate } from "./estate-fixture.ts";
import { authFrame as auth, placeEstate, session, startWorker } from "./worker-harness.ts";

let mf: Miniflare;
before(async () => { mf = await startWorker(); });
after(async () => { await mf?.dispose(); });

test("through the Worker a machine sees another come online and go offline, and asks for it by kid", async () => {
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
  a.ws.close(1000, "done");
  await b.until(() => b.frames.some((f) => f.type === "presence" && f.kid === e.machine.kid && f.state === "offline"));
  b.ws.send(JSON.stringify({ v: 1, type: "presence-query", id: "q1", kids: [e.machine.kid, e.second.kid, "m-stranger#sig"] }));
  await b.until(() => b.frames.filter((f) => f.type === "presence").length >= 4);
  const answered = b.frames.filter((f) => f.type === "presence").slice(-2).map((f) => [f.kid, f.state]);
  assert.deepEqual(answered, [[e.machine.kid, "offline"], [e.second.kid, "online"]]);
  b.ws.close(1000, "done");
  await remove();
});
