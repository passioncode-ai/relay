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

test("a deploy drops every socket without a close: after the restart, a machine that reconnects is announced online again", async () => {
  const { mkdtemp, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "relay-deploy-"));
  const persist = { durableObjectsPersist: join(dir, "do"), r2Persist: join(dir, "r2") };
  const workers: Miniflare[] = [];
  try {
    const e = estate(new Date(), "ES256");
    const first = await startWorker(persist);
    workers.push(first);
    await placeEstate(first, e);
    // B first, admitted, then A: B is told A came online (a machine is told only while it is admitted).
    const b0 = await session(first);
    await b0.until(() => b0.frames.length >= 1);
    b0.ws.send(auth(e.second, b0.frames[0]!.nonce));
    await b0.until(() => b0.frames.some((f) => f.type === "welcome"));
    const a0 = await session(first);
    await a0.until(() => a0.frames.length >= 1);
    a0.ws.send(auth(e.machine, a0.frames[0]!.nonce));
    await b0.until(() => b0.frames.some((f) => f.type === "presence" && f.kid === e.machine.kid && f.state === "online"));
    const seen = b0.frames.find((f) => f.type === "presence" && f.kid === e.machine.kid)!.lastSeen;
    await workers.pop()!.dispose(); // every object restarts, every socket drops, no close event reaches the relay
    const second = await startWorker(persist);
    workers.push(second);
    const b = await session(second);
    await b.until(() => b.frames.length >= 1);
    b.ws.send(auth(e.second, b.frames[0]!.nonce));
    await b.until(() => b.frames.some((f) => f.type === "welcome"));
    // lastSeen survived the restart in the hub's storage; who was connected did not.
    b.ws.send(JSON.stringify({ v: 1, type: "presence-query", id: "q1", kids: [e.machine.kid] }));
    await b.until(() => b.frames.some((f) => f.type === "presence"));
    const answered = b.frames.find((f) => f.type === "presence")!;
    assert.deepEqual([answered.kid, answered.state, answered.lastSeen], [e.machine.kid, "offline", seen]);
    const a = await session(second);
    await a.until(() => a.frames.length >= 1);
    a.ws.send(auth(e.machine, a.frames[0]!.nonce));
    await b.until(() => b.frames.some((f) => f.type === "presence" && f.kid === e.machine.kid && f.state === "online"));
    for (const c of [a, b]) c.ws.close(1000, "done");
  } finally {
    for (const worker of workers) await worker.dispose();
    await rm(dir, { recursive: true, force: true });
  }
});

test("structural (RLY-014): the hosted relay accepts sockets through the Hibernation API, with no interval and no accept()", async () => {
  const { readFileSync, readdirSync } = await import("node:fs");
  const sources = Object.fromEntries(readdirSync("src/cloudflare").filter((f) => f.endsWith(".ts")).map((f) => [f, readFileSync(`src/cloudflare/${f}`, "utf8")]));
  const all = Object.values(sources).join("\n");
  assert.match(sources["estate.ts"] ?? "", /ctx\.acceptWebSocket\(/, "estate.ts accepts sockets through the Hibernation API");
  assert.doesNotMatch(all, /setInterval\(/, "a timer keeps a Durable Object from hibernating");
  assert.doesNotMatch(all, /\.accept\(\)/, "server.accept() holds the socket outside the Hibernation API");
  assert.doesNotMatch(all, /newUniqueId\(/, "no object per connection");
});

test("a socket that never authenticates is refused by the hub's alarm about 10 s after it opened, and admits nobody after", async () => {
  // Measured 2026-10-12 (miniflare 4.20260730.0): a close the hub sends from alarm() reaches the runtime (it reports the
  // socket closed, code 4401) but this local bridge does not hand the close frame to the test's client until dispose,
  // while a close sent from webSocketMessage arrives at once. So the test asserts what the relay controls: the alarm's
  // refusal frame, on time, and a closed session. The deployed close is checked after the first deploy (F-8).
  const e = estate(new Date(), "ES256");
  const remove = await placeEstate(mf, e);
  const c = await session(mf);
  await c.until(() => c.frames.length >= 1);
  const opened = Date.now();
  await c.until(() => c.frames.some((f) => f.type === "error"), 15_000);
  const waited = Date.now() - opened;
  assert.deepEqual([c.frames.at(-1)!.code, c.frames.at(-1)!.message], ["unauthenticated", "no auth within 10 s"]);
  assert.ok(waited >= 9_000 && waited < 14_000, `refused after ${waited} ms`);
  c.ws.send(auth(e.machine, c.frames[0]!.nonce));
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(c.frames.filter((f) => f.type === "welcome").length, 0, "a refused session admits nobody");
  await remove();
});
