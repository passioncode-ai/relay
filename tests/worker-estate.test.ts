// The hosted build's routes and admission, in workerd (tests/worker-harness.ts).
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import type { Miniflare } from "miniflare";
import { sign as signBytes } from "node:crypto";
import { relayAuthSigningInput } from "../src/contract/relay.ts";
import { estate, revise } from "./estate-fixture.ts";
import { authFrame, session, startLoggedWorker } from "./worker-harness.ts";

let mf: Miniflare;
let events: (name: string) => Array<Record<string, any>>;
before(async () => { ({ mf, events } = await startLoggedWorker()); });
after(async () => { await mf?.dispose(); });

test("the Worker answers health as the cloudflare runtime", async () => {
  const response = await mf.dispatchFetch("http://relay.test/healthz");
  assert.equal(response.status, 200);
  const body = (await response.json()) as { runtime: string; protocol: { decision: string }; ready: boolean };
  assert.equal(body.runtime, "cloudflare");
  assert.equal(body.protocol.decision, "DEC-0047");
  assert.equal(body.ready, true);
});

test("the Worker and its estate hub object refuse anything but a fabric-relay.v1 upgrade", async () => {
  const plain = await mf.dispatchFetch("http://relay.test/v1/connect");
  assert.equal(plain.status, 426);
  await plain.arrayBuffer();
  const namespace = await mf.getDurableObjectNamespace("ESTATE");
  const stub = namespace.get(namespace.idFromName("estate"));
  const noProtocol = await stub.fetch("http://relay.test/v1/connect", { headers: { upgrade: "websocket" } });
  assert.equal(noProtocol.status, 400);
  assert.equal(((await noProtocol.json()) as { error: { code: string } }).error.code, "protocol-unsupported");
});

for (const passkey of ["EdDSA", "ES256"] as const) test(`a machine of an estate record signed by an ${passkey} passkey, in R2, opens a session: hello, auth, welcome, ping/pong`, async () => {
  const e = estate(new Date(), passkey);
  const bucket = await mf.getR2Bucket("BLOBS");
  await bucket.put("estate/pinned.json", JSON.stringify(e.pinned));
  await bucket.put("estate/revisions/1.json", JSON.stringify(e.record));
  const c = await session(mf);
  await c.until(() => c.frames.length >= 1);
  const hello = c.frames[0]!;
  assert.deepEqual([hello.type, hello.relay], ["hello", "http://relay.test"]);
  const iat = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const sign = (kid: string, nonce: string) => {
    const fields = { relay: "http://relay.test", nonce, estate: "estate-5d0f1a", kid, iat };
    const sig = signBytes("sha256", Buffer.from(relayAuthSigningInput(fields)), { key: e.machine.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    return JSON.stringify({ v: 1, type: "auth", id: "a1", protocol: "fabric-relay/0.1", alg: "ES256", ...fields, sig });
  };
  c.ws.send(sign(e.machine.kid, hello.nonce));
  await c.until(() => c.frames.length >= 2);
  assert.deepEqual([c.frames[1]!.type, c.frames[1]!.estateRevision], ["welcome", 1]);
  c.ws.send(JSON.stringify({ v: 1, type: "ping", id: "p1" }));
  await c.until(() => c.frames.length >= 3);
  assert.deepEqual([c.frames[2]!.type, c.frames[2]!.id], ["pong", "p1"]);
  c.ws.close(1000, "done");

  const stranger = await session(mf);
  await stranger.until(() => stranger.frames.length >= 1);
  stranger.ws.send(sign("m-stranger#sig", stranger.frames[0]!.nonce));
  await stranger.until(() => stranger.closed() !== undefined);
  assert.deepEqual([stranger.frames.at(-1)!.code, stranger.closed()], ["not-admitted", 4403]);
  await bucket.delete(["estate/pinned.json", "estate/revisions/1.json"]);
});

test("a read that finds an older revision than the one held is not applied: the hub stays on the newer one", async () => {
  const e = estate(new Date(), "ES256");
  const bucket = await mf.getR2Bucket("BLOBS");
  await bucket.put("estate/pinned.json", JSON.stringify(e.pinned));
  await bucket.put("estate/revisions/1.json", JSON.stringify(e.record));
  await bucket.put("estate/revisions/2.json", JSON.stringify(revise(e).record));
  const welcomed = async () => {
    const c = await session(mf);
    await c.until(() => c.frames.length >= 1);
    c.ws.send(authFrame(e.machine, c.frames[0]!.nonce));
    await c.until(() => c.frames.some((f) => f.type === "welcome" || f.type === "error"));
    c.ws.close(1000, "done");
    return c.frames.find((f) => f.type === "welcome")?.estateRevision;
  };
  assert.equal(await welcomed(), 2);
  await bucket.delete("estate/revisions/2.json");
  const before = events("estate-rollback-refused").length;
  assert.equal(await welcomed(), 2, "the read of revision 1 alone does not roll the hub back");
  assert.deepEqual(events("estate-rollback-refused").slice(before).map((l) => [l.held, l.read]), [[2, 1]]);
  await bucket.delete(["estate/pinned.json", "estate/revisions/1.json"]);
});
