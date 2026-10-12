// The hosted build, run in workerd through Miniflare with no network: the bundle `npm run build:worker`
// writes, its Durable Object and R2 bindings local.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import { Miniflare } from "miniflare";
import { createHash, sign as signBytes } from "node:crypto";
import { relayAuthSigningInput, relayBlobSigningInput, relayRequestHeader } from "../src/contract/relay.ts";
import { estate } from "./estate-fixture.ts";

const SCRIPT = "dist/worker/worker.js";
// The same date the deployment uses: wrangler.jsonc is the one place it is set.
const CONFIG = JSON.parse(readFileSync("wrangler.jsonc", "utf8").replace(/^\s*\/\/.*$/gm, "")) as { compatibility_date: string; compatibility_flags: string[] };
let mf: Miniflare;

before(async () => {
  assert.ok(existsSync(SCRIPT), `${SCRIPT} is missing: run npm run build:worker (npm test does)`);
  mf = new Miniflare({
    modules: true,
    scriptPath: SCRIPT,
    compatibilityDate: CONFIG.compatibility_date,
    compatibilityFlags: CONFIG.compatibility_flags,
    durableObjects: { SESSIONS: { className: "RelaySession", useSQLite: true }, MAILBOX: { className: "RelayMailbox", useSQLite: true } },
    r2Buckets: ["BLOBS"],
  });
  await mf.ready;
});
after(async () => {
  await mf?.dispose();
});

test("the Worker answers health as the cloudflare runtime", async () => {
  const response = await mf.dispatchFetch("http://relay.test/healthz");
  assert.equal(response.status, 200);
  const body = (await response.json()) as { runtime: string; protocol: { decision: string }; ready: boolean };
  assert.equal(body.runtime, "cloudflare");
  assert.equal(body.protocol.decision, "DEC-0047");
  assert.equal(body.ready, true);
});

test("the Worker and its session object refuse anything but a fabric-relay.v1 upgrade", async () => {
  const plain = await mf.dispatchFetch("http://relay.test/v1/connect");
  assert.equal(plain.status, 426);
  await plain.arrayBuffer();
  const namespace = await mf.getDurableObjectNamespace("SESSIONS");
  const stub = namespace.get(namespace.newUniqueId());
  const noProtocol = await stub.fetch("http://relay.test/v1/connect", { headers: { upgrade: "websocket" } });
  assert.equal(noProtocol.status, 400);
  assert.equal(((await noProtocol.json()) as { error: { code: string } }).error.code, "protocol-unsupported");
});

async function session(relayOrigin = "http://relay.test") {
  const response = await mf.dispatchFetch(`${relayOrigin}/v1/connect`, { headers: { upgrade: "websocket", "sec-websocket-protocol": "fabric-relay.v1" } });
  assert.equal(response.status, 101);
  const ws = response.webSocket!;
  const frames: Array<Record<string, any>> = [];
  let closed: number | undefined;
  ws.addEventListener("message", (event) => frames.push(JSON.parse(String(event.data))));
  ws.addEventListener("close", (event) => { closed = event.code; });
  ws.accept();
  const until = async (done: () => boolean) => {
    const end = Date.now() + 5000;
    while (!done() && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.ok(done(), JSON.stringify({ frames, closed }));
  };
  return { ws, frames, until, closed: () => closed };
}

for (const passkey of ["EdDSA", "ES256"] as const) test(`a machine of an estate record signed by an ${passkey} passkey, in R2, opens a session: hello, auth, welcome, ping/pong`, async () => {
  const e = estate(new Date(), passkey);
  const bucket = await mf.getR2Bucket("BLOBS");
  await bucket.put("estate/pinned.json", JSON.stringify(e.pinned));
  await bucket.put("estate/revisions/1.json", JSON.stringify(e.record));
  const c = await session();
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

  const stranger = await session();
  await stranger.until(() => stranger.frames.length >= 1);
  stranger.ws.send(sign("m-stranger#sig", stranger.frames[0]!.nonce));
  await stranger.until(() => stranger.closed() !== undefined);
  assert.deepEqual([stranger.frames.at(-1)!.code, stranger.closed()], ["not-admitted", 4403]);
  await bucket.delete(["estate/pinned.json", "estate/revisions/1.json"]);
});

test("the R2 binding the blob store uses exists in the bundle's bindings", async () => {
  const bucket = await mf.getR2Bucket("BLOBS");
  assert.equal(await bucket.get("sha256:" + "0".repeat(64)), null);
});

test("two machines of the record exchange a message through the Worker: send, accepted, deliver, ack", async () => {
  const e = estate(new Date(), "ES256");
  const bucket = await mf.getR2Bucket("BLOBS");
  await bucket.put("estate/pinned.json", JSON.stringify(e.pinned));
  await bucket.put("estate/revisions/1.json", JSON.stringify(e.record));
  const iat = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const auth = (m: { kid: string; privateKey: import("node:crypto").KeyObject }, nonce: string) => {
    const fields = { relay: "http://relay.test", nonce, estate: "estate-5d0f1a", kid: m.kid, iat };
    const sig = signBytes("sha256", Buffer.from(relayAuthSigningInput(fields)), { key: m.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    return JSON.stringify({ v: 1, type: "auth", id: "a1", protocol: "fabric-relay/0.1", alg: "ES256", ...fields, sig });
  };
  const a = await session(), b = await session();
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
  const again = await session();
  await again.until(() => again.frames.length >= 1);
  again.ws.send(auth(e.second, again.frames[0]!.nonce));
  await again.until(() => again.frames.some((f) => f.type === "welcome"));
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(again.frames.filter((f) => f.type === "deliver").length, 0);
  for (const c of [a, b, again]) c.ws.close(1000, "done");
  await bucket.delete(["estate/pinned.json", "estate/revisions/1.json"]);
});


test("a blob goes through the Worker: PUT by one machine of the record, GET by its recipient, then it is gone", async () => {
  const e = estate(new Date(), "ES256");
  const bucket = await mf.getR2Bucket("BLOBS");
  await bucket.put("estate/pinned.json", JSON.stringify(e.pinned));
  await bucket.put("estate/revisions/1.json", JSON.stringify(e.record));
  const bytes = new TextEncoder().encode("sealed envelope bytes");
  const digest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  const header = (m: { kid: string; privateKey: import("node:crypto").KeyObject }, method: "PUT" | "GET") => {
    const iat = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const recipients = [e.second.kid];
    const sig = signBytes("sha256", Buffer.from(relayBlobSigningInput({ relay: "http://relay.test", method, digest, recipients, iat })), { key: m.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    return relayRequestHeader({ alg: "ES256", kid: m.kid, recipients, iat, sig });
  };
  const put = await mf.dispatchFetch(`http://relay.test/v1/blobs/${digest}`, { method: "PUT", body: bytes, headers: { "Fabric-Relay-Request": header(e.machine, "PUT") } });
  assert.equal(put.status, 201, await put.text());
  const got = await mf.dispatchFetch(`http://relay.test/v1/blobs/${digest}`, { headers: { "Fabric-Relay-Request": header(e.second, "GET") } });
  assert.equal(got.status, 200);
  assert.deepEqual(new Uint8Array(await got.arrayBuffer()), bytes);
  assert.equal(await bucket.get(digest), null);
  assert.equal(await bucket.get(`blobindex/${digest}`), null);
  const stranger = await mf.dispatchFetch(`http://relay.test/v1/blobs/${digest}`, { headers: { "Fabric-Relay-Request": header(e.machine, "GET") } });
  assert.equal(stranger.status, 403);
  await stranger.arrayBuffer();
  await bucket.delete(["estate/pinned.json", "estate/revisions/1.json"]);
});
