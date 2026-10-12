import assert from "node:assert/strict";
import { mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { DigestMismatch, getVerified, putVerified, sha256Digest } from "../src/core/digest.ts";
import { FsBlobStore, FsEstateSource } from "../src/portable/fs-store.ts";
import { SqliteMailbox } from "../src/portable/sqlite-mailbox.ts";
import { SqliteLastSeen } from "../src/portable/sqlite-last-seen.ts";
import { mkdir } from "node:fs/promises";
import { sign } from "node:crypto";
import { relayAuthSigningInput } from "../src/contract/relay.ts";
import { estate, revise } from "./estate-fixture.ts";
import { serve } from "../src/portable/server.ts";

const roots: string[] = [];
after(async () => {
  for (const root of roots) await rm(root, { recursive: true, force: true });
});
async function dataDir(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "relay-test-"));
  roots.push(root);
  return root;
}
const bytes = (text: string) => new TextEncoder().encode(text);

test("the file store round-trips a verified blob, owner-only, with no temporary file left", async () => {
  const dir = await dataDir();
  const store = new FsBlobStore(dir);
  const blob = bytes("package bytes");
  const digest = await sha256Digest(blob);
  await putVerified(store, digest, blob);
  assert.deepEqual(await getVerified(store, digest), blob);

  const folder = join(dir, "blobs", "sha256");
  assert.deepEqual(await readdir(folder), [digest.slice("sha256:".length)]);
  if (process.platform !== "win32") {
    assert.equal((await stat(folder)).mode & 0o777, 0o700);
    assert.equal((await stat(join(folder, digest.slice(7)))).mode & 0o777, 0o600);
  }
});

test("the file store answers null for a blob it does not hold and refuses a file edited on disk", async () => {
  const dir = await dataDir();
  const store = new FsBlobStore(dir);
  const digest = await sha256Digest(bytes("original"));
  assert.equal(await getVerified(store, digest), null);
  await putVerified(store, digest, bytes("original"));
  await writeFile(join(dir, "blobs", "sha256", digest.slice(7)), "tampered");
  await assert.rejects(getVerified(store, digest), DigestMismatch);
});

test("the file store will not build a path from anything but a digest", async () => {
  const store = new FsBlobStore(await dataDir());
  await assert.rejects(store.read("../../etc/passwd"), TypeError);
  await assert.rejects(store.write("sha256:../x", bytes("x")), TypeError);
});

test("the portable server routes through the same core: health, a non-upgrade connect refused, typed 404", async () => {
  const events: Record<string, unknown>[] = [];
  const { server, stop } = await serve(
    { runtime: "portable", blobs: new FsBlobStore(await dataDir()) },
    { host: "127.0.0.1", port: 0, log: (event) => events.push(event) },
  );
  try {
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const health = await fetch(`${base}/healthz`);
    assert.equal(health.status, 200);
    assert.equal((await health.json()).runtime, "portable");

    const connect = await fetch(`${base}/v1/connect`, { method: "POST", body: "hello" });
    assert.equal(connect.status, 405);
    assert.equal((await connect.json()).error.code, "method-not-allowed");

    const missing = await fetch(`${base}/nope`);
    assert.equal(missing.status, 404);
    await missing.body?.cancel();

    assert.deepEqual(events.filter((event) => event.event === "request").map((event) => [event.path, event.status]), [["/healthz", 200], ["/v1/connect", 405], ["/nope", 404]]);
    assert.ok(events.every((event) => !JSON.stringify(event).includes("hello")), "a request body never reaches the log");
  } finally {
    await stop({ graceMs: 100 });
  }
});

test("the portable server refuses a declared body over its limit before reading it", async () => {
  const { server, stop } = await serve({ runtime: "portable", blobs: new FsBlobStore(await dataDir()) }, { host: "127.0.0.1", port: 0 });
  try {
    const { port } = server.address() as AddressInfo;
    const response = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      import("node:http").then(({ request }) => {
        const req = request({ host: "127.0.0.1", port, path: "/v1/connect", method: "POST", headers: { "content-length": String(64 * 1024 * 1024) } }, (res) => {
          let body = "";
          res.on("data", (chunk) => (body += chunk));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
        });
        req.on("error", reject);
        req.end();
      }, reject);
    });
    assert.equal(response.status, 413);
    assert.equal(JSON.parse(response.body).error.code, "too-large");
  } finally {
    await stop({ graceMs: 100 });
  }
});

/** Opens a WebSocket to the relay and collects what it sends until it closes. */
function connect(url: string, protocols: string | string[] = "fabric-relay.v1") {
  const ws = new WebSocket(url, protocols);
  const frames: Array<Record<string, any>> = [];
  const waiters: Array<() => void> = [];
  let closed: { code: number } | undefined;
  ws.addEventListener("message", (event) => { frames.push(JSON.parse(String(event.data))); waiters.splice(0).forEach((w) => w()); });
  ws.addEventListener("close", (event) => { closed = { code: event.code }; waiters.splice(0).forEach((w) => w()); });
  ws.addEventListener("error", () => waiters.splice(0).forEach((w) => w()));
  const until = async (done: () => boolean, ms = 5000) => {
    const end = Date.now() + ms;
    while (!done() && Date.now() < end) await new Promise<void>((resolve) => { waiters.push(resolve); setTimeout(resolve, 50); });
    assert.ok(done(), `timed out: ${JSON.stringify({ frames, closed })}`);
  };
  return { ws, frames, until, closed: () => closed };
}

async function relayWithEstate(withEstate = true) {
  const root = await dataDir();
  const e = estate();
  if (withEstate) {
    await mkdir(join(root, "estate", "revisions"), { recursive: true });
    await writeFile(join(root, "estate", "pinned.json"), JSON.stringify(e.pinned));
    await writeFile(join(root, "estate", "revisions", "1.json"), JSON.stringify(e.record));
  }
  const events: Record<string, unknown>[] = [];
  const { server, stop } = await serve({ runtime: "portable", blobs: new FsBlobStore(root) }, { host: "127.0.0.1", port: 0, estate: new FsEstateSource(root), mailbox: new SqliteMailbox(join(root, "mailbox.sqlite")), lastSeen: new SqliteLastSeen(join(root, "presence.sqlite")), log: (event) => events.push(event) });
  const port = (server.address() as AddressInfo).port;
  return { server, stop, e, events, root, url: `ws://127.0.0.1:${port}/v1/connect`, origin: `http://127.0.0.1:${port}` };
}

const authFrame = (e: ReturnType<typeof estate>, origin: string, nonce: string, kid = e.machine.kid, privateKey = e.machine.privateKey) => {
  const iat = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const fields = { relay: origin, nonce, estate: "estate-5d0f1a", kid, iat };
  const sig = sign("sha256", Buffer.from(relayAuthSigningInput(fields)), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return JSON.stringify({ v: 1, type: "auth", id: "a1", protocol: "fabric-relay/0.1", alg: "ES256", ...fields, sig });
};

test("a machine of the verified estate record opens a session: hello, auth, welcome, ping/pong", async () => {
  const relay = await relayWithEstate();
  try {
    const c = connect(relay.url);
    await c.until(() => c.frames.length >= 1);
    assert.equal(c.ws.protocol, "fabric-relay.v1");
    const hello = c.frames[0]!;
    assert.deepEqual([hello.type, hello.relay], ["hello", relay.origin]);
    c.ws.send(authFrame(relay.e, relay.origin, hello.nonce));
    await c.until(() => c.frames.length >= 2);
    assert.deepEqual([c.frames[1]!.type, c.frames[1]!.estateRevision], ["welcome", 1]);
    c.ws.send(JSON.stringify({ v: 1, type: "ping", id: "p1" }));
    await c.until(() => c.frames.length >= 3);
    assert.deepEqual([c.frames[2]!.type, c.frames[2]!.id], ["pong", "p1"]);
    c.ws.close();
  } finally {
    await relay.stop({ graceMs: 100 });
  }
});

test("a machine the record does not list is refused 4403; with no estate at all, so is every machine", async () => {
  for (const withEstate of [true, false]) {
    const relay = await relayWithEstate(withEstate);
    try {
      const c = connect(relay.url);
      await c.until(() => c.frames.length >= 1);
      c.ws.send(authFrame(relay.e, relay.origin, c.frames[0]!.nonce, withEstate ? "m-stranger#sig" : relay.e.machine.kid));
      await c.until(() => c.closed() !== undefined);
      assert.equal(c.frames.at(-1)!.code, "not-admitted");
      assert.equal(c.closed()!.code, 4403);
    } finally {
      await relay.stop({ graceMs: 100 });
    }
  }
});

test("an upgrade that does not offer fabric-relay.v1 is refused before any session", async () => {
  const relay = await relayWithEstate();
  try {
    const c = connect(relay.url, "chat");
    await c.until(() => c.closed() !== undefined);
    assert.equal(c.frames.length, 0);
    assert.ok(relay.events.some((event) => event.event === "upgrade-refused" && event.status === 400));
  } finally {
    await relay.stop({ graceMs: 100 });
  }
});


test("two machines of the record exchange a message through the portable relay: send, accepted, deliver, ack", async () => {
  const relay = await relayWithEstate();
  try {
    const a = connect(relay.url), b = connect(relay.url);
    await a.until(() => a.frames.length >= 1);
    await b.until(() => b.frames.length >= 1);
    a.ws.send(authFrame(relay.e, relay.origin, a.frames[0]!.nonce));
    b.ws.send(authFrame(relay.e, relay.origin, b.frames[0]!.nonce, relay.e.second.kid, relay.e.second.privateKey));
    await a.until(() => a.frames.some((f) => f.type === "welcome"));
    await b.until(() => b.frames.some((f) => f.type === "welcome"));
    a.ws.send(JSON.stringify({ v: 1, type: "send", id: "s1", to: relay.e.second.kid, msgId: "m-1", body: "eyJoaSI6MX0", ttl: 600 }));
    await a.until(() => a.frames.some((f) => f.type === "accepted"));
    await b.until(() => b.frames.some((f) => f.type === "deliver"));
    const deliver = b.frames.find((f) => f.type === "deliver")!;
    assert.deepEqual([deliver.from, deliver.msgId, deliver.body], [relay.e.machine.kid, "m-1", "eyJoaSI6MX0"]);
    b.ws.send(JSON.stringify({ v: 1, type: "ack", id: "k1", seq: deliver.seq }));
    await new Promise((resolve) => setTimeout(resolve, 100));
    const box = new SqliteMailbox(join(relay.root, "mailbox.sqlite"));
    assert.deepEqual(await box.pending(relay.e.second.kid, new Date()), []);
    box.close();
    a.ws.close(); b.ws.close();
  } finally {
    await relay.stop({ graceMs: 100 });
  }
});

test("through the portable relay a machine sees another come online and go offline, and asks for it by kid", async () => {
  const relay = await relayWithEstate();
  try {
    const b = connect(relay.url);
    await b.until(() => b.frames.length >= 1);
    b.ws.send(authFrame(relay.e, relay.origin, b.frames[0]!.nonce, relay.e.second.kid, relay.e.second.privateKey));
    await b.until(() => b.frames.some((f) => f.type === "welcome"));
    const a = connect(relay.url);
    await a.until(() => a.frames.length >= 1);
    a.ws.send(authFrame(relay.e, relay.origin, a.frames[0]!.nonce));
    await b.until(() => b.frames.some((f) => f.type === "presence" && f.state === "online"));
    assert.equal(b.frames.find((f) => f.type === "presence")!.kid, relay.e.machine.kid);
    a.ws.close();
    await b.until(() => b.frames.some((f) => f.type === "presence" && f.state === "offline"));
    const offline = b.frames.find((f) => f.type === "presence" && f.state === "offline")!;
    b.ws.send(JSON.stringify({ v: 1, type: "presence-query", id: "q1", kids: [relay.e.machine.kid, "m-stranger#sig"] }));
    await b.until(() => b.frames.filter((f) => f.type === "presence").length >= 3);
    assert.deepEqual(b.frames.filter((f) => f.type === "presence").at(-1), { ...offline, id: b.frames.filter((f) => f.type === "presence").at(-1)!.id });
    b.ws.close();
  } finally {
    await relay.stop({ graceMs: 100 });
  }
});

test("the portable hub's one timer refuses a machine that never authenticates, 10 to 12 s after it opened", async () => {
  const relay = await relayWithEstate();
  try {
    const opened = Date.now(); // before the upgrade: the relay opens the session (and its 10 s deadline) after this
    const c = connect(relay.url);
    await c.until(() => c.frames.length >= 1);
    await c.until(() => c.closed() !== undefined, 15_000);
    const waited = Date.now() - opened;
    assert.deepEqual([c.frames.at(-1)!.code, c.closed()!.code], ["unauthenticated", 4401]);
    assert.ok(waited >= 10_000 && waited <= 12_000, `refused after ${waited} ms`);
  } finally {
    await relay.stop({ graceMs: 100 });
  }
});

/** Opens a session for `machine` and answers the revision `welcome` names. */
async function welcomeRevision(relay: Awaited<ReturnType<typeof relayWithEstate>>, machine = relay.e.machine) {
  const c = connect(relay.url);
  await c.until(() => c.frames.length >= 1);
  c.ws.send(authFrame(relay.e, relay.origin, c.frames[0]!.nonce, machine.kid, machine.privateKey));
  await c.until(() => c.frames.some((f) => f.type === "welcome" || f.type === "error"));
  c.ws.close();
  return c.frames.find((f) => f.type === "welcome")?.estateRevision as number | undefined;
}

test("a read that finds an older revision than the one held is not applied: the hub stays on the newer one", async () => {
  const relay = await relayWithEstate();
  try {
    await writeFile(join(relay.root, "estate", "revisions", "2.json"), JSON.stringify(revise(relay.e).record));
    assert.equal(await welcomeRevision(relay), 2);
    await rm(join(relay.root, "estate", "revisions", "2.json"));
    assert.equal(await welcomeRevision(relay), 2, "the read of revision 1 alone does not roll the hub back");
    assert.deepEqual(relay.events.filter((e) => e.event === "estate-rollback-refused").map((e) => [e.held, e.read]), [[2, 1]]);
  } finally {
    await relay.stop({ graceMs: 100 });
  }
});

test("a revision file that does not parse is refused like any bad revision: the ones before it still admit", async () => {
  const relay = await relayWithEstate();
  try {
    await writeFile(join(relay.root, "estate", "revisions", "2.json"), "{not json");
    assert.equal(await welcomeRevision(relay), 1);
    const refused = relay.events.find((e) => e.event === "estate-revision-refused") as { refused: Array<{ revision: number }> } | undefined;
    assert.deepEqual(refused?.refused.map((r) => r.revision), [2]);
  } finally {
    await relay.stop({ graceMs: 100 });
  }
});
