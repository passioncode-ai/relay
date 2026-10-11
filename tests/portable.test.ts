import assert from "node:assert/strict";
import { mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { DigestMismatch, getVerified, putVerified, sha256Digest } from "../src/core/digest.ts";
import { FsBlobStore } from "../src/portable/fs-store.ts";
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

test("the portable server routes through the same core: health, refused sessions, typed 404", async () => {
  const events: Record<string, unknown>[] = [];
  const server = await serve(
    { runtime: "portable", blobs: new FsBlobStore(await dataDir()) },
    { host: "127.0.0.1", port: 0, log: (event) => events.push(event) },
  );
  try {
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const health = await fetch(`${base}/healthz`);
    assert.equal(health.status, 200);
    assert.equal((await health.json()).runtime, "portable");

    const connect = await fetch(`${base}/v0/connect`, { method: "POST", body: "hello" });
    assert.equal(connect.status, 501);
    assert.equal((await connect.json()).error.code, "protocol-not-ready");

    const missing = await fetch(`${base}/nope`);
    assert.equal(missing.status, 404);
    await missing.body?.cancel();

    assert.deepEqual(events.map((event) => [event.path, event.status]), [["/healthz", 200], ["/v0/connect", 501], ["/nope", 404]]);
    assert.ok(events.every((event) => !JSON.stringify(event).includes("hello")), "a request body never reaches the log");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("the portable server refuses a declared body over its limit before reading it", async () => {
  const server = await serve({ runtime: "portable", blobs: new FsBlobStore(await dataDir()) }, { host: "127.0.0.1", port: 0 });
  try {
    const { port } = server.address() as AddressInfo;
    const response = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      import("node:http").then(({ request }) => {
        const req = request({ host: "127.0.0.1", port, path: "/v0/connect", method: "POST", headers: { "content-length": String(64 * 1024 * 1024) } }, (res) => {
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
    await new Promise((resolve) => server.close(resolve));
  }
});
