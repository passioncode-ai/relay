import assert from "node:assert/strict";
import { test } from "node:test";
import { DigestMismatch, getVerified, isDigest, MemoryBlobStore, putVerified, sha256Digest } from "../src/core/digest.ts";
import { handle, PROTOCOL, upgradeRefusal } from "../src/core/relay.ts";

const deps = () => ({ runtime: "portable" as const, blobs: new MemoryBlobStore() });
const bytes = (text: string) => new TextEncoder().encode(text);

test("health names the service, the runtime and the protocol it serves", async () => {
  const response = await handle(new Request("http://relay/healthz"), deps());
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await response.json();
  assert.equal(body.service, "relay");
  assert.equal(body.runtime, "portable");
  assert.deepEqual(body.protocol, PROTOCOL);
  assert.equal(body.protocol.version, "fabric-relay/0.1");
  assert.equal(body.ready, true);
  assert.deepEqual(body.degraded, []);
});

test("health answers GET and HEAD only", async () => {
  const response = await handle(new Request("http://relay/healthz", { method: "POST" }), deps());
  assert.equal(response.status, 405);
  assert.equal((await response.json()).error.code, "method-not-allowed");
});

test("/v1/connect is a WebSocket endpoint: a GET upgrade offering fabric-relay.v1, nothing else", async () => {
  const cases: Array<[RequestInit, number, string]> = [
    [{}, 426, "upgrade-required"],
    [{ method: "POST", body: "x" }, 405, "method-not-allowed"],
    [{ headers: { upgrade: "websocket" } }, 400, "protocol-unsupported"],
    [{ headers: { upgrade: "websocket", "sec-websocket-protocol": "chat, superchat" } }, 400, "protocol-unsupported"],
  ];
  for (const [init, status, code] of cases) {
    const response = await handle(new Request("http://relay/v1/connect", init), deps());
    assert.equal(response.status, status, code);
    assert.equal((await response.json()).error.code, code);
  }
  const ok = new Request("http://relay/v1/connect", { headers: { upgrade: "websocket", "sec-websocket-protocol": "x, fabric-relay.v1" } });
  assert.equal(upgradeRefusal(ok), null);
});

test("the draft's /v0/connect is gone", async () => {
  assert.equal((await handle(new Request("http://relay/v0/connect"), deps())).status, 404);
});

test("an unknown route is a typed not-found", async () => {
  const response = await handle(new Request("http://relay/v0/blobs/x"), deps());
  assert.equal(response.status, 404);
  assert.deepEqual(Object.keys((await response.json()).error).sort(), ["code", "message"]);
});

test("the digest is sha256 of the bytes, in the sha256:<hex> form", async () => {
  // Known answer: SHA-256 of "abc".
  assert.equal(await sha256Digest(bytes("abc")), "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.ok(isDigest(await sha256Digest(new Uint8Array())));
  for (const bad of ["", "sha256:", "sha256:ABC", "sha1:" + "0".repeat(40), "sha256:" + "0".repeat(63), " sha256:" + "0".repeat(64)]) {
    assert.equal(isDigest(bad), false, bad);
  }
});

test("a blob is stored only under the digest of its own bytes", async () => {
  const store = new MemoryBlobStore();
  const blob = bytes("sealed envelope");
  const digest = await sha256Digest(blob);
  await putVerified(store, digest, blob);
  assert.deepEqual(await getVerified(store, digest), blob);

  const other = await sha256Digest(bytes("something else"));
  await assert.rejects(putVerified(store, other, blob), (error: unknown) => error instanceof DigestMismatch && error.code === "digest-mismatch");
  assert.equal(await getVerified(store, other), null, "the refused blob was not written");
  await assert.rejects(putVerified(store, "not-a-digest", blob), TypeError);
});

test("bytes a store hands back under the wrong digest are refused, not served", async () => {
  const store = new MemoryBlobStore();
  const digest = await sha256Digest(bytes("original"));
  await store.write(digest, bytes("tampered"));
  await assert.rejects(getVerified(store, digest), DigestMismatch);
});

test("the memory store keeps its own copy of what it was given", async () => {
  const store = new MemoryBlobStore();
  const blob = bytes("abc");
  const digest = await sha256Digest(blob);
  await putVerified(store, digest, blob);
  blob[0] = 0;
  assert.deepEqual(await getVerified(store, digest), bytes("abc"));
});
