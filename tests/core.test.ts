import assert from "node:assert/strict";
import { test } from "node:test";
import { DigestMismatch, getVerified, isDigest, MemoryBlobStore, putVerified, sha256Digest } from "../src/core/digest.ts";
import { handle, PROTOCOL } from "../src/core/relay.ts";

const deps = () => ({ runtime: "portable" as const, blobs: new MemoryBlobStore() });
const bytes = (text: string) => new TextEncoder().encode(text);

test("health names the service, the runtime and the protocol it is waiting for", async () => {
  const response = await handle(new Request("http://relay/healthz"), deps());
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await response.json();
  assert.equal(body.service, "relay");
  assert.equal(body.runtime, "portable");
  assert.deepEqual(body.protocol, PROTOCOL);
  assert.equal(body.ready, false);
  assert.deepEqual(body.degraded, ["protocol:draft"]);
});

test("health answers GET and HEAD only", async () => {
  const response = await handle(new Request("http://relay/healthz", { method: "POST" }), deps());
  assert.equal(response.status, 405);
  assert.equal((await response.json()).error.code, "method-not-allowed");
});

test("a session is refused until DEC-0047 is accepted, a websocket upgrade included", async () => {
  for (const init of [{}, { headers: { upgrade: "websocket", connection: "Upgrade" } }]) {
    const response = await handle(new Request("http://relay/v0/connect", init), deps());
    assert.equal(response.status, 501);
    const body = await response.json();
    assert.equal(body.error.code, "protocol-not-ready");
    assert.match(body.error.message, /DEC-0047/);
  }
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
