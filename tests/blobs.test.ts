// Blob routes (RLY-03; DEC-0047 item 8 and its 2026-10-12 annotation): who may PUT and GET is the contract's
// verifyBlobRequest over the relay's admission set; this checks what the relay does around it — storage by digest,
// the recipient list kept, deletion once every recipient fetched or after 7 days.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import type { AdmissionResult } from "../src/contract/relay.ts";
import { BLOB_RETENTION_SECONDS, MAX_BLOB_BYTES, MemoryBlobIndex } from "../src/core/blobs.ts";
import { MemoryBlobStore } from "../src/core/digest.ts";
import { handle } from "../src/core/relay.ts";
import { admittedSet, blobHeader, machine, type TestMachine } from "./test-signer.ts";

const ORIGIN = "https://relay.example";
const T0 = new Date("2026-10-12T12:00:00Z");
const A = machine("urn:fabric:machine:a#sig"), B = machine("urn:fabric:machine:b#sig"), C = machine("urn:fabric:machine:c#sig");
const STRANGER = machine("urn:fabric:machine:stranger#sig");
const bytes = new TextEncoder().encode("an envelope's bytes");
const digest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

function relay(admitted = [A, B, C]) {
  let now = T0;
  const blobs = new MemoryBlobStore(), index = new MemoryBlobIndex();
  let set = admitted;
  const deps = { runtime: "portable" as const, blobs, blobAccess: { origin: ORIGIN, index, now: () => now,
    admission: (): AdmissionResult => admittedSet(set) } };
  const header = (m: TestMachine, method: "PUT" | "GET", recipients: string[], at = now) =>
    blobHeader(m, { relay: ORIGIN, method, digest, recipients, at });
  // A PUT declares its length, as every client on the wire does (a constructed Request carries none of its own).
  const put = (m: TestMachine, recipients: string[], body: Uint8Array = bytes, headers: Record<string, string> = {}) =>
    handle(new Request(`${ORIGIN}/v1/blobs/${digest}`, { method: "PUT", body: new Uint8Array(body),
      headers: { "Fabric-Relay-Request": header(m, "PUT", recipients), "content-length": String(body.byteLength), ...headers } }), deps);
  const get = (m: TestMachine, recipients: string[]) =>
    handle(new Request(`${ORIGIN}/v1/blobs/${digest}`, { headers: { "Fabric-Relay-Request": header(m, "GET", recipients) } }), deps);
  return { blobs, index, put, get, header, deps, advance: (ms: number) => { now = new Date(now.getTime() + ms); }, revoke: (kid: string) => { set = set.filter((m) => m.kid !== kid); } };
}
const code = async (response: Response) => [response.status, ((await response.json()) as { error?: { code: string } }).error?.code];

test("a PUT stores the bytes under their digest with its recipients; the same PUT again changes nothing; another list is 409", async () => {
  const r = relay();
  assert.equal((await r.put(A, [B.kid])).status, 201);
  assert.deepEqual(await r.index.get(digest), { recipients: [B.kid], fetched: [], expiresAt: T0.getTime() + BLOB_RETENTION_SECONDS * 1000 });
  assert.equal((await r.put(A, [B.kid])).status, 200);
  assert.deepEqual(await code(await r.put(A, [B.kid, C.kid])), [409, "recipients-mismatch"]);
});

test("a PUT that names a recipient twice is 400 malformed, and nothing is kept", async () => {
  const r = relay();
  assert.deepEqual(await code(await r.put(A, [B.kid, B.kid])), [400, "malformed"]);
  assert.equal(await r.index.get(digest), null);
  assert.equal(await r.blobs.read(digest), null);
});

test("a PUT whose bytes do not hash to the path's digest is 422, and nothing is kept", async () => {
  const r = relay();
  assert.deepEqual(await code(await r.put(A, [B.kid], new TextEncoder().encode("other bytes"))), [422, "digest-mismatch"]);
  assert.equal(await r.index.get(digest), null);
  assert.equal(await r.blobs.read(digest), null);
});

test("a GET by a recipient gets the bytes; once every recipient fetched, the blob is gone", async () => {
  const r = relay();
  await r.put(A, [B.kid, C.kid]);
  const first = await r.get(B, [B.kid, C.kid]);
  assert.equal(first.status, 200);
  assert.deepEqual(new Uint8Array(await first.arrayBuffer()), bytes);
  assert.deepEqual((await r.index.get(digest))?.fetched, [B.kid]);
  assert.equal((await r.get(B, [B.kid, C.kid])).status, 200); // B again: still held for C
  assert.equal((await r.get(C, [B.kid, C.kid])).status, 200);
  assert.equal(await r.index.get(digest), null);
  assert.equal(await r.blobs.read(digest), null);
  assert.deepEqual(await code(await r.get(C, [B.kid, C.kid])), [403, "not-admitted"]);
});

test("a GET by an admitted machine that is not a recipient is 403; by a recipient no longer admitted, 401 (its signer is unproven)", async () => {
  const r = relay();
  await r.put(A, [B.kid]);
  assert.deepEqual(await code(await r.get(C, [B.kid])), [403, "not-admitted"]);
  r.revoke(B.kid);
  assert.deepEqual(await code(await r.get(B, [B.kid])), [401, "unauthenticated"]);
});

test("a blob nobody fetched is deleted after 7 days, without notice", async () => {
  const r = relay();
  await r.put(A, [B.kid]);
  r.advance(BLOB_RETENTION_SECONDS * 1000 - 1000);
  assert.ok(await r.index.get(digest));
  r.advance(1000);
  assert.deepEqual(await code(await r.get(B, [B.kid])), [403, "not-admitted"]);
  assert.equal(await r.blobs.read(digest), null);
  assert.equal(await r.index.get(digest), null);
});

test("a declared body over the limit is 413 before it is read; other methods 405; a name that is not a digest 404; no access, no route", async () => {
  const r = relay();
  const big = await handle(new Request(`${ORIGIN}/v1/blobs/${digest}`, { method: "PUT", body: "x",
    headers: { "Fabric-Relay-Request": "", "content-length": String(64 * 1024 * 1024) } }), r.deps);
  assert.equal(big.status, 400); // the header is checked first: malformed before any byte is read
  assert.deepEqual(await code(await r.put(A, [B.kid], bytes, { "content-length": String(MAX_BLOB_BYTES + 1) })), [413, "too-large"]);
  const auth = await r.put(A, [B.kid]); // valid request with a body under the limit
  assert.equal(auth.status, 201);
  assert.equal((await handle(new Request(`${ORIGIN}/v1/blobs/${digest}`, { method: "DELETE" }), r.deps)).status, 405);
  assert.equal((await handle(new Request(`${ORIGIN}/v1/blobs/not-a-digest`), r.deps)).status, 404);
  assert.equal((await handle(new Request(`${ORIGIN}/v1/blobs/${digest}`), { runtime: "portable", blobs: r.blobs })).status, 404);
});

test("a blob path that is not valid percent-encoding (/v1/blobs/%) is 400 malformed, not a 500", async () => {
  const r = relay();
  for (const path of ["%", "%E0%A4%A", "sha256:%ZZ"]) {
    assert.deepEqual(await code(await handle(new Request(`${ORIGIN}/v1/blobs/${path}`), r.deps)), [400, "malformed"], path);
  }
});

// DEC-0066's order of checks: authenticate, then authorize, then touch state, then answer.
test("a PUT without Content-Length is 411 malformed, and a declared length is judged after the request's own bytes and before the signer", async () => {
  const r = relay();
  const unsized = await handle(new Request(`${ORIGIN}/v1/blobs/${digest}`, { method: "PUT", body: new Uint8Array(bytes),
    headers: { "Fabric-Relay-Request": r.header(A, "PUT", [B.kid]) } }), r.deps);
  assert.deepEqual(await code(unsized), [411, "malformed"]);
  // Step 5 comes before step 6: an unknown signer with an over-long declared body learns 413, which its own bytes decide.
  assert.deepEqual(await code(await r.put(STRANGER, [B.kid], bytes, { "content-length": String(MAX_BLOB_BYTES + 1) })), [413, "too-large"]);
  assert.deepEqual(await code(await r.put(STRANGER, [B.kid])), [401, "unauthenticated"]);
  // Step 4 comes before step 5: an iat outside the window is 401 whatever the length.
  const stale = await handle(new Request(`${ORIGIN}/v1/blobs/${digest}`, { method: "PUT", body: new Uint8Array(bytes),
    headers: { "Fabric-Relay-Request": r.header(A, "PUT", [B.kid], new Date(T0.getTime() - 120_000)), "content-length": String(MAX_BLOB_BYTES + 1) } }), r.deps);
  assert.deepEqual(await code(stale), [401, "unauthenticated"]);
  assert.equal(await r.index.get(digest), null);
});

test("a PUT whose body is longer than it declared is 413, and nothing is kept", async () => {
  const r = relay();
  assert.deepEqual(await code(await r.put(A, [B.kid], bytes, { "content-length": String(bytes.byteLength - 1) })), [413, "too-large"]);
  assert.equal(await r.index.get(digest), null);
});

test("a PUT under another recipient list is 409 only for a holder of the bytes: wrong bytes are 422 whatever is stored", async () => {
  const r = relay();
  assert.equal((await r.put(A, [B.kid])).status, 201);
  assert.deepEqual(await code(await r.put(A, [C.kid], new TextEncoder().encode("other bytes"))), [422, "digest-mismatch"]);
  assert.deepEqual(await code(await r.put(A, [C.kid])), [409, "recipients-mismatch"]);
  assert.deepEqual((await r.index.get(digest))?.recipients, [B.kid]); // never merged
});

test("a repeat PUT with the same list is 200 and restores an object the store lost", async () => {
  const r = relay();
  assert.equal((await r.put(A, [B.kid])).status, 201);
  await r.blobs.delete(digest);
  assert.deepEqual(await code(await r.get(B, [B.kid])), [403, "not-admitted"]); // a lost object is 403, never 404
  assert.equal((await r.put(A, [B.kid])).status, 200);
  const back = await r.get(B, [B.kid]);
  assert.equal(back.status, 200);
  assert.deepEqual(new Uint8Array(await back.arrayBuffer()), bytes);
});

test("a GET whose signed list differs from the stored one is 403 not-admitted, even from a recipient", async () => {
  const r = relay();
  await r.put(A, [B.kid, C.kid]);
  assert.deepEqual(await code(await r.get(B, [B.kid])), [403, "not-admitted"]);
  assert.deepEqual(await code(await r.get(B, [C.kid, B.kid])), [403, "not-admitted"]); // letter for letter
  assert.equal((await r.get(B, [B.kid, C.kid])).status, 200);
});

test("a GET of a blob never stored is 403 not-admitted, the answer a held blob gives a non-recipient", async () => {
  const r = relay();
  assert.deepEqual(await code(await r.get(B, [B.kid])), [403, "not-admitted"]);
});
