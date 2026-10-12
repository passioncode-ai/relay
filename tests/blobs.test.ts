// Blob routes (RLY-03; DEC-0047 item 8 and its 2026-10-12 annotation): who may PUT and GET is the contract's
// verifyBlobRequest over the relay's admission set; this checks what the relay does around it — storage by digest,
// the recipient list kept, deletion once every recipient fetched or after 7 days.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import { relayBlobSigningInput, relayRequestHeader, type AdmissionResult } from "../src/contract/relay.ts";
import { BLOB_RETENTION_SECONDS, MemoryBlobIndex } from "../src/core/blobs.ts";
import { MemoryBlobStore } from "../src/core/digest.ts";
import { handle } from "../src/core/relay.ts";

const ORIGIN = "https://relay.example";
const T0 = new Date("2026-10-12T12:00:00Z");
const machine = (kid: string) => {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { kid, privateKey: pair.privateKey, jwk: pair.publicKey.export({ format: "jwk" }) };
};
const A = machine("urn:fabric:machine:a#sig"), B = machine("urn:fabric:machine:b#sig"), C = machine("urn:fabric:machine:c#sig");
const bytes = new TextEncoder().encode("an envelope's bytes");
const digest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

function relay(admitted = [A, B, C]) {
  let now = T0;
  const blobs = new MemoryBlobStore(), index = new MemoryBlobIndex();
  let set = new Map(admitted.map((m) => [m.kid, m.jwk]));
  const deps = { runtime: "portable" as const, blobs, blobAccess: { origin: ORIGIN, index, now: () => now,
    admission: (): AdmissionResult => ({ ok: true, held: {}, revision: 1, set: set as unknown as Map<string, Uint8Array> }) } };
  const header = (m: ReturnType<typeof machine>, method: "PUT" | "GET", recipients: string[], at = now) => {
    const iat = at.toISOString().replace(/\.\d{3}Z$/, "Z");
    const sig = sign("sha256", Buffer.from(relayBlobSigningInput({ relay: ORIGIN, method, digest, recipients, iat })), { key: m.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    return relayRequestHeader({ alg: "ES256", kid: m.kid, recipients, iat, sig });
  };
  const put = (m: ReturnType<typeof machine>, recipients: string[], body: Uint8Array = bytes) =>
    handle(new Request(`${ORIGIN}/v1/blobs/${digest}`, { method: "PUT", body: new Uint8Array(body), headers: { "Fabric-Relay-Request": header(m, "PUT", recipients) } }), deps);
  const get = (m: ReturnType<typeof machine>, recipients: string[]) =>
    handle(new Request(`${ORIGIN}/v1/blobs/${digest}`, { headers: { "Fabric-Relay-Request": header(m, "GET", recipients) } }), deps);
  return { blobs, index, put, get, deps, advance: (ms: number) => { now = new Date(now.getTime() + ms); }, revoke: (kid: string) => { set = new Map([...set].filter(([k]) => k !== kid)); } };
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

test("a GET by a machine that is not a recipient, or by a recipient no longer admitted, is 403", async () => {
  const r = relay();
  await r.put(A, [B.kid]);
  assert.deepEqual(await code(await r.get(C, [B.kid])), [403, "not-admitted"]);
  r.revoke(B.kid);
  assert.deepEqual(await code(await r.get(B, [B.kid])), [403, "not-admitted"]);
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
  const auth = await r.put(A, [B.kid]); // valid request with a body under the limit
  assert.equal(auth.status, 201);
  assert.equal((await handle(new Request(`${ORIGIN}/v1/blobs/${digest}`, { method: "DELETE" }), r.deps)).status, 405);
  assert.equal((await handle(new Request(`${ORIGIN}/v1/blobs/not-a-digest`), r.deps)).status, 404);
  assert.equal((await handle(new Request(`${ORIGIN}/v1/blobs/${digest}`), { runtime: "portable", blobs: r.blobs })).status, 404);
});
