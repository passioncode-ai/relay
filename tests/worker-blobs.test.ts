// The hosted build's blob routes over R2, in workerd (tests/worker-harness.ts).
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import type { Miniflare } from "miniflare";
import { createHash } from "node:crypto";
import { relayBlobSigningInput, relayRequestHeader } from "../src/contract/relay.ts";
import { estate } from "./estate-fixture.ts";
import { startWorker } from "./worker-harness.ts";
import { signEs256 } from "../src/contract/p256.ts";

let mf: Miniflare;
before(async () => { mf = await startWorker(); });
after(async () => { await mf?.dispose(); });

test("the R2 binding the blob store uses exists in the bundle's bindings", async () => {
  const bucket = await mf.getR2Bucket("BLOBS");
  assert.equal(await bucket.get("sha256:" + "0".repeat(64)), null);
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
    const sig = signEs256(m.privateKey, relayBlobSigningInput({ relay: "http://relay.test", method, digest, recipients, iat }));
    return relayRequestHeader({ alg: "ES256", kid: m.kid, recipients, iat, sig });
  };
  // dispatchFetch does not carry a body's length to workerd on its own; a client on the wire does (DEC-0066 step 5: 411 without it).
  const put = await mf.dispatchFetch(`http://relay.test/v1/blobs/${digest}`, { method: "PUT", body: bytes, headers: { "Fabric-Relay-Request": header(e.machine, "PUT"), "content-length": String(bytes.byteLength) } });
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
