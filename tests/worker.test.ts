// The hosted build, run in workerd through Miniflare with no network: the bundle `npm run build:worker`
// writes, its Durable Object and R2 bindings local.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import { Miniflare } from "miniflare";

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
    durableObjects: { SESSIONS: { className: "RelaySession", useSQLite: true } },
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
  assert.equal(body.ready, false);
});

test("the Worker refuses a websocket session until DEC-0047 is accepted", async () => {
  const response = await mf.dispatchFetch("http://relay.test/v0/connect", { headers: { upgrade: "websocket", connection: "Upgrade" } });
  assert.equal(response.status, 501);
  assert.equal(((await response.json()) as { error: { code: string } }).error.code, "protocol-not-ready");
});

test("the session Durable Object refuses too, so no path opens a session early", async () => {
  const namespace = await mf.getDurableObjectNamespace("SESSIONS");
  const stub = namespace.get(namespace.idFromName("probe"));
  const response = await stub.fetch("http://session/");
  assert.equal(response.status, 501);
  await response.arrayBuffer();
});

test("the R2 binding the blob store uses exists in the bundle's bindings", async () => {
  const bucket = await mf.getR2Bucket("BLOBS");
  assert.equal(await bucket.get("sha256:" + "0".repeat(64)), null);
});
