// The hosted build, run in workerd through Miniflare with no network: the bundle `npm run build:worker` writes, its
// Durable Object and R2 bindings local. Each tests/worker-*.test.ts file starts its own Miniflare from here; the
// bindings are read from wrangler.jsonc, so a binding added there is in every test without editing this file.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { sign as signBytes, type KeyObject } from "node:crypto";
import { Miniflare, type MiniflareOptions } from "miniflare";
import { relayAuthSigningInput } from "../src/contract/relay.ts";
import type { Estate } from "./estate-fixture.ts";

export const SCRIPT = "dist/worker/worker.js";

interface WranglerConfig {
  compatibility_date: string;
  compatibility_flags: string[];
  durable_objects: { bindings: Array<{ name: string; class_name: string }> };
  r2_buckets: Array<{ binding: string }>;
}
/** wrangler.jsonc is the one place the date, the flags and the bindings are set. */
export const CONFIG = JSON.parse(readFileSync("wrangler.jsonc", "utf8").replace(/^\s*\/\/.*$/gm, "")) as WranglerConfig;

export async function startWorker(extra: Partial<MiniflareOptions> = {}): Promise<Miniflare> {
  assert.ok(existsSync(SCRIPT), `${SCRIPT} is missing: run npm run build:worker (npm test does)`);
  const mf = new Miniflare({
    modules: true,
    scriptPath: SCRIPT,
    compatibilityDate: CONFIG.compatibility_date,
    compatibilityFlags: CONFIG.compatibility_flags,
    durableObjects: Object.fromEntries(CONFIG.durable_objects.bindings.map((b) => [b.name, { className: b.class_name, useSQLite: true }])),
    r2Buckets: CONFIG.r2_buckets.map((b) => b.binding),
    ...extra,
  } as MiniflareOptions);
  await mf.ready;
  return mf;
}

/**
 * A Worker whose log lines (one JSON object per line on workerd's stdout) the test can read: `logs()` answers every
 * line seen so far, `events(name)` those with that event.
 */
export async function startLoggedWorker(extra: Partial<MiniflareOptions> = {}) {
  const lines: Array<Record<string, any>> = [];
  let buffered = "";
  const mf = await startWorker({
    ...extra,
    handleRuntimeStdio: (stdout: NodeJS.ReadableStream) => {
      stdout.on("data", (chunk: Buffer) => {
        buffered += chunk.toString("utf8");
        for (let i = buffered.indexOf("\n"); i >= 0; i = buffered.indexOf("\n")) {
          const line = buffered.slice(0, i);
          buffered = buffered.slice(i + 1);
          const start = line.indexOf("{");
          if (start < 0) continue;
          try {
            lines.push(JSON.parse(line.slice(start)));
          } catch {
            // not one of the relay's lines
          }
        }
      });
    },
  } as Partial<MiniflareOptions>);
  return { mf, logs: () => lines, events: (name: string) => lines.filter((line) => line.event === name) };
}

/** Opens a session through the Worker and collects what the relay sends until it closes. */
export async function session(mf: Miniflare, relayOrigin = "http://relay.test") {
  const response = await mf.dispatchFetch(`${relayOrigin}/v1/connect`, { headers: { upgrade: "websocket", "sec-websocket-protocol": "fabric-relay.v1" } });
  assert.equal(response.status, 101);
  const ws = response.webSocket!;
  const frames: Array<Record<string, any>> = [];
  let closed: number | undefined;
  ws.addEventListener("message", (event) => frames.push(JSON.parse(String(event.data))));
  ws.addEventListener("close", (event) => { closed = event.code; });
  ws.accept();
  const until = async (done: () => boolean, ms = 5000) => {
    const end = Date.now() + ms;
    while (!done() && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.ok(done(), JSON.stringify({ frames, closed }));
  };
  return { ws, frames, until, closed: () => closed };
}

/** A machine's `auth` frame for `nonce`, signed for `relay` with the machine's own key. */
export function authFrame(m: { kid: string; privateKey: KeyObject }, nonce: string, relay = "http://relay.test") {
  const iat = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const fields = { relay, nonce, estate: "estate-5d0f1a", kid: m.kid, iat };
  const sig = signBytes("sha256", Buffer.from(relayAuthSigningInput(fields)), { key: m.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return JSON.stringify({ v: 1, type: "auth", id: "a1", protocol: "fabric-relay/0.1", alg: "ES256", ...fields, sig });
}

/** Places the estate in the bucket the way the operator does, and answers how to take it out again. */
export async function placeEstate(mf: Miniflare, e: Estate): Promise<() => Promise<void>> {
  const bucket = await mf.getR2Bucket("BLOBS");
  await bucket.put("estate/pinned.json", JSON.stringify(e.pinned));
  await bucket.put("estate/revisions/1.json", JSON.stringify(e.record));
  return async () => { await bucket.delete(["estate/pinned.json", "estate/revisions/1.json"]); };
}
