// The portable relay's one origin (RLY-017): RELAY_ORIGIN normalised or refused, the loopback default computed after
// listen, and the same origin for sessions and blob routes. http:// is allowed only on loopback literals — 127.0.0.0/8
// and [::1], never the name "localhost", which resolves where a literal cannot (the contract owner's answer to P9).
import assert from "node:assert/strict";
import { createHash, sign } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { relayAuthSigningInput, relayBlobSigningInput, relayRequestHeader } from "../src/contract/relay.ts";
import { isLocalOnly, isLoopbackLiteral, OriginRefused, relayOrigin } from "../src/portable/origin.ts";
import { FsBlobIndex, FsBlobStore, FsEstateSource } from "../src/portable/fs-store.ts";
import { serve } from "../src/portable/server.ts";
import { estate } from "./estate-fixture.ts";

const roots: string[] = [];
after(async () => { for (const root of roots) await rm(root, { recursive: true, force: true }); });

// A URL with a user part, built so no literal "user:password@host" sits in the source.
const withUserPart = ["https://", "someone", ":", "x", "@relay.example"].join("");

test("a set origin is normalised: host lowercased, :443 and the root path dropped", () => {
  for (const [raw, origin] of [["https://Relay.Example/", "https://relay.example"], ["https://relay.example:443", "https://relay.example"], ["https://relay.example:8443/", "https://relay.example:8443"]] as const) {
    const rule = relayOrigin(raw, "0.0.0.0");
    assert.ok(rule.ok, JSON.stringify(rule));
    assert.deepEqual([rule.at(1234), rule.localOnly, rule.defaulted], [origin, false, false]);
  }
});

test("a set origin is refused, with the exact problem, when it is not a bare https origin (or http on a loopback literal)", () => {
  const cases: Array<[string, RegExp]> = [
    ["https://relay.example/x", /path/],
    ["https://relay.example/?a=1", /query/],
    ["https://relay.example/#f", /fragment/],
    [withUserPart, /credentials/],
    ["http://relay.example", /https/],
    ["http://localhost:8787", /loopback literal/],
    ["ftp://relay.example", /https/],
    ["relay.example", /not a URL/],
  ];
  for (const [raw, problem] of cases) {
    const rule = relayOrigin(raw, "0.0.0.0");
    assert.equal(rule.ok, false, raw);
    if (!rule.ok) assert.match(rule.reason, problem, raw);
  }
  const loopback = relayOrigin("http://127.0.0.1:9000/", "127.0.0.1");
  assert.ok(loopback.ok && loopback.at(1) === "http://127.0.0.1:9000" && loopback.localOnly);
  const v6 = relayOrigin("http://[::1]:9000", "::1");
  assert.ok(v6.ok && v6.at(1) === "http://[::1]:9000");
});

test("unset: an http default only on a loopback literal, computed from the bound port; refused on any other host, localhost included", () => {
  const v4 = relayOrigin(undefined, "127.0.0.1");
  assert.ok(v4.ok && v4.defaulted && v4.localOnly);
  assert.equal(v4.at(54321), "http://127.0.0.1:54321");
  const v6 = relayOrigin(undefined, "::1");
  assert.ok(v6.ok && v6.at(8787) === "http://[::1]:8787");
  for (const host of ["0.0.0.0", "localhost", "relay.example", "10.0.0.1", "::"]) {
    const rule = relayOrigin(undefined, host);
    assert.equal(rule.ok, false, host);
    if (!rule.ok) assert.match(rule.reason, /RELAY_ORIGIN/);
  }
  assert.deepEqual(["127.0.0.1", "127.255.0.9", "::1", "[::1]", "localhost", "128.0.0.1", "::"].map(isLoopbackLiteral), [true, true, true, true, false, false, false]);
  assert.deepEqual([isLocalOnly("http://127.0.0.1:1"), isLocalOnly("https://relay.example")], [true, false]);
});

test("serve() refuses to start with an origin the rules refuse", async () => {
  const root = await mkdtemp(join(tmpdir(), "relay-origin-")); roots.push(root);
  await assert.rejects(serve({ runtime: "portable", blobs: new FsBlobStore(root) }, { host: "127.0.0.1", port: 0, origin: "https://relay.example/x" }), OriginRefused);
  await assert.rejects(serve({ runtime: "portable", blobs: new FsBlobStore(root) }, { host: "0.0.0.0", port: 0 }), OriginRefused);
});

async function relay(origin: string | undefined) {
  const root = await mkdtemp(join(tmpdir(), "relay-origin-")); roots.push(root);
  const e = estate(new Date(), "ES256");
  await mkdir(join(root, "estate", "revisions"), { recursive: true });
  await writeFile(join(root, "estate", "pinned.json"), JSON.stringify(e.pinned));
  await writeFile(join(root, "estate", "revisions", "1.json"), JSON.stringify(e.record));
  const served = await serve({ runtime: "portable", blobs: new FsBlobStore(root) }, { host: "127.0.0.1", port: 0, estate: new FsEstateSource(root), blobIndex: new FsBlobIndex(root), ...(origin ? { origin } : {}) });
  const port = (served.server.address() as AddressInfo).port;
  const stop = () => new Promise<void>((resolve) => served.server.close(() => resolve()));
  return { ...served, e, port, stop };
}

test("RELAY_ORIGIN=https://Relay.Example/ admits a machine that signed https://relay.example", async () => {
  const r = await relay("https://Relay.Example/");
  try {
    assert.equal(r.origin, "https://relay.example");
    const ws = new WebSocket(`ws://127.0.0.1:${r.port}/v1/connect`, "fabric-relay.v1");
    const frames: Array<Record<string, any>> = [];
    ws.addEventListener("message", (event) => frames.push(JSON.parse(String(event.data))));
    const until = async (done: () => boolean) => { const end = Date.now() + 5000; while (!done() && Date.now() < end) await new Promise((res) => setTimeout(res, 20)); assert.ok(done(), JSON.stringify(frames)); };
    await until(() => frames.length >= 1);
    assert.equal(frames[0]!.relay, "https://relay.example");
    const iat = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const fields = { relay: "https://relay.example", nonce: frames[0]!.nonce, estate: "estate-5d0f1a", kid: r.e.machine.kid, iat };
    const sig = sign("sha256", Buffer.from(relayAuthSigningInput(fields)), { key: r.e.machine.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    ws.send(JSON.stringify({ v: 1, type: "auth", id: "a1", protocol: "fabric-relay/0.1", alg: "ES256", ...fields, sig }));
    await until(() => frames.some((f) => f.type === "welcome" || f.type === "error"));
    assert.equal(frames.at(-1)!.type, "welcome", JSON.stringify(frames.at(-1)));
    ws.close();
  } finally {
    await r.stop();
  }
});

test("port 0 without an origin: the blob route verifies against the same origin hello names", async () => {
  const r = await relay(undefined);
  try {
    assert.equal(r.origin, `http://127.0.0.1:${r.port}`);
    const bytes = new TextEncoder().encode("sealed");
    const digest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    const recipients = [r.e.second.kid];
    const iat = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const sig = sign("sha256", Buffer.from(relayBlobSigningInput({ relay: r.origin, method: "PUT", digest, recipients, iat })), { key: r.e.machine.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    const put = await fetch(`http://127.0.0.1:${r.port}/v1/blobs/${digest}`, { method: "PUT", body: bytes, headers: { "Fabric-Relay-Request": relayRequestHeader({ alg: "ES256", kid: r.e.machine.kid, recipients, iat, sig }) } });
    assert.equal(put.status, 201, await put.text());
  } finally {
    await r.stop();
  }
});
