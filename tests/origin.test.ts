// The portable relay's one origin (RLY-017): RELAY_ORIGIN normalised or refused, the loopback default computed after
// listen, and the same origin for sessions and blob routes. http:// is allowed only on loopback literals — 127.0.0.0/8
// and [::1], never the name "localhost", which resolves where a literal cannot (the contract owner's answer to P9).
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
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
import { signEs256 } from "../src/contract/p256.ts";

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
  const exposed = relayOrigin("http://127.0.0.1:8787", "0.0.0.0");
  assert.equal(exposed.ok, false, "a local-only origin served on every interface");
  if (!exposed.ok) assert.match(exposed.reason, /RELAY_HOST 0\.0\.0\.0 is not a loopback literal/);
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
  // A failing assertion must fail the test, never hang it on an open socket.
  const stop = () => served.stop({ graceMs: 100 });
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
    const sig = signEs256(r.e.machine.privateKey, relayAuthSigningInput(fields));
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
    const sig = signEs256(r.e.machine.privateKey, relayBlobSigningInput({ relay: r.origin, method: "PUT", digest, recipients, iat }));
    const put = await fetch(`http://127.0.0.1:${r.port}/v1/blobs/${digest}`, { method: "PUT", body: bytes, headers: { "Fabric-Relay-Request": relayRequestHeader({ alg: "ES256", kid: r.e.machine.kid, recipients, iat, sig }) } });
    assert.equal(put.status, 201, await put.text());
  } finally {
    await r.stop();
  }
});

// Round 3: the defaulted origin is the URL parser's canonical form of RELAY_HOST, never RELAY_HOST verbatim.

test("unset: the defaulted origin is canonical — ::1 for every spelling of it, 127.0.0.1 for 127.000.000.001", () => {
  for (const [host, origin] of [["0:0:0:0:0:0:0:1", "http://[::1]:8787"], ["::1", "http://[::1]:8787"], ["0:0::1", "http://[::1]:8787"],
    ["127.000.000.001", "http://127.0.0.1:8787"], ["127.0.0.1", "http://127.0.0.1:8787"]] as const) {
    const rule = relayOrigin(undefined, host);
    assert.ok(rule.ok, `${host}: ${JSON.stringify(rule)}`);
    assert.equal(rule.at(8787), origin, host);
  }
  assert.equal((relayOrigin(undefined, "127.0.0.1") as { at(port: number): string }).at(80), "http://127.0.0.1", "the default port is dropped, as url.origin does");
});

test("unset: a loopback spelling the URL parser reads differently from the address (octal parts) or not at all is refused", () => {
  for (const host of ["127.010.0.1", "127.08.0.1"]) {
    const rule = relayOrigin(undefined, host);
    assert.equal(rule.ok, false, host);
    if (!rule.ok) assert.match(rule.reason, /RELAY_HOST/, host);
  }
});

test("a bracketed RELAY_HOST is refused with the bare address to use, whether RELAY_ORIGIN is set or not", () => {
  for (const origin of [undefined, "https://relay.example", "http://[::1]:9000"]) {
    const rule = relayOrigin(origin, "[::1]");
    assert.equal(rule.ok, false, String(origin));
    if (!rule.ok) assert.match(rule.reason, /RELAY_HOST \[::1\] .*::1/, String(origin));
  }
});

test("RELAY_HOST=[::1] refuses to start with exit 2 and refused-to-start, not a raw listen error", async () => {
  const root = await mkdtemp(join(tmpdir(), "relay-origin-")); roots.push(root);
  const child = spawn(process.execPath, ["--import", "tsx", "src/portable/main.ts"], {
    env: { ...process.env, RELAY_DATA_DIR: root, RELAY_PORT: "0", RELAY_HOST: "[::1]", RELAY_ORIGIN: "" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "", err = "";
  child.stdout.on("data", (chunk: Buffer) => { out += chunk.toString("utf8"); });
  child.stderr.on("data", (chunk: Buffer) => { err += chunk.toString("utf8"); });
  const code = await Promise.race([
    new Promise<number | null>((resolve) => child.on("exit", (exit) => resolve(exit))),
    new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), 10_000)),
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
  assert.equal(code, 2, `stdout: ${out}\nstderr: ${err}`);
  const lines = out.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const refused = lines.find((line) => line.event === "refused-to-start");
  assert.ok(refused, out);
  assert.match(refused.reason, /RELAY_HOST \[::1\]/);
});

// Round 4: every RELAY_HOST must parse as a URL host, and a RELAY_ORIGIN host must mean what it says.

test("F2: a RELAY_HOST the URL parser cannot read (a zone id, a space) is refused whether RELAY_ORIGIN is set or not", () => {
  for (const host of ["fe80::1%lo0", "::1%lo0", " 127.0.0.1", "127.08.0.1"]) {
    for (const origin of [undefined, "https://relay.example"]) {
      const rule = relayOrigin(origin, host);
      assert.equal(rule.ok, false, `${host} with ${origin}`);
      if (!rule.ok) assert.match(rule.reason, /RELAY_HOST/, `${host} with ${origin}`);
    }
  }
  const octal = relayOrigin("https://relay.example", "127.010.0.1");
  assert.equal(octal.ok, false, "a RELAY_HOST a URL reads as another address is refused with a set origin too");
  for (const host of ["relay-box", "0.0.0.0", "::", "Relay.Example"]) assert.ok(relayOrigin("https://relay.example", host).ok, host);
});

test("F4: an IPv4 RELAY_ORIGIN host must be four decimal parts that read as the same address", () => {
  for (const raw of ["http://127.010.0.1:8787", "http://0x7f.1:8787", "http://127.1:8787", "https://2130706433", "http://127.0.0.1.:8787"]) {
    const rule = relayOrigin(raw, "127.0.0.1");
    assert.equal(rule.ok, false, raw);
    if (!rule.ok) assert.match(rule.reason, /RELAY_ORIGIN/, raw);
  }
  const zeros = relayOrigin("http://127.000.000.001:8787", "127.0.0.1");
  assert.ok(zeros.ok && zeros.at(1) === "http://127.0.0.1:8787", "leading zeros that read the same are normalised");
});

test("F4: a RELAY_ORIGIN with port 0 or a trailing dot is refused", () => {
  for (const [raw, problem] of [["https://relay.example:0", /port/], ["http://127.0.0.1:0", /port/], ["https://relay.example.", /trailing dot/], ["https://relay.example.:8443", /trailing dot/]] as const) {
    const rule = relayOrigin(raw, "127.0.0.1");
    assert.equal(rule.ok, false, raw);
    if (!rule.ok) assert.match(rule.reason, problem, raw);
  }
});

test("round 5: a RELAY_ORIGIN host with an empty label (.relay.test, relay..test) is refused", () => {
  for (const raw of ["https://.relay.test", "https://relay..test", "https://..relay.test:8443"]) {
    const rule = relayOrigin(raw, "127.0.0.1");
    assert.equal(rule.ok, false, raw);
    if (!rule.ok) assert.match(rule.reason, /empty label/, raw);
  }
});

test("round 6: a RELAY_ORIGIN with an empty query or fragment (https://relay.test? or #) is refused like any query or fragment", () => {
  for (const [raw, problem] of [["https://relay.test?", /query/], ["https://relay.test#", /fragment/], ["https://relay.test/?", /query/], ["https://relay.test/#", /fragment/]] as const) {
    const rule = relayOrigin(raw, "127.0.0.1");
    assert.equal(rule.ok, false, raw);
    if (!rule.ok) assert.match(rule.reason, problem, raw);
  }
});

test("DEC-0066: an origin the URL parser accepts but the contract's relay-origin pattern refuses does not start (a name over 253 characters)", () => {
  const long = `https://${Array.from({ length: 5 }, () => "a".repeat(60)).join(".")}.test`;
  assert.equal(new URL(long).origin, long, "the URL parser accepts it as written");
  const rule = relayOrigin(long, "0.0.0.0");
  assert.equal(rule.ok, false);
  if (!rule.ok) assert.match(rule.reason, /DEC-0066/);
  assert.ok(relayOrigin("https://relay.example", "0.0.0.0").ok, "an ordinary origin still starts");
});
