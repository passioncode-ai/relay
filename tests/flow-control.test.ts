// Flow control in the portable relay (round 6): mail is delivered at the pace the machine reads it, the relay keeps
// reading what the machine sends meanwhile (acks and pings always arrive), outbound progress is liveness, one machine
// holds at most `maxSessionsPerMachine` sessions, and what the relay keeps in memory for a machine stays bounded.
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import WebSocket from "ws";
import { relayAuthSigningInput } from "../src/contract/relay.ts";
import { FsBlobStore, FsEstateSource } from "../src/portable/fs-store.ts";
import { serve } from "../src/portable/server.ts";
import { SqliteMailbox } from "../src/portable/sqlite-mailbox.ts";
import { estate, type Estate } from "./estate-fixture.ts";

const roots: string[] = [];
after(async () => { for (const root of roots) await rm(root, { recursive: true, force: true }); });

async function dataDir(e: Estate): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "relay-flow-"));
  roots.push(root);
  await mkdir(join(root, "estate", "revisions"), { recursive: true });
  await writeFile(join(root, "estate", "pinned.json"), JSON.stringify(e.pinned));
  await writeFile(join(root, "estate", "revisions", "1.json"), JSON.stringify(e.record));
  return root;
}

const within = <T>(promise: Promise<T>, ms: number) => Promise.race([promise, new Promise<undefined>((resolve) => setTimeout(resolve, ms))]);

/** `count` messages of about `kib` KiB each, from the second machine to the first, queued before the relay starts. */
async function prefill(root: string, e: Estate, count: number, kib: number) {
  const mailbox = new SqliteMailbox(join(root, "mailbox.sqlite"));
  const body = Buffer.alloc(kib * 1024, 7).toString("base64url");
  for (let n = 0; n < count; n += 1) await mailbox.append(e.machine.kid, e.second.kid, `m-${n}`, body, 3600, new Date());
  return mailbox;
}

function authFrame(m: Estate["machine"], relay: string, nonce: string): string {
  const iat = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const fields = { relay, nonce, estate: "estate-5d0f1a", kid: m.kid, iat };
  const sig = sign("sha256", Buffer.from(relayAuthSigningInput(fields)), { key: m.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return JSON.stringify({ v: 1, type: "auth", id: "a1", protocol: "fabric-relay/0.1", alg: "ES256", ...fields, sig });
}

/**
 * A machine's session through the `ws` client: it authenticates on `hello`, collects every frame and counts the bytes
 * received. `outcome` resolves with "welcome", or with the refusal (error code and close code).
 */
function machine(url: string, m: Estate["machine"], relay: string) {
  const ws = new WebSocket(url, "fabric-relay.v1", { maxPayload: 4 * 1024 * 1024 });
  const frames: Array<Record<string, any>> = [];
  let bytes = 0;
  let closed: number | undefined;
  ws.on("error", () => {});
  const outcome = new Promise<{ welcome: boolean; error?: string; close?: number }>((resolve) => {
    ws.on("message", (data) => {
      bytes += (data as Buffer).length;
      const frame = JSON.parse(String(data));
      frames.push(frame);
      if (frame.type === "hello") ws.send(authFrame(m, relay, frame.nonce));
      if (frame.type === "welcome") resolve({ welcome: true });
    });
    ws.on("close", (code) => {
      closed = code;
      resolve({ welcome: false, error: frames.find((f) => f.type === "error")?.code, close: code });
    });
  });
  return { ws, frames, outcome, bytes: () => bytes, closed: () => closed };
}

async function relay(root: string, mailbox: SqliteMailbox, extra: Record<string, unknown> = {}) {
  const events: Array<Record<string, any>> = [];
  const served = await serve({ runtime: "portable", blobs: new FsBlobStore(root) }, {
    host: "127.0.0.1", port: 0, estate: new FsEstateSource(root), mailbox, log: (event) => events.push(event), ...extra,
  });
  const port = (served.server.address() as AddressInfo).port;
  return { ...served, events, url: `ws://127.0.0.1:${port}/v1/connect` };
}

test("round 6: a machine that reads at full speed drains a 40 MiB backlog completely and acks it all", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const mailbox = await prefill(root, e, 40, 760);
  const r = await relay(root, mailbox);
  try {
    const a = machine(r.url, e.machine, r.origin);
    assert.deepEqual(await a.outcome, { welcome: true });
    a.ws.on("message", (data) => {
      const frame = JSON.parse(String(data));
      if (frame.type === "deliver") a.ws.send(JSON.stringify({ v: 1, type: "ack", id: `k${frame.seq}`, seq: frame.seq }));
    });
    const end = Date.now() + 20_000;
    while (Date.now() < end && ((await mailbox.pending(e.machine.kid, new Date(), 0)).length > 0 || a.frames.filter((f) => f.type === "deliver").length < 40)) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const delivered = a.frames.filter((f) => f.type === "deliver").map((f) => f.seq);
    assert.equal(delivered.length, 40, `delivered ${delivered.length}; events ${JSON.stringify(r.events.map((ev) => ev.event))}`);
    assert.deepEqual(delivered, [...delivered].sort((x, y) => x - y), "in seq order");
    assert.equal((await mailbox.pending(e.machine.kid, new Date(), 0)).length, 0, "every message acked and deleted");
    assert.equal(a.closed(), undefined, "the session is still open");
    assert.ok(!r.events.some((ev) => ev.event === "send-overflow"));
    a.ws.close();
  } finally {
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 6: a slow reader with a 24 MiB backlog is still read while it drains: its ping is answered mid-drain, and it gets every byte", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const mailbox = await prefill(root, e, 24, 760);
  const r = await relay(root, mailbox);
  try {
    const a = machine(r.url, e.machine, r.origin);
    assert.deepEqual(await a.outcome, { welcome: true });
    // Read about 2 MiB a second: the client stops reading its socket whenever it is ahead of that pace.
    const started = Date.now();
    const pacer = setInterval(() => {
      if (a.bytes() < (2 * 1048576 * (Date.now() - started)) / 1000) a.ws.resume();
      else a.ws.pause();
    }, 25);
    const pongs: number[] = [];
    a.ws.on("message", (data) => { if (JSON.parse(String(data)).type === "pong") pongs.push(a.bytes()); });
    await new Promise((resolve) => setTimeout(resolve, 1000));
    a.ws.send(JSON.stringify({ v: 1, type: "ping", id: "mid-drain" }));
    const end = Date.now() + 60_000;
    while (Date.now() < end && a.frames.filter((f) => f.type === "deliver").length < 24 && a.closed() === undefined) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    clearInterval(pacer);
    a.ws.resume();
    const total = a.bytes();
    assert.equal(a.frames.filter((f) => f.type === "deliver").length, 24, `closed ${a.closed()}`);
    assert.equal(pongs.length, 1, "the ping was answered");
    assert.ok(pongs[0]! < total * 0.7, `the pong came after ${(pongs[0]! / 1048576).toFixed(1)} of ${(total / 1048576).toFixed(1)} MiB: the ping waited for the drain`);
    a.ws.send(JSON.stringify({ v: 1, type: "ping", id: "after-drain" }));
    const afterEnd = Date.now() + 3000;
    while (Date.now() < afterEnd && pongs.length < 2) await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(pongs.length, 2, "a pong after the drain");
    assert.equal(a.closed(), undefined);
    a.ws.close();
  } finally {
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 6: one machine holds at most 8 sessions; the ninth is refused rate-limited and closed 1013", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const mailbox = new SqliteMailbox(join(root, "mailbox.sqlite"));
  const r = await relay(root, mailbox);
  try {
    const sessions = [];
    for (let n = 0; n < 9; n += 1) {
      const s = machine(r.url, e.machine, r.origin);
      sessions.push(s);
      await s.outcome;
    }
    const outcomes = await Promise.all(sessions.map((s) => s.outcome));
    assert.equal(outcomes.filter((o) => o.welcome).length, 8);
    assert.deepEqual(outcomes.at(-1), { welcome: false, error: "rate-limited", close: 1013 });
    assert.ok(r.events.some((ev) => ev.event === "session-limit" && ev.limit === 8));
    // A session that ends makes room for another.
    sessions[0]!.ws.close();
    await new Promise((resolve) => setTimeout(resolve, 200));
    const again = machine(r.url, e.machine, r.origin);
    assert.deepEqual(await again.outcome, { welcome: true });
    for (const s of [...sessions, again]) s.ws.terminate();
  } finally {
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 6: the session limit is configurable (maxSessionsPerMachine: 2)", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const r = await relay(root, new SqliteMailbox(join(root, "mailbox.sqlite")), { maxSessionsPerMachine: 2 });
  try {
    const outcomes = [];
    const sessions = [];
    for (let n = 0; n < 3; n += 1) {
      const s = machine(r.url, e.machine, r.origin);
      sessions.push(s);
      outcomes.push(await s.outcome);
    }
    assert.deepEqual(outcomes.map((o) => o.welcome), [true, true, false]);
    for (const s of sessions) s.ws.terminate();
  } finally {
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

/** The relay process's memory in MiB: its physical footprint on macOS (`footprint`), its resident set elsewhere. */
function memoryMiB(pid: number): number {
  if (process.platform === "darwin") {
    const out = execFileSync("footprint", ["-p", String(pid)], { stdio: ["ignore", "pipe", "ignore"] }).toString();
    const m = /Footprint:\s*([\d.]+)\s*(KB|MB|GB)/.exec(out);
    assert.ok(m, out.slice(0, 200));
    return Number(m[1]) / (m[2] === "KB" ? 1024 : m[2] === "GB" ? 1 / 1024 : 1);
  }
  const status = readFileSync(`/proc/${pid}/status`, "utf8");
  return Number(/VmRSS:\s*(\d+)/.exec(status)?.[1] ?? 0) / 1024;
}

test("round 6: 30 sessions of one machine that never read, with 11 MiB queued for it, keep the relay's memory bounded", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  (await prefill(root, e, 15, 760)).close();
  const child = spawn(process.execPath, ["--import", "tsx", "src/portable/main.ts"], {
    env: { ...process.env, RELAY_DATA_DIR: root, RELAY_PORT: "0", RELAY_HOST: "127.0.0.1", RELAY_ORIGIN: "https://relay.test" },
    stdio: ["ignore", "pipe", "inherit"],
  });
  const lines: Array<Record<string, any>> = [];
  let buffered = "";
  child.stdout.on("data", (chunk: Buffer) => {
    buffered += chunk.toString("utf8");
    for (let i = buffered.indexOf("\n"); i >= 0; i = buffered.indexOf("\n")) {
      lines.push(JSON.parse(buffered.slice(0, i)));
      buffered = buffered.slice(i + 1);
    }
  });
  const exited = new Promise<number | null>((resolve) => child.on("exit", (code) => resolve(code)));
  const sessions: Array<ReturnType<typeof machine>> = [];
  try {
    const end = Date.now() + 10_000;
    while (!lines.some((l) => l.event === "listening") && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 50));
    const port = lines.find((l) => l.event === "listening")?.port;
    assert.ok(port, JSON.stringify(lines));
    await new Promise((resolve) => setTimeout(resolve, 500));
    const before = memoryMiB(child.pid!);
    for (let n = 0; n < 30; n += 1) {
      const s = machine(`ws://127.0.0.1:${port}/v1/connect`, e.machine, "https://relay.test");
      sessions.push(s);
      const outcome = await s.outcome;
      if (outcome.welcome) s.ws.pause(); // never read another byte
    }
    await new Promise((resolve) => setTimeout(resolve, 3000));
    const grown = memoryMiB(child.pid!) - before;
    const admitted = sessions.filter((s) => s.frames.some((f) => f.type === "welcome")).length;
    // The bound: at most 8 sessions, each with at most SEND_HIGH (1 MiB) plus one delivery frame (about 1 MiB) queued on
    // its socket: 16 MiB held. On top of that come the pages a flush reads (FLUSH_PAGE = 4 bodies) and copies the
    // collector has not reclaimed yet. Measured footprint growth on macOS: 41 to 44 MiB alone, up to 75 MiB with the
    // whole suite running at once; 727 MiB before paced delivery and the session limit. 128 MiB leaves room for the
    // collector's timing and still fails the old design by a factor of five.
    assert.ok(grown < 128, `the relay grew ${grown.toFixed(0)} MiB for ${admitted} admitted sessions`);
    assert.ok(admitted <= 8, `${admitted} sessions admitted`);
    assert.equal(child.exitCode, null);
  } finally {
    for (const s of sessions) s.ws.terminate();
    child.kill("SIGTERM");
    if ((await within(exited, 12_000)) === undefined) child.kill("SIGKILL");
  }
});

test("round 6: a machine flooding pings it never reads while the relay stops: the overflow and the stop both finish", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const r = await relay(root, new SqliteMailbox(join(root, "mailbox.sqlite")));
  const a = machine(r.url, e.machine, r.origin);
  try {
    assert.deepEqual(await a.outcome, { welcome: true });
    a.ws.pause();
    // Pings with the longest id the relay echoes (128 characters): each pong is as large as a reply gets.
    const id = "x".repeat(120);
    for (let n = 0; n < 100_000; n += 1) a.ws.send(JSON.stringify({ v: 1, type: "ping", id: `${n}`.padStart(8, "0") + id }));
    // The replies pile up past the cap; the stop begins the moment the overflow is logged, while its close is in flight.
    const until = Date.now() + 20_000;
    while (!r.events.some((ev) => ev.event === "send-overflow") && Date.now() < until) await new Promise((resolve) => setTimeout(resolve, 5));
    assert.ok(r.events.some((ev) => ev.event === "send-overflow"), JSON.stringify(r.events.map((ev) => ev.event)));
    const started = Date.now();
    const result = await within(r.stop({ graceMs: 500 }), 4000);
    assert.ok(result, `stop() had not finished ${Date.now() - started} ms after it began: ${JSON.stringify(r.events.map((ev) => ev.event))}`);
    assert.ok(r.events.some((ev) => ev.event === "stopped"));
  } finally {
    a.ws.terminate();
    await within(r.stop({ graceMs: 100 }), 3000);
  }
});

// Round 7.

test("round 7: 2 machines x 8 sessions that never read, each sending 15 pings with a 1000 KiB id, keep the relay's memory bounded", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const child = spawn(process.execPath, ["--import", "tsx", "src/portable/main.ts"], {
    env: { ...process.env, RELAY_DATA_DIR: root, RELAY_PORT: "0", RELAY_HOST: "127.0.0.1", RELAY_ORIGIN: "https://relay.test" },
    stdio: ["ignore", "pipe", "inherit"],
  });
  const lines: Array<Record<string, any>> = [];
  let buffered = "";
  child.stdout.on("data", (chunk: Buffer) => {
    buffered += chunk.toString("utf8");
    for (let i = buffered.indexOf("\n"); i >= 0; i = buffered.indexOf("\n")) {
      lines.push(JSON.parse(buffered.slice(0, i)));
      buffered = buffered.slice(i + 1);
    }
  });
  const exited = new Promise<number | null>((resolve) => child.on("exit", (code) => resolve(code)));
  const sessions: Array<ReturnType<typeof machine>> = [];
  try {
    const end = Date.now() + 10_000;
    while (!lines.some((l) => l.event === "listening") && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 50));
    const port = lines.find((l) => l.event === "listening")?.port;
    assert.ok(port, JSON.stringify(lines));
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const before = memoryMiB(child.pid!);
    const id = "x".repeat(1000 * 1024);
    for (const m of [e.machine, e.second]) {
      for (let n = 0; n < 8; n += 1) {
        const s = machine(`ws://127.0.0.1:${port}/v1/connect`, m, "https://relay.test");
        sessions.push(s);
        assert.deepEqual(await s.outcome, { welcome: true });
        s.ws.pause(); // never read another byte
        for (let k = 0; k < 15; k += 1) s.ws.send(JSON.stringify({ v: 1, type: "ping", id }));
      }
    }
    let peak = 0;
    for (let t = 0; t < 12; t += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      peak = Math.max(peak, memoryMiB(child.pid!) - before);
    }
    const settled = memoryMiB(child.pid!) - before;
    // The bound (docs/protocol/sessions.md, Flow control): at most SEND_CAP (3 MiB) queued per session, 8 sessions per
    // machine, so 2 x 8 x 3 = 48 MiB queued at most; here the pings' 1000 KiB ids are refused, not echoed, so almost
    // nothing is queued. What the footprint still shows is the 240 MiB of inbound frames being parsed and collected: a
    // peak that falls back. Measured on 0680d20: 372-393 MiB, held. Here: a peak of about 85 MiB, about 43 MiB at 12 s.
    assert.ok(peak < 128, `the relay's footprint peaked ${peak.toFixed(0)} MiB above its start`);
    assert.ok(settled < 64, `the relay still holds ${settled.toFixed(0)} MiB after 12 s`);
    assert.equal(child.exitCode, null);
  } finally {
    for (const s of sessions) s.ws.terminate();
    child.kill("SIGTERM");
    if ((await within(exited, 12_000)) === undefined) child.kill("SIGKILL");
  }
});

test("round 7: the relay pings each socket; one that shows no sign of life for two heartbeats is terminated and frees its slot", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const r = await relay(root, new SqliteMailbox(join(root, "mailbox.sqlite")), { heartbeatMs: 200 });
  try {
    const live = machine(r.url, e.second, r.origin); // reads, so `ws` answers each ping with a pong
    assert.deepEqual(await live.outcome, { welcome: true });
    const stuck = [];
    for (let n = 0; n < 8; n += 1) {
      const s = machine(r.url, e.machine, r.origin);
      assert.deepEqual(await s.outcome, { welcome: true });
      s.ws.pause(); // a dead peer: it reads nothing, so it answers no ping
      stuck.push(s);
    }
    const end = Date.now() + 3000;
    while (r.events.filter((ev) => ev.event === "heartbeat-timeout").length < 8 && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(r.events.filter((ev) => ev.event === "heartbeat-timeout").length, 8, JSON.stringify(r.events.map((ev) => ev.event)));
    await new Promise((resolve) => setTimeout(resolve, 100));
    const ninth = machine(r.url, e.machine, r.origin);
    assert.deepEqual(await ninth.outcome, { welcome: true }, "the dead sessions' slots are free");
    assert.equal(live.closed(), undefined, "a socket that answers pings stays open");
    for (const s of [...stuck, ninth, live]) s.ws.terminate();
  } finally {
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});
