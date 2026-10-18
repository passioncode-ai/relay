// Flow control in the portable relay (round 6): mail is delivered at the pace the machine reads it, the relay keeps
// reading what the machine sends meanwhile (acks and pings always arrive), outbound progress is liveness, one machine
// holds at most `maxSessionsPerMachine` sessions, and what the relay keeps in memory for a machine stays bounded.
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { connect as tcp, type AddressInfo, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import WebSocket from "ws";
import { relayAuthSigningInput } from "../src/contract/relay.ts";
import { FsBlobStore, FsEstateSource } from "../src/portable/fs-store.ts";
import { serve } from "../src/portable/server.ts";
import { SqliteMailbox } from "../src/portable/sqlite-mailbox.ts";
import { estate, type Estate } from "./estate-fixture.ts";
import { signEs256 } from "../src/contract/p256.ts";

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
  const sig = signEs256(m.privateKey, relayAuthSigningInput(fields));
  return JSON.stringify({ v: 1, type: "auth", id: "a1", protocol: "fabric-relay/0.1", alg: "ES256", ...fields, sig });
}

/**
 * A machine's session through the `ws` client: it authenticates on `hello`, collects every frame and counts the bytes
 * received. `outcome` resolves with "welcome", or with the refusal (error code and close code).
 */
function machine(url: string, m: Estate["machine"], relay: string, onWelcome?: (ws: WebSocket) => void) {
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
      if (frame.type === "welcome") {
        onWelcome?.(ws);
        resolve({ welcome: true });
      }
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
    // Mid-drain: the pong is not behind the whole backlog. Where it lands depends on how much the kernel's buffers held
    // when the ping was answered (up to about 9 MiB on macOS), so the check is that deliveries still followed it,
    // several of them, rather than a fixed share of the bytes.
    const pongAt = a.frames.findIndex((f) => f.type === "pong");
    const after = a.frames.slice(pongAt).filter((f) => f.type === "deliver").length;
    assert.ok(after >= 4, `the pong came after ${(pongs[0]! / 1048576).toFixed(1)} of ${(total / 1048576).toFixed(1)} MiB, with ${after} deliveries after it: the ping waited for the drain`);
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
    // Pings with the longest id the relay echoes (128 code points, four-byte characters): each pong is about 550 bytes.
    // Sent in batches until the replies pile up past the cap, however much the kernel's buffers take first (Linux's
    // grow larger than macOS's); the stop begins the moment the overflow is logged, while its close is in flight.
    // First about 9 MiB of mail to itself: deliveries fill the kernel's buffers in a few large writes (CI's Linux
    // runners take up to ~10 MiB there, and pongs alone filled them too slowly under load: no overflow in 30 s).
    const body = Buffer.alloc(760 * 1024, 7).toString("base64url");
    for (let k = 0; k < 12; k += 1) a.ws.send(JSON.stringify({ v: 1, type: "send", id: `m${k}`, to: e.machine.kid, msgId: `self-${k}`, body, ttl: 600 }));
    const id = "\u{1F600}".repeat(120);
    let n = 0;
    const until = Date.now() + 30_000;
    while (!r.events.some((ev) => ev.event === "send-overflow") && Date.now() < until) {
      for (let k = 0; k < 2000; k += 1) a.ws.send(JSON.stringify({ v: 1, type: "ping", id: `${n++}`.padStart(8, "0") + id }));
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
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

test("round 7: 2 machines x 8 sessions that never read, flooding pings with 1000 KiB ids and sends with 1000 KiB msgIds, queue nothing past the cap", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const r = await relay(root, new SqliteMailbox(join(root, "mailbox.sqlite")));
  const sessions: Array<ReturnType<typeof machine>> = [];
  try {
    for (const m of [e.machine, e.second]) {
      for (let n = 0; n < 8; n += 1) {
        const s = machine(r.url, m, r.origin);
        sessions.push(s);
        assert.deepEqual(await s.outcome, { welcome: true });
        s.ws.pause(); // never read another byte
      }
    }
    const long = "x".repeat(1000 * 1024);
    for (const s of sessions) {
      const to = s === sessions[0] ? e.second.kid : e.machine.kid;
      for (let k = 0; k < 10; k += 1) {
        s.ws.send(JSON.stringify({ v: 1, type: "ping", id: long }));
        s.ws.send(JSON.stringify({ v: 1, type: "send", id: `s${k}`, to, msgId: long, body: "AA", ttl: 60 }));
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 4000));
    // What a session queues is read from the relay itself, not from the process's footprint (allocator retention): each
    // refused ping and send is answered by a short error, never by an echo of its 1000 KiB id or msgId, so no session
    // comes near the cap. With the id check planted out, every session overflows; on dbd0764 the msgId echo did, with
    // 4 MiB queued.
    const overflows = r.events.filter((ev) => ev.event === "send-overflow");
    assert.deepEqual(overflows, [], "no session overflowed");
    assert.ok(r.flow().peakBuffered <= 3 * 1024 * 1024, `peak queued ${r.flow().peakBuffered}`);
    assert.ok(r.flow().peakBuffered < 64 * 1024, `peak queued ${r.flow().peakBuffered}: only short errors were sent`);
  } finally {
    for (const s of sessions) s.ws.terminate();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 7: the relay pings each socket; an idle one (nothing outstanding) that shows no sign of life for three heartbeats is terminated and frees its slot", async () => {
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
    const timeouts = r.events.filter((ev) => ev.event === "heartbeat-timeout");
    assert.equal(timeouts.length, 8, JSON.stringify(r.events.map((ev) => ev.event)));
    // Freed after 3 quiet beats, at the beat that sees it: within 4 beats of its last sign of life.
    // (Interval timers drift by a few ms either way, so the bounds carry a margin.)
    for (const t of timeouts) assert.ok(t.silentMs >= 550 && t.silentMs <= 900, JSON.stringify(t));
    await new Promise((resolve) => setTimeout(resolve, 100));
    const ninth = machine(r.url, e.machine, r.origin);
    assert.deepEqual(await ninth.outcome, { welcome: true }, "the dead sessions' slots are free");
    assert.equal(live.closed(), undefined, "a socket that answers pings stays open");
    for (const s of [...stuck, ninth, live]) s.ws.terminate();
  } finally {
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

// Round 8.

/** A client WebSocket frame (masked, as RFC 6455 requires of a client), with a zero key. */
function clientFrame(opcode: number, payload: Buffer): Buffer {
  const head = payload.length < 126 ? Buffer.from([0x80 | opcode, 0x80 | payload.length])
    : Buffer.from([0x80 | opcode, 0x80 | 126, payload.length >> 8, payload.length & 0xff]);
  return Buffer.concat([head, Buffer.alloc(4), payload]);
}

/**
 * A machine over a raw socket that reads at `bytesPerSecond`, a slice every 50 ms, from its socket in paused mode: Node
 * stops reading the kernel once its own buffer holds 64 KiB, so the relay sees a reader at exactly that pace. It answers
 * the relay's pings, acks every delivery, and reports what it got.
 */
async function slowReader(port: number, m: Estate["machine"], relay: string, bytesPerSecond: number, reading: () => boolean = () => true, acks = true, pongs = true) {
  const socket = tcp(port, "127.0.0.1");
  socket.on("error", () => {});
  await new Promise<void>((resolve) => socket.on("connect", () => resolve()));
  socket.pause();
  socket.write(["GET /v1/connect HTTP/1.1", "Host: 127.0.0.1", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Version: 13",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol: fabric-relay.v1", "", ""].join("\r\n"));
  const frames: Array<Record<string, any>> = [];
  let pending = Buffer.alloc(0);
  let upgraded = false;
  let closed: number | undefined;
  socket.on("close", () => { closed ??= 1006; });
  const take = (chunk: Buffer) => {
    pending = Buffer.concat([pending, chunk]);
    if (!upgraded) {
      const end = pending.indexOf("\r\n\r\n");
      if (end < 0) return;
      pending = pending.subarray(end + 4);
      upgraded = true;
    }
    for (;;) {
      if (pending.length < 2) return;
      const opcode = pending[0]! & 0x0f;
      let length = pending[1]! & 0x7f, offset = 2;
      if (length === 126) { if (pending.length < 4) return; length = pending.readUInt16BE(2); offset = 4; }
      else if (length === 127) { if (pending.length < 10) return; length = Number(pending.readBigUInt64BE(2)); offset = 10; }
      if (pending.length < offset + length) return;
      const payload = pending.subarray(offset, offset + length);
      pending = pending.subarray(offset + length);
      if (opcode === 9 && pongs) socket.write(clientFrame(10, Buffer.from(payload)));
      else if (opcode === 8) closed = payload.length >= 2 ? payload.readUInt16BE(0) : 1005;
      else if (opcode === 1) {
        const frame = JSON.parse(payload.toString("utf8"));
        frames.push(frame);
        if (frame.type === "hello") socket.write(clientFrame(1, Buffer.from(authFrame(m, relay, frame.nonce))));
        if (frame.type === "deliver" && acks) socket.write(clientFrame(1, Buffer.from(JSON.stringify({ v: 1, type: "ack", id: `k${frame.seq}`, seq: frame.seq }))));
      }
    }
  };
  const slice = Math.max(1, Math.round(bytesPerSecond / 20));
  const reader = setInterval(() => {
    if (!reading()) return;
    if (socket.readableLength === 0) socket.read(0); // ask Node to fill its buffer from the kernel
    const chunk = socket.read(Math.min(slice, socket.readableLength)) as Buffer | null;
    if (chunk) take(chunk);
  }, 50);
  return { frames, closed: () => closed, stop: () => { clearInterval(reader); socket.destroy(); } };
}

test("round 10: a slow reader (20 KiB/s) that acks every delivery gets its whole backlog: unconfirmed bytes are never a heartbeat death", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  // About 160 KiB queued: all of it fits in the kernel's buffers at once, so the relay's writes stop at once, and its
  // ping waits behind all of it (about 8 s at this pace) while the heartbeat beats every 0.2 s. Only the rule "never
  // terminate a socket with bytes outstanding" keeps this reader: at 958f16a it was terminated before its first pong.
  const mailbox = await prefill(root, e, 3, 40);
  const r = await relay(root, mailbox, { heartbeatMs: 200 });
  const port = Number(new URL(r.url).port);
  const a = await slowReader(port, e.machine, r.origin, 20 * 1024);
  try {
    const end = Date.now() + 30_000;
    while (Date.now() < end && a.frames.filter((f) => f.type === "deliver").length < 3 && a.closed() === undefined) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const told = JSON.stringify(r.events);
    assert.equal(a.frames.filter((f) => f.type === "deliver").length, 3, `closed ${a.closed()}; ${told}`);
    assert.equal(a.closed(), undefined, told);
    assert.ok(!r.events.some((ev) => ev.event === "heartbeat-timeout"), told);
    const until = Date.now() + 3000;
    while ((await mailbox.pending(e.machine.kid, new Date(), 0)).length > 0 && Date.now() < until) await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal((await mailbox.pending(e.machine.kid, new Date(), 0)).length, 0, "every delivery acked");
  } finally {
    a.stop();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 10: a dead peer with a backlog is left to the idle close (5 min while bytes are outstanding), not the heartbeat (fake clock), and its slot frees", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const mailbox = await prefill(root, e, 8, 760);
  let skew = 0;
  const r = await relay(root, mailbox, { heartbeatMs: 100, maxSessionsPerMachine: 1, now: () => new Date(Date.now() + skew) });
  const a = machine(r.url, e.machine, r.origin, (ws) => ws.pause()); // reads nothing after its welcome, answers no ping
  try {
    assert.deepEqual(await a.outcome, { welcome: true });
    await new Promise((resolve) => setTimeout(resolve, 1500)); // 15 beats: bytes are outstanding, so no heartbeat death
    assert.ok(!r.events.some((ev) => ev.event === "heartbeat-timeout"), JSON.stringify(r.events));
    const blocked = machine(r.url, e.machine, r.origin);
    assert.equal((await blocked.outcome).close, 1013, "the dead peer still holds the one slot");
    skew = 301_000; // 301 s pass on the wall clock the sessions read: the next beats run the hub's due idle close
    await new Promise((resolve) => setTimeout(resolve, 500));
    skew = 0; // back to now, so a new machine's auth (signed with the real time) is within its window
    const end = Date.now() + 3000;
    let after: Awaited<ReturnType<typeof machine>["outcome"]> | undefined;
    while (Date.now() < end) {
      await new Promise((resolve) => setTimeout(resolve, 200));
      const again = machine(r.url, e.machine, r.origin);
      after = await again.outcome;
      again.ws.terminate();
      if (after.welcome) break;
    }
    assert.deepEqual(after, { welcome: true }, `the idle close freed the slot: ${JSON.stringify(r.events.map((ev) => ev.event))}`);
    assert.ok(!r.events.some((ev) => ev.event === "heartbeat-timeout"));
    assert.equal((await mailbox.pending(e.machine.kid, new Date(), 0)).length, 8, "nothing acked, nothing lost");
  } finally {
    a.ws.terminate();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 10: a socket whose writes are backed up gets no second ping behind an unwritten one", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const mailbox = await prefill(root, e, 8, 760); // about 8 MiB: the kernel's buffers fill and the relay holds the rest
  const r = await relay(root, mailbox, { heartbeatMs: 50 });
  const a = machine(r.url, e.machine, r.origin, (ws) => ws.pause());
  try {
    assert.deepEqual(await a.outcome, { welcome: true });
    await new Promise((resolve) => setTimeout(resolve, 2000)); // 40 beats
    const flow = r.flow();
    assert.ok(flow.pingsSent <= 3, JSON.stringify(flow));
    assert.ok(flow.pingsSkipped >= 30, JSON.stringify(flow));
  } finally {
    a.ws.terminate();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 10: the heartbeat runs on a monotonic clock: a wall clock stepped 30 s either way, or a stalled loop, kills no healthy peer and spares no dead one", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const r = await relay(root, new SqliteMailbox(join(root, "mailbox.sqlite")), { heartbeatMs: 200 });
  const peers = [machine(r.url, e.machine, r.origin), machine(r.url, e.second, r.origin)]; // they read: ws answers pings
  const realNow = Date.now;
  try {
    for (const p of peers) assert.deepEqual(await p.outcome, { welcome: true });
    await new Promise((resolve) => setTimeout(resolve, 600));
    Date.now = () => realNow() + 30_000; // an NTP step
    await new Promise((resolve) => setTimeout(resolve, 1000));
    Date.now = realNow;
    const stalled = realNow() + 2000; // the loop stalls for 10 beats
    while (realNow() < stalled) { /* busy */ }
    await new Promise((resolve) => setTimeout(resolve, 1000));
    assert.ok(!r.events.some((ev) => ev.event === "heartbeat-timeout"), JSON.stringify(r.events));
    for (const p of peers) assert.equal(p.closed(), undefined);
    // And a wall clock stepped 30 s back does not make a dead idle peer immortal: it is still freed within a few beats.
    const dead = machine(r.url, e.machine, r.origin, (ws) => ws.pause());
    assert.deepEqual(await dead.outcome, { welcome: true });
    Date.now = () => realNow() - 30_000;
    const end = realNow() + 3000;
    while (!r.events.some((ev) => ev.event === "heartbeat-timeout") && realNow() < end) await new Promise((resolve) => setTimeout(resolve, 50));
    Date.now = realNow;
    assert.equal(r.events.filter((ev) => ev.event === "heartbeat-timeout").length, 1, JSON.stringify(r.events.map((ev) => ev.event)));
    for (const p of peers) assert.equal(p.closed(), undefined);
    dead.ws.terminate();
  } finally {
    Date.now = realNow;
    for (const p of peers) p.ws.terminate();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

/** A paused (never reading) session flooding pings with `idLength`-character ids until the relay logs send-overflow. */
async function overflow(extra: Record<string, unknown>, idLength: number, char = "x", inspect?: (r: Awaited<ReturnType<typeof relay>>) => void) {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const r = await relay(root, new SqliteMailbox(join(root, "mailbox.sqlite")), extra);
  const a = machine(r.url, e.machine, r.origin);
  try {
    assert.deepEqual(await a.outcome, { welcome: true });
    a.ws.pause();
    const pad = char.repeat(Math.max(0, idLength - 8));
    let n = 0;
    const until = Date.now() + 30_000;
    while (!r.events.some((ev) => ev.event === "send-overflow") && Date.now() < until) {
      for (let k = 0; k < 2000; k += 1) a.ws.send(JSON.stringify({ v: 1, type: "ping", id: `${n++}`.padStart(8, "0") + pad }));
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    inspect?.(r);
    const found = r.events.find((ev) => ev.event === "send-overflow");
    // No overflow in 30 s: say what the relay did meanwhile, so a failure on a CI runner can be read from its log.
    assert.ok(found, `no send-overflow after ${n} pings: client closed ${JSON.stringify(a.closed())}, client unsent ${a.ws.bufferedAmount}, peak queued ${r.flow().peakBuffered}, events ${JSON.stringify(r.events.slice(-12))}`);
    return found;
  } finally {
    a.ws.terminate();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
}

test("round 8: the byte cap alone stops a non-reader at 3 MiB queued (the frame cap set aside)", async () => {
  let peak = 0;
  // Ids of four-byte characters (still 128 code points): each pong is about 550 bytes, so 3 MiB is reached quickly.
  const event = await overflow({ sendFramesCap: Infinity }, 128, "\u{1F600}", (r) => { peak = r.flow().peakBuffered; });
  assert.ok(event, "no send-overflow");
  // Checked before the write: what is queued stays within 3 MiB, and the frame that would have passed it is not written.
  // The peak is read after every write, so a check made after the write (which lets one frame through) is caught too.
  assert.ok(peak > 0 && peak <= 3 * 1024 * 1024, `peak queued ${peak}`);
  assert.ok(event.bufferedAmount <= 3 * 1024 * 1024 && event.bufferedAmount + event.frame > 3 * 1024 * 1024, JSON.stringify(event));
  assert.ok(event.frames > 4096, `the byte cap tripped, not the frame cap: ${JSON.stringify(event)}`);
});

test("round 8: the frame cap alone stops a non-reader at 4096 queued frames (the byte cap set aside)", async () => {
  const event = await overflow({ sendCap: Infinity }, 128);
  assert.ok(event, "no send-overflow");
  assert.equal(event.frames, 4096, JSON.stringify(event));
  assert.ok(event.bufferedAmount < 3 * 1024 * 1024, JSON.stringify(event));
});

// Round 12: only the peer's progress is activity (never the relay's own pings), and a session with bytes outstanding
// gets IDLE_OUTSTANDING_MS (5 min) instead of 90 s.

test("round 12: a client that answers pings but sends no frame is idle-closed at 90 s: the relay's own pings are not its activity", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  let skew = 0;
  const r = await relay(root, new SqliteMailbox(join(root, "mailbox.sqlite")), { heartbeatMs: 100, now: () => new Date(Date.now() + skew) });
  const a = machine(r.url, e.machine, r.origin); // reads, so ws answers every ping; sends nothing
  try {
    assert.deepEqual(await a.outcome, { welcome: true });
    await new Promise((resolve) => setTimeout(resolve, 1000)); // 10 pings written and answered
    skew = 87_000; // 88.x s since its welcome
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(a.closed(), undefined, "under 90 s: not idle yet");
    skew = 91_000;
    const end = Date.now() + 3000;
    while (a.closed() === undefined && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(a.closed(), 1001, JSON.stringify(r.events));
    assert.ok(r.events.some((ev) => ev.event === "idle-close" && ev.limitMs === 90_000), JSON.stringify(r.events));
  } finally {
    a.ws.terminate();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 12: a frozen peer with one delivery unconfirmed keeps no slot past the 5 min bound, and is not cut at 90 s", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const mailbox = await prefill(root, e, 1, 15); // about 20 KiB: in the kernel at once, never confirmed by a pong
  let skew = 0;
  const r = await relay(root, mailbox, { heartbeatMs: 100, now: () => new Date(Date.now() + skew) });
  const a = machine(r.url, e.machine, r.origin, (ws) => ws.pause()); // frozen after its welcome (SIGSTOP)
  try {
    assert.deepEqual(await a.outcome, { welcome: true });
    await new Promise((resolve) => setTimeout(resolve, 1000));
    assert.ok(!r.events.some((ev) => ev.event === "heartbeat-timeout"), "bytes outstanding: not the heartbeat's to end");
    skew = 200_000; // past 90 s, inside 5 min
    await new Promise((resolve) => setTimeout(resolve, 500));
    assert.ok(!r.events.some((ev) => ev.event === "idle-close"), JSON.stringify(r.events));
    skew = 301_000; // past 5 min: freed, and its pings in the meantime did not count as its activity
    const end = Date.now() + 3000;
    while (!r.events.some((ev) => ev.event === "idle-close") && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 50));
    const close = r.events.find((ev) => ev.event === "idle-close");
    assert.ok(close, JSON.stringify(r.events));
    assert.equal(close.limitMs, 300_000);
    assert.equal((await mailbox.pending(e.machine.kid, new Date(), 0)).length, 1, "nothing acked, nothing lost");
  } finally {
    a.ws.terminate();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 12: a bursty slow reader (Linux-shaped: no progress for 120 s at a time, about 10 KiB/s overall) gets its whole backlog", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const mailbox = await prefill(root, e, 3, 760);
  // A clock 20 times faster than real time: 6 s of real silence is 120 s on the clock the sessions read. Linux tells the
  // relay its socket is writable only once about a third of the send buffer is free, so a slow reader's progress comes
  // in steps that long; between them nothing shows it is alive. 90 s would cut it; 5 min does not.
  const base = Date.now();
  const r = await relay(root, mailbox, { heartbeatMs: 2000, now: () => new Date(base + (Date.now() - base) * 20) });
  const port = Number(new URL(r.url).port);
  const started = Date.now();
  // Reads 1.5 s, then nothing for 6 s, and again: 1 MiB/s while reading, about 200 KiB/s real, 10 KiB/s on the clock.
  // (Slower than that, on Linux one burst may not free a third of the send buffer: no step at all between two bursts,
  // which is below the floor docs/protocol/sessions.md states.)
  const a = await slowReader(port, e.machine, r.origin, 1024 * 1024, () => (Date.now() - started) % 7500 < 1500);
  try {
    const end = Date.now() + 60_000;
    while (Date.now() < end && a.frames.filter((f) => f.type === "deliver").length < 3 && a.closed() === undefined) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const told = JSON.stringify(r.events);
    assert.equal(a.frames.filter((f) => f.type === "deliver").length, 3, `closed ${a.closed()}; ${told}`);
    assert.equal(a.closed(), undefined, told);
    assert.ok(!r.events.some((ev) => ev.event === "idle-close" || ev.event === "heartbeat-timeout"), told);
  } finally {
    a.stop();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

// Round 13: progress is only what the peer confirms (a matched pong or a frame); the relay answers WebSocket pings itself,
// under the send caps.

/** A raw machine that floods WebSocket pings (125-byte payloads) and never reads. */
async function pingFlooder(port: number, m: Estate["machine"], relay: string) {
  const socket = tcp(port, "127.0.0.1");
  socket.on("error", () => {});
  await new Promise<void>((resolve) => socket.on("connect", () => resolve()));
  socket.write(["GET /v1/connect HTTP/1.1", "Host: 127.0.0.1", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Version: 13",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol: fabric-relay.v1", "", ""].join("\r\n"));
  let got = "";
  await new Promise<void>((resolve) => {
    socket.on("data", (chunk: Buffer) => {
      got += chunk.toString("latin1");
      const nonce = /"nonce":"([^"]+)"/.exec(got)?.[1];
      if (nonce && !got.includes("AUTHSENT")) { got += "AUTHSENT"; socket.write(clientFrame(1, Buffer.from(authFrame(m, relay, nonce)))); }
      if (got.includes('"type":"welcome"')) resolve();
    });
  });
  socket.pause(); // never read again
  return socket;
}

test("round 13: a machine flooding WebSocket pings it never reads cannot queue pongs past the send cap: send-overflow, 1008", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const r = await relay(root, new SqliteMailbox(join(root, "mailbox.sqlite")));
  const port = Number(new URL(r.url).port);
  const socket = await pingFlooder(port, e.machine, r.origin);
  try {
    const ping = clientFrame(9, Buffer.alloc(125, 7));
    // At most 64 MiB of pings (about 500 000): far past what fills any kernel's buffers and the 3 MiB cap, and a bound
    // on what a broken relay (pongs outside the caps) is made to queue before the test fails.
    const end = Date.now() + 20_000;
    let sent = 0;
    while (!r.events.some((ev) => ev.event === "send-overflow") && Date.now() < end && sent < 64 * 1024 * 1024) {
      const batch = Buffer.concat(Array.from({ length: 2000 }, () => ping));
      sent += batch.length;
      if (!socket.write(batch)) await new Promise((resolve) => { socket.once("drain", resolve); setTimeout(resolve, 200); });
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.ok(r.events.some((ev) => ev.event === "send-overflow"), `no overflow: ws's own autoPong would queue without bound (${JSON.stringify(r.events.map((ev) => ev.event))})`);
    assert.ok(r.flow().peakBuffered <= 3 * 1024 * 1024, `peak queued ${r.flow().peakBuffered}`);
  } finally {
    socket.destroy();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 13: a frozen peer that keeps receiving mail is still freed within 5 minutes: the relay's writes are not its progress", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const mailbox = new SqliteMailbox(join(root, "mailbox.sqlite"));
  let skew = 0;
  const r = await relay(root, mailbox, { heartbeatMs: 100, now: () => new Date(Date.now() + skew) });
  const frozen = machine(r.url, e.machine, r.origin, (ws) => ws.pause()); // SIGSTOP after its welcome
  const sender = machine(r.url, e.second, r.origin);
  try {
    assert.deepEqual(await frozen.outcome, { welcome: true });
    assert.deepEqual(await sender.outcome, { welcome: true });
    const body = Buffer.alloc(6 * 1024, 3).toString("base64url");
    // One 6 KiB message every 60 s of the clock the sessions read (the sender stays inside its own 90 s), up to 420 s:
    // the kernel takes each one, and the frozen peer confirms none.
    for (let n = 1; n <= 7 && !r.events.some((ev) => ev.event === "idle-close" && ev.kid === e.machine.kid); n += 1) {
      skew = n * 60_000;
      sender.ws.send(JSON.stringify({ v: 1, type: "send", id: `s${n}`, to: e.machine.kid, msgId: `m-${n}`, body, ttl: 3600 }));
      await new Promise((resolve) => setTimeout(resolve, 600));
    }
    const close = r.events.find((ev) => ev.event === "idle-close" && ev.kid === e.machine.kid);
    assert.ok(close, `the frozen peer was never freed: ${JSON.stringify(r.events)}`);
    assert.ok(close.silentMs > 300_000 && close.silentMs <= 300_000 + 60_000 + 1000 && close.limitMs === 300_000, JSON.stringify(close));
    assert.equal(sender.closed(), undefined, "the sender, which sends frames, stays");
  } finally {
    frozen.ws.terminate();
    sender.ws.terminate();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 13: a client that only sends WebSocket pings is idle-closed at 90 s: a transport ping is answered, never activity", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  let skew = 0;
  const r = await relay(root, new SqliteMailbox(join(root, "mailbox.sqlite")), { heartbeatMs: 100, now: () => new Date(Date.now() + skew) });
  const a = machine(r.url, e.machine, r.origin);
  const pongs: number[] = [];
  try {
    assert.deepEqual(await a.outcome, { welcome: true });
    a.ws.on("pong", () => pongs.push(Date.now()));
    let sent = 0;
    const pinger = setInterval(() => { a.ws.ping(Buffer.from("keepalive")); sent += 1; }, 50);
    await new Promise((resolve) => setTimeout(resolve, 500));
    assert.ok(pongs.length > 3, "the relay answers its pings");
    assert.ok(pongs.length <= sent, `one pong per ping: ${pongs.length} pongs for ${sent} pings (ws's own autoPong would double them)`);
    // The clock moves 30 s at a time while the pings go on, so pings that counted as activity would keep it open.
    for (let step = 1; step <= 5 && a.closed() === undefined; step += 1) {
      skew = step * 30_000;
      await new Promise((resolve) => setTimeout(resolve, 400));
    }
    const end = Date.now() + 2000;
    while (a.closed() === undefined && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 50));
    clearInterval(pinger);
    assert.equal(a.closed(), 1001, JSON.stringify(r.events));
  } finally {
    a.ws.terminate();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 13: at most 64 heartbeat pings await their pongs: the 65th is not sent", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const mailbox = await prefill(root, e, 1, 15); // 20 KiB never confirmed: outstanding, so never the heartbeat's to end
  const r = await relay(root, mailbox, { heartbeatMs: 20 });
  // A client that reads everything but answers no ping (autoPong off): every ping is written and stays unanswered.
  const ws = new WebSocket(r.url, "fabric-relay.v1", { autoPong: false });
  ws.on("error", () => {});
  const welcomed = new Promise<void>((resolve) => ws.on("message", (data) => {
    const frame = JSON.parse(String(data));
    if (frame.type === "hello") ws.send(authFrame(e.machine, r.origin, frame.nonce));
    if (frame.type === "welcome") resolve();
  }));
  try {
    await welcomed;
    // Beats until 64 pings await their pongs (under load a beat can come late, so this waits for the count, not a time),
    // then 50 more beats: not one more ping. Without the cap every beat sends one.
    const end = Date.now() + 15_000;
    while (r.flow().pingsSent < 64 && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 50));
    const at64 = r.flow();
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const flow = r.flow();
    assert.equal(at64.pingsSent, 64, `${JSON.stringify(at64)} ${JSON.stringify(r.events)}`);
    assert.equal(flow.pingsSent, 64, `a ping past 64 awaiting: ${JSON.stringify(flow)}`);
    assert.ok(flow.pingsSkipped - at64.pingsSkipped >= 20, JSON.stringify(flow));
    assert.ok(!r.events.some((ev) => ev.event === "heartbeat-timeout"), "bytes outstanding: not the heartbeat's to end");
  } finally {
    ws.terminate();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 13: unsolicited or unknown pongs confirm nothing: an idle peer that sends them instead of answering is still freed", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const r = await relay(root, new SqliteMailbox(join(root, "mailbox.sqlite")), { heartbeatMs: 100 });
  const ws = new WebSocket(r.url, "fabric-relay.v1", { autoPong: false }); // answers no ping
  ws.on("error", () => {});
  const frames: Array<Record<string, any>> = [];
  const welcomed = new Promise<void>((resolve) => ws.on("message", (data) => {
    const frame = JSON.parse(String(data));
    frames.push(frame);
    if (frame.type === "hello") ws.send(authFrame(e.machine, r.origin, frame.nonce));
    if (frame.type === "welcome") resolve();
  }));
  try {
    await welcomed;
    const unknown = Buffer.alloc(8);
    unknown.writeBigUInt64BE(2n ** 63n); // a sequence number the relay never sent
    const spoofer = setInterval(() => { ws.pong(unknown); ws.pong(); ws.pong(Buffer.from("x")); }, 30);
    const end = Date.now() + 3000;
    while (!r.events.some((ev) => ev.event === "heartbeat-timeout") && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 50));
    clearInterval(spoofer);
    assert.ok(r.events.some((ev) => ev.event === "heartbeat-timeout"), JSON.stringify(r.events.map((ev) => ev.event)));
  } finally {
    ws.terminate();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 13: a slow reader that never acks keeps its session on matched pongs alone", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const mailbox = await prefill(root, e, 8, 760);
  // A clock 20 times faster than real time and the default idle limit of 300 s on it (15 s real) while bytes are
  // outstanding: the reader reads 1 s of every 3 s (about 340 KiB/s real) and sends no frame at all, so only the pongs to
  // the relay's pings (every 10 s on the clock) show it alive; they come back about once per delivery read (1 MiB),
  // every 3 to 6 s real (up to 10 s under load). The backlog takes about 24 s real, so with matched pongs not counted it
  // is idle-closed.
  const base = Date.now();
  const r = await relay(root, mailbox, { heartbeatMs: 500, now: () => new Date(base + (Date.now() - base) * 20) });
  const port = Number(new URL(r.url).port);
  const started = Date.now();
  const a = await slowReader(port, e.machine, r.origin, 1024 * 1024, () => (Date.now() - started) % 3000 < 1000, false);
  try {
    const end = Date.now() + 60_000;
    while (Date.now() < end && a.frames.filter((f) => f.type === "deliver").length < 8 && a.closed() === undefined) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const told = JSON.stringify(r.events);
    assert.equal(a.frames.filter((f) => f.type === "deliver").length, 8, `closed ${a.closed()}; ${told}`);
    assert.equal(a.closed(), undefined, told);
    // Each delivery is followed by a marker ping, so the reader confirms each one as soon as it has read it.
    assert.ok(r.flow().marks >= 8, JSON.stringify(r.flow()));
  } finally {
    a.stop();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});

test("round 13: a reader that reads but never confirms (no pong, no frame) is freed within 5 minutes: drains are not its progress", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const mailbox = await prefill(root, e, 8, 760);
  let skew = 0;
  const r = await relay(root, mailbox, { heartbeatMs: 200, now: () => new Date(Date.now() + skew) });
  const port = Number(new URL(r.url).port);
  // Reads 512 KiB/s, so the relay's writes back up and drain again and again, but answers no ping and acks nothing.
  const a = await slowReader(port, e.machine, r.origin, 512 * 1024, () => true, false, false);
  try {
    const welcomed = Date.now() + 5000;
    while (!a.frames.some((f) => f.type === "welcome") && Date.now() < welcomed) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.ok(a.frames.some((f) => f.type === "welcome"), JSON.stringify(r.events));
    for (let step = 1; step <= 7 && !r.events.some((ev) => ev.event === "idle-close"); step += 1) {
      skew = step * 60_000;
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    const close = r.events.find((ev) => ev.event === "idle-close");
    assert.ok(close, `never freed: ${JSON.stringify(r.events.map((ev) => ev.event))}`);
    assert.ok(close.limitMs === 300_000 && close.silentMs <= 300_000 + 60_000 + 1000, JSON.stringify(close));
  } finally {
    a.stop();
    await within(r.stop({ graceMs: 200 }), 3000);
  }
});
