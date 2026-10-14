// Graceful shutdown of the portable relay (RLY-010): SIGTERM closes every session 1001 ("going away") through the
// estate hub, records lastSeen, closes the SQLite stores and exits 0; a socket that ignores the close is terminated
// at the grace period; an upgrade that arrives while the relay stops is refused 503.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { sign } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { connect as tcp } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { relayAuthSigningInput } from "../src/contract/relay.ts";
import { FsBlobStore, FsEstateSource } from "../src/portable/fs-store.ts";
import { serve } from "../src/portable/server.ts";
import { SqliteLastSeen } from "../src/portable/sqlite-last-seen.ts";
import { SqliteMailbox } from "../src/portable/sqlite-mailbox.ts";
import { estate, type Estate } from "./estate-fixture.ts";

const roots: string[] = [];
after(async () => { for (const root of roots) await rm(root, { recursive: true, force: true }); });

async function dataDir(e: Estate): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "relay-stop-"));
  roots.push(root);
  await mkdir(join(root, "estate", "revisions"), { recursive: true });
  await writeFile(join(root, "estate", "pinned.json"), JSON.stringify(e.pinned));
  await writeFile(join(root, "estate", "revisions", "1.json"), JSON.stringify(e.record));
  return root;
}

function authFrame(m: Estate["machine"], relay: string, nonce: string): string {
  const iat = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const fields = { relay, nonce, estate: "estate-5d0f1a", kid: m.kid, iat };
  const sig = sign("sha256", Buffer.from(relayAuthSigningInput(fields)), { key: m.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return JSON.stringify({ v: 1, type: "auth", id: "a1", protocol: "fabric-relay/0.1", alg: "ES256", ...fields, sig });
}

/** An admitted session: resolves once `welcome` arrived; `closed` resolves with the close code and when it came. */
async function admitted(url: string, m: Estate["machine"], relay: string) {
  const ws = new WebSocket(url, "fabric-relay.v1");
  const frames: Array<Record<string, any>> = [];
  let onWelcome: () => void;
  const welcome = new Promise<void>((resolve) => { onWelcome = resolve; });
  const closed = new Promise<{ code: number; at: number }>((resolve) => ws.addEventListener("close", (event) => resolve({ code: event.code, at: Date.now() })));
  ws.addEventListener("message", (event) => {
    const frame = JSON.parse(String(event.data));
    frames.push(frame);
    if (frame.type === "hello") ws.send(authFrame(m, relay, frame.nonce));
    if (frame.type === "welcome") onWelcome();
  });
  await Promise.race([welcome, new Promise((_, reject) => setTimeout(() => reject(new Error(`no welcome: ${JSON.stringify(frames)}`)), 5000))]);
  return { ws, frames, closed };
}

test("SIGTERM with a pinging admitted session: the client gets 1001 within 1 s, the process exits 0 within 3 s, and logs stopped", async () => {
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
  const exited = new Promise<{ code: number | null; at: number }>((resolve) => child.on("exit", (code) => resolve({ code, at: Date.now() })));
  try {
    const end = Date.now() + 10_000;
    while (!lines.some((l) => l.event === "listening") && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 50));
    const port = lines.find((l) => l.event === "listening")?.port;
    assert.ok(port, JSON.stringify(lines));
    const a = await admitted(`ws://127.0.0.1:${port}/v1/connect`, e.machine, "https://relay.test");
    const pinger = setInterval(() => a.ws.send(JSON.stringify({ v: 1, type: "ping", id: `p${Date.now()}` })), 2000);
    await new Promise((resolve) => setTimeout(resolve, 2100)); // one ping answered, the next one on its way
    const sent = Date.now();
    child.kill("SIGTERM");
    const close = await Promise.race([a.closed, new Promise<undefined>((resolve) => setTimeout(resolve, 5000))]);
    clearInterval(pinger);
    assert.ok(close, "no close came while the session pinged");
    assert.equal(close.code, 1001);
    assert.ok(close.at - sent < 1000, `close after ${close.at - sent} ms`);
    const exit = await Promise.race([exited, new Promise<undefined>((resolve) => setTimeout(resolve, 5000))]);
    assert.ok(exit, "the process did not exit");
    assert.equal(exit.code, 0);
    assert.ok(exit.at - sent < 3000, `exit after ${exit.at - sent} ms`);
    const stopped = lines.find((l) => l.event === "stopped");
    assert.ok(stopped, JSON.stringify(lines.map((l) => l.event)));
    assert.deepEqual([stopped.sessions, stopped.forced, stopped.service, stopped.runtime], [1, 0, "relay", "portable"]);
  } finally {
    if (child.exitCode === null) child.kill("SIGKILL");
  }
});

test("stop(): lastSeen is recorded at the stop, both SQLite stores are closed, a socket that ignores the close is terminated at the grace period", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const events: Array<Record<string, any>> = [];
  const lastSeen = new SqliteLastSeen(join(root, "presence.sqlite"));
  const mailbox = new SqliteMailbox(join(root, "mailbox.sqlite"));
  const relay = await serve({ runtime: "portable", blobs: new FsBlobStore(root) }, { host: "127.0.0.1", port: 0, estate: new FsEstateSource(root), mailbox, lastSeen, log: (event) => events.push(event) });
  const port = (relay.server.address() as AddressInfo).port;
  const a = await admitted(`ws://127.0.0.1:${port}/v1/connect`, e.machine, relay.origin);
  // A raw upgrade that never answers a close frame: the relay must not wait for it past the grace period.
  const stubborn = tcp(port, "127.0.0.1");
  await new Promise<void>((resolve) => stubborn.on("connect", () => resolve()));
  stubborn.write(["GET /v1/connect HTTP/1.1", "Host: 127.0.0.1", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Version: 13",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol: fabric-relay.v1", "", ""].join("\r\n"));
  stubborn.on("data", () => {}); // read, never reply
  const stubbornClosed = new Promise<void>((resolve) => stubborn.on("close", () => resolve()));
  await new Promise((resolve) => setTimeout(resolve, 200));
  const before = Date.now();
  const result = await relay.stop({ graceMs: 300 });
  assert.deepEqual(result, { sessions: 2, forced: 1 });
  assert.equal((await a.closed).code, 1001);
  await stubbornClosed;
  assert.ok(Date.now() - before < 2000);
  const seen = Date.parse(new SqliteLastSeen(join(root, "presence.sqlite")).get(e.machine.kid) ?? "");
  assert.ok(seen >= before - 1000 && seen <= Date.now(), "lastSeen is the stop time");
  assert.throws(() => lastSeen.get(e.machine.kid), "the lastSeen handle is closed");
  await assert.rejects(mailbox.pending(e.machine.kid, new Date()), "the mailbox handle is closed");
  const stopped = events.find((event) => event.event === "stopped");
  assert.deepEqual([stopped?.sessions, stopped?.forced], [2, 1]);
});

test("an upgrade that arrives while the relay stops is refused 503", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const relay = await serve({ runtime: "portable", blobs: new FsBlobStore(root) }, { host: "127.0.0.1", port: 0, estate: new FsEstateSource(root) });
  const port = (relay.server.address() as AddressInfo).port;
  const a = await admitted(`ws://127.0.0.1:${port}/v1/connect`, e.machine, relay.origin);
  // Keep the stop waiting on a socket that ignores the close, so the relay is still listening while it stops.
  const stubborn = tcp(port, "127.0.0.1");
  await new Promise<void>((resolve) => stubborn.on("connect", () => resolve()));
  stubborn.write(["GET /v1/connect HTTP/1.1", "Host: 127.0.0.1", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Version: 13",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol: fabric-relay.v1", "", ""].join("\r\n"));
  stubborn.on("data", () => {});
  await new Promise((resolve) => setTimeout(resolve, 200));
  const stopping = relay.stop({ graceMs: 1000 });
  const status = await new Promise<string>((resolve) => {
    const late = tcp(port, "127.0.0.1", () => late.write(["GET /v1/connect HTTP/1.1", "Host: 127.0.0.1", "Upgrade: websocket", "Connection: Upgrade",
      "Sec-WebSocket-Version: 13", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol: fabric-relay.v1", "", ""].join("\r\n")));
    let got = "";
    late.on("data", (chunk) => { got += chunk.toString("latin1"); });
    late.on("close", () => resolve(got.split("\r\n")[0] ?? ""));
    late.on("error", () => resolve(got.split("\r\n")[0] ?? "refused"));
  });
  assert.match(status, /^HTTP\/1\.1 503/);
  await stopping;
  await a.closed;
});

/**
 * Starts the relay, either directly (`node src/portable/main.ts`) or as an operator does, through `npm run portable`,
 * which forwards the signals it receives to the relay. Through npm the tree leads its own process group, so a signal to
 * the group reaches npm and the relay, as a terminal's Ctrl-C does. Lines are the relay's log, one JSON object each.
 */
async function launch(root: string, throughNpm: boolean) {
  const env = { ...process.env, RELAY_DATA_DIR: root, RELAY_PORT: "0", RELAY_HOST: "127.0.0.1", RELAY_ORIGIN: "https://relay.test" };
  const forwarded = throughNpm;
  const child = throughNpm
    ? spawn("npm", ["run", "--silent", "portable"], { env, stdio: ["ignore", "pipe", "inherit"], detached: true })
    : spawn(process.execPath, ["--import", "tsx", "src/portable/main.ts"], { env, stdio: ["ignore", "pipe", "inherit"] });
  const lines: Array<Record<string, any>> = [];
  let buffered = "";
  child.stdout!.on("data", (chunk: Buffer) => {
    buffered += chunk.toString("utf8");
    for (let i = buffered.indexOf("\n"); i >= 0; i = buffered.indexOf("\n")) {
      lines.push(JSON.parse(buffered.slice(0, i)));
      buffered = buffered.slice(i + 1);
    }
  });
  const exited = new Promise<number | null>((resolve) => child.on("exit", (code) => resolve(code)));
  const end = Date.now() + 10_000;
  while (!lines.some((l) => l.event === "listening") && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 50));
  const port = lines.find((l) => l.event === "listening")?.port as number;
  assert.ok(port, JSON.stringify(lines));
  const kill = () => { try { forwarded ? process.kill(-child.pid!, "SIGKILL") : child.kill("SIGKILL"); } catch { /* gone */ } };
  return { child, lines, exited, port, kill, signalGroup: (signal: NodeJS.Signals) => process.kill(-child.pid!, signal) };
}

const within = <T>(promise: Promise<T>, ms: number) => Promise.race([promise, new Promise<undefined>((resolve) => setTimeout(resolve, ms))]);

test("Ctrl-C on `npm run portable` with a session open: the forwarded SIGINT is the same press, the stop is clean, exit 0", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const relay = await launch(root, true);
  try {
    const a = await admitted(`ws://127.0.0.1:${relay.port}/v1/connect`, e.machine, "https://relay.test");
    relay.signalGroup("SIGINT"); // the terminal's Ctrl-C reaches the parent and the relay; the parent forwards it again
    const close = await within(a.closed, 5000);
    assert.equal(close?.code, 1001);
    assert.equal(await within(relay.exited, 8000), 0, JSON.stringify(relay.lines.map((l) => l.event)));
    assert.ok(relay.lines.some((l) => l.event === "stopped"), JSON.stringify(relay.lines.map((l) => l.event)));
    assert.ok(!relay.lines.some((l) => l.event === "stop-forced"));
  } finally {
    relay.kill();
  }
});

test("a distinct second press, over a second after the first, forces the stop: stop-forced, exit 1", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const relay = await launch(root, false);
  try {
    // A socket that never answers a close keeps the graceful stop waiting for its grace period.
    const stubborn = tcp(relay.port, "127.0.0.1");
    await new Promise<void>((resolve) => stubborn.on("connect", () => resolve()));
    stubborn.write(["GET /v1/connect HTTP/1.1", "Host: 127.0.0.1", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Version: 13",
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol: fabric-relay.v1", "", ""].join("\r\n"));
    stubborn.on("data", () => {});
    stubborn.on("error", () => {});
    await new Promise((resolve) => setTimeout(resolve, 300));
    relay.child.kill("SIGINT");
    await new Promise((resolve) => setTimeout(resolve, 1200));
    relay.child.kill("SIGINT");
    assert.equal(await within(relay.exited, 3000), 1);
    assert.deepEqual(relay.lines.filter((l) => ["stopping", "stop-forced"].includes(l.event)).map((l) => l.event), ["stopping", "stop-forced"]);
    stubborn.destroy();
  } finally {
    relay.kill();
  }
});

/** The estate as the data directory holds it, read `delayMs` late: the window in which a stop or a close can land. */
function slowEstate(root: string, delayMs: number) {
  const inner = new FsEstateSource(root);
  return { pinned: async () => { await new Promise((resolve) => setTimeout(resolve, delayMs)); return inner.pinned(); }, revisions: () => inner.revisions() };
}

/** A raw upgrade that completes the handshake and then never answers a close frame. */
async function stuckUpgrade(port: number) {
  const socket = tcp(port, "127.0.0.1");
  await new Promise<void>((resolve) => socket.on("connect", () => resolve()));
  socket.write(["GET /v1/connect HTTP/1.1", "Host: 127.0.0.1", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Version: 13",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol: fabric-relay.v1", "", ""].join("\r\n"));
  socket.on("data", () => {});
  socket.on("error", () => {});
  return socket;
}

test("an upgrade still reading the estate when the stop begins is refused and terminated at the grace period", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const events: Array<Record<string, any>> = [];
  const relay = await serve({ runtime: "portable", blobs: new FsBlobStore(root) }, { host: "127.0.0.1", port: 0, estate: slowEstate(root, 300), log: (event) => events.push(event) });
  const port = (relay.server.address() as AddressInfo).port;
  const stuck = await stuckUpgrade(port);
  await new Promise((resolve) => setTimeout(resolve, 100)); // the handshake is done; the estate read is in flight
  const started = Date.now();
  const result = await within(relay.stop({ graceMs: 600 }), 3000);
  assert.ok(result, "stop() did not resolve");
  assert.ok(Date.now() - started < 1000, `stop took ${Date.now() - started} ms`);
  assert.ok(result.forced >= 1, JSON.stringify(result));
  assert.equal(result.sessions, 0, "the refused upgrade never became a session");
  stuck.destroy();
});

test("a socket that closes while its estate is read never joins the hub", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const relay = await serve({ runtime: "portable", blobs: new FsBlobStore(root) }, { host: "127.0.0.1", port: 0, estate: slowEstate(root, 300) });
  const port = (relay.server.address() as AddressInfo).port;
  const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/connect`, "fabric-relay.v1");
  await new Promise<void>((resolve) => ws.addEventListener("open", () => resolve()));
  ws.close(); // before the estate read ends
  await new Promise((resolve) => setTimeout(resolve, 600));
  assert.deepEqual(await within(relay.stop({ graceMs: 100 }), 3000), { sessions: 0, forced: 0 });
});

test("SIGHUP (the terminal that started the relay closed) stops it gracefully: 1001, stopped, exit 0", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const relay = await launch(root, false);
  try {
    const a = await admitted(`ws://127.0.0.1:${relay.port}/v1/connect`, e.machine, "https://relay.test");
    relay.child.kill("SIGHUP");
    assert.equal((await within(a.closed, 5000))?.code, 1001);
    assert.equal(await within(relay.exited, 8000), 0);
    assert.ok(relay.lines.some((l) => l.event === "stopped"), JSON.stringify(relay.lines.map((l) => l.event)));
  } finally {
    relay.kill();
  }
});

// Round 3: an upgrade the relay refuses (404, 400, 503) to a client that keeps its side open must not hold the stop.
// Upgraded sockets leave the HTTP server's books, so `closeAllConnections()` never sees them and `server.close()` would
// wait for that client for ever.

/** A raw upgrade request from a client that never closes its side (`allowHalfOpen`): `status` is the answer's first line. */
async function halfOpenUpgrade(port: number, lines: string[]) {
  const socket = tcp({ port, host: "127.0.0.1", allowHalfOpen: true });
  socket.on("error", () => {});
  await new Promise<void>((resolve) => socket.on("connect", () => resolve()));
  let got = "";
  socket.on("data", (chunk: Buffer) => { got += chunk.toString("latin1"); });
  const status = new Promise<string>((resolve) => {
    socket.on("end", () => resolve(got.split("\r\n")[0] ?? ""));
    socket.on("close", () => resolve(got.split("\r\n")[0] ?? ""));
  });
  socket.write([...lines, "", ""].join("\r\n"));
  return { socket, status };
}

const GRACE_MS = 5000; // main.ts's grace period
const MARGIN_MS = 1500;

test("E1: SIGTERM after an upgrade refused 400 to a half-open client: stopped, stores closed, exit 0 within the grace period", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const relay = await launch(root, false);
  let client: Awaited<ReturnType<typeof halfOpenUpgrade>> | undefined;
  try {
    // An upgrade with no key and no subprotocol: the relay refuses it 400 and must not keep the socket.
    client = await halfOpenUpgrade(relay.port, ["GET /v1/connect HTTP/1.1", "Host: 127.0.0.1", "Upgrade: websocket", "Connection: Upgrade"]);
    assert.match((await within(client.status, 3000)) ?? "", /^HTTP\/1\.1 400/);
    const sent = Date.now();
    relay.child.kill("SIGTERM");
    const code = await within(relay.exited, GRACE_MS + MARGIN_MS);
    const events = relay.lines.map((l) => l.event);
    assert.equal(code, 0, `exit ${code} after ${Date.now() - sent} ms: ${JSON.stringify(events)}`);
    assert.ok(Date.now() - sent < GRACE_MS + MARGIN_MS, `exit after ${Date.now() - sent} ms`);
    assert.ok(events.includes("stopped") && !events.includes("stop-timeout"), JSON.stringify(events));
    // Closing SQLite checkpoints its WAL and removes it: the stores were closed.
    for (const name of ["mailbox.sqlite-wal", "presence.sqlite-wal"]) assert.ok(!existsSync(join(root, name)), `${name} is left behind`);
  } finally {
    client?.socket.destroy();
    relay.kill();
  }
});

test("S1: an upgrade refused 503 during the grace period to a half-open client does not hold the stop", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const events: Array<Record<string, any>> = [];
  const relay = await serve({ runtime: "portable", blobs: new FsBlobStore(root) }, { host: "127.0.0.1", port: 0, estate: new FsEstateSource(root), log: (event) => events.push(event) });
  const port = (relay.server.address() as AddressInfo).port;
  const stuck = await stuckUpgrade(port); // keeps the stop in its grace period
  await new Promise((resolve) => setTimeout(resolve, 200));
  let late: Awaited<ReturnType<typeof halfOpenUpgrade>> | undefined;
  try {
    const graceMs = 800;
    const started = Date.now();
    const stopping = relay.stop({ graceMs });
    late = await halfOpenUpgrade(port, ["GET /v1/connect HTTP/1.1", "Host: 127.0.0.1", "Upgrade: websocket", "Connection: Upgrade",
      "Sec-WebSocket-Version: 13", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol: fabric-relay.v1"]);
    assert.match((await within(late.status, 2000)) ?? "", /^HTTP\/1\.1 503/);
    const result = await within(stopping, graceMs + MARGIN_MS);
    assert.ok(result, `stop() had not resolved ${Date.now() - started} ms after it began`);
    assert.ok(events.some((event) => event.event === "stopped"));
  } finally {
    late?.socket.destroy();
    stuck.destroy();
  }
});

test("S2: an upgrade refused 404 before the stop, to a half-open client, does not hold the stop", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const relay = await serve({ runtime: "portable", blobs: new FsBlobStore(root) }, { host: "127.0.0.1", port: 0, estate: new FsEstateSource(root) });
  const port = (relay.server.address() as AddressInfo).port;
  const client = await halfOpenUpgrade(port, ["GET /no-such-route HTTP/1.1", "Host: 127.0.0.1", "Upgrade: websocket", "Connection: Upgrade",
    "Sec-WebSocket-Version: 13", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol: fabric-relay.v1"]);
  try {
    assert.match((await within(client.status, 2000)) ?? "", /^HTTP\/1\.1 404/);
    // The refusal itself lets go of the socket, before any stop: the server holds no connection for it.
    const count = () => new Promise<number>((resolve) => relay.server.getConnections((_, n) => resolve(n)));
    const until = Date.now() + 1500;
    while ((await count()) > 0 && Date.now() < until) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(await count(), 0, "the refused upgrade's socket is still open on the server");
    const graceMs = 300;
    const started = Date.now();
    const result = await within(relay.stop({ graceMs }), graceMs + MARGIN_MS);
    assert.ok(result, `stop() had not resolved ${Date.now() - started} ms after it began`);
    assert.equal(result.sessions, 0);
  } finally {
    client.socket.destroy();
    await within(relay.stop({ graceMs: 50 }), 2000); // a failed assertion above must not leave the server listening
  }
});

/** A client text frame, masked with a zero key (RFC 6455 allows any key; zero leaves the payload as it is). */
function clientFrame(text: string): Buffer {
  const payload = Buffer.from(text, "utf8");
  const head = payload.length < 126 ? Buffer.from([0x81, 0x80 | payload.length]) : Buffer.from([0x81, 0x80 | 126, payload.length >> 8, payload.length & 0xff]);
  return Buffer.concat([head, Buffer.alloc(4), payload]);
}

/** An admitted session over a raw socket, so a test can put megabytes of frames on the wire in one write. */
async function rawAdmitted(port: number, m: Estate["machine"], relay: string) {
  const socket = tcp(port, "127.0.0.1");
  socket.on("error", () => {});
  await new Promise<void>((resolve) => socket.on("connect", () => resolve()));
  socket.write(["GET /v1/connect HTTP/1.1", "Host: 127.0.0.1", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Version: 13",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol: fabric-relay.v1", "", ""].join("\r\n"));
  let got = Buffer.alloc(0);
  const welcomed = new Promise<void>((resolve, reject) => {
    const limit = setTimeout(() => reject(new Error(`no welcome: ${got.toString("latin1").slice(0, 400)}`)), 5000);
    let authed = false;
    socket.on("data", (chunk: Buffer) => {
      if (authed && got.length > 65536) return; // past the welcome: the pongs are not read
      got = Buffer.concat([got, chunk]);
      const text = got.toString("latin1");
      const nonce = /"nonce":"([^"]+)"/.exec(text)?.[1];
      if (nonce && !authed) {
        authed = true;
        socket.write(clientFrame(authFrame(m, relay, nonce)));
      }
      if (text.includes('"type":"welcome"')) { clearTimeout(limit); resolve(); }
    });
  });
  await welcomed;
  return socket;
}

test("F3: an admitted machine flooding 8 MiB of frames does not hold SIGTERM: stopping is logged within 1 s of the signal", async () => {
  const e = estate(new Date(), "ES256");
  const root = await dataDir(e);
  const relay = await launch(root, false);
  try {
    const socket = await rawAdmitted(relay.port, e.machine, "https://relay.test");
    const frames: Buffer[] = [];
    let size = 0;
    for (let i = 0; size < 8 * 1024 * 1024; i += 1) {
      // Pings and stored messages to itself: the relay's cheapest frame and one that writes SQLite and delivers.
      const frame = clientFrame(JSON.stringify(i % 2 === 0 ? { v: 1, type: "ping", id: `f${i}` } : { v: 1, type: "send", id: `f${i}`, msgId: `m-${i}`, to: e.machine.kid, body: "AA", ttl: 60 }));
      frames.push(frame);
      size += frame.length;
    }
    socket.write(Buffer.concat(frames)); // 8 MiB of pings in one write
    await new Promise((resolve) => setTimeout(resolve, 200)); // the relay is now working through the backlog
    const signalled = Date.now();
    relay.child.kill("SIGTERM");
    const end = Date.now() + 15_000;
    while (!relay.lines.some((l) => l.event === "stopping") && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 20));
    const stopping = relay.lines.find((l) => l.event === "stopping");
    assert.ok(stopping, JSON.stringify(relay.lines.map((l) => l.event)));
    const lag = Date.parse(stopping.at) - signalled;
    assert.ok(lag < 1000, `stopping was logged ${lag} ms after SIGTERM`);
    assert.equal(await within(relay.exited, 15_000), 0, JSON.stringify(relay.lines.map((l) => l.event)));
    assert.ok(relay.lines.some((l) => l.event === "stopped"));
    socket.destroy();
  } finally {
    relay.kill();
  }
});
