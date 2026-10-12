// Graceful shutdown of the portable relay (RLY-010): SIGTERM closes every session 1001 ("going away") through the
// estate hub, records lastSeen, closes the SQLite stores and exits 0; a socket that ignores the close is terminated
// at the grace period; an upgrade that arrives while the relay stops is refused 503.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { sign } from "node:crypto";
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
