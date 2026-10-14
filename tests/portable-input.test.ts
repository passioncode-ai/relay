// What the portable relay does with input it cannot use (round 4): a request target Node's HTTP parser accepts but the
// URL parser does not is answered 400 on both the plain and the upgrade path, and the relay stays up; a RELAY_HOST or
// RELAY_PORT it cannot use, and a listen that fails, refuse to start (exit 2, `refused-to-start`), never a crash.
// Each case runs the relay as an operator does, `node src/portable/main.ts`, in a child process.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { connect as tcp, createServer as createTcpServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

const roots: string[] = [];
after(async () => { for (const root of roots) await rm(root, { recursive: true, force: true }); });

async function dataDir(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "relay-input-"));
  roots.push(root);
  return root;
}

const within = <T>(promise: Promise<T>, ms: number) => Promise.race([promise, new Promise<undefined>((resolve) => setTimeout(resolve, ms))]);

/** Starts `main.ts` with `env` over the defaults; lines are its log, one JSON object each. */
async function start(env: Record<string, string>) {
  const root = await dataDir();
  const child = spawn(process.execPath, ["--import", "tsx", "src/portable/main.ts"], {
    env: { ...process.env, RELAY_DATA_DIR: root, RELAY_PORT: "0", RELAY_HOST: "127.0.0.1", RELAY_ORIGIN: "https://relay.test", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const lines: Array<Record<string, any>> = [];
  let buffered = "", stderr = "";
  child.stdout.on("data", (chunk: Buffer) => {
    buffered += chunk.toString("utf8");
    for (let i = buffered.indexOf("\n"); i >= 0; i = buffered.indexOf("\n")) {
      try { lines.push(JSON.parse(buffered.slice(0, i))); } catch { lines.push({ event: "unparsed", text: buffered.slice(0, i) }); }
      buffered = buffered.slice(i + 1);
    }
  });
  child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
  const exited = new Promise<number | null>((resolve) => child.on("exit", (code) => resolve(code)));
  const kill = () => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); };
  return { child, lines, exited, kill, stderr: () => stderr };
}

async function listening(relay: Awaited<ReturnType<typeof start>>): Promise<number> {
  const end = Date.now() + 10_000;
  while (!relay.lines.some((l) => l.event === "listening") && relay.child.exitCode === null && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 50));
  const port = relay.lines.find((l) => l.event === "listening")?.port as number;
  assert.ok(port, `not listening: ${JSON.stringify(relay.lines)} ${relay.stderr()}`);
  return port;
}

/** Sends raw request lines and reads until the server closes (3 s at most): the answer's status line. */
function raw(port: number, lines: string[]): Promise<string> {
  return new Promise((resolve) => {
    const socket = tcp(port, "127.0.0.1", () => socket.write([...lines, "", ""].join("\r\n")));
    let got = "";
    const done = () => { clearTimeout(limit); socket.destroy(); resolve(got.split("\r\n")[0] ?? ""); };
    const limit = setTimeout(done, 3000);
    socket.on("data", (chunk) => { got += chunk.toString("latin1"); if (/\r\n\r\n/.test(got) && !/^HTTP\/1\.1 101/.test(got)) setTimeout(done, 50); });
    socket.on("close", done);
    socket.on("error", done);
  });
}

const TARGETS = ["//[", "http://[/v1/connect", "http://x:99999/v1/connect"];
const plain = (target: string) => [`GET ${target} HTTP/1.1`, "Host: x", "Connection: close"];
const upgrade = (target: string) => [`GET ${target} HTTP/1.1`, "Host: x", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Version: 13",
  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol: fabric-relay.v1"];

test("F1: a request target the URL parser rejects is answered 400 on both paths, the relay stays up, and SIGTERM still stops it", async () => {
  const relay = await start({});
  try {
    const port = await listening(relay);
    for (const target of TARGETS) {
      for (const [path, request] of [["plain", plain], ["upgrade", upgrade]] as const) {
        const status = await raw(port, request(target));
        assert.match(status, /^HTTP\/1\.1 400/, `${path} ${target}: ${status} ${JSON.stringify(relay.lines.map((l) => l.event))} ${relay.stderr()}`);
        assert.equal(relay.child.exitCode, null, `${path} ${target}: the relay exited ${relay.stderr()}`);
        assert.match(await raw(port, ["GET /healthz HTTP/1.1", "Host: x", "Connection: close"]), /^HTTP\/1\.1 200/, `${path} ${target}: healthz`);
      }
    }
    assert.equal(relay.lines.filter((l) => l.event === "request-refused" || l.event === "upgrade-refused").length, TARGETS.length * 2);
    relay.child.kill("SIGTERM");
    assert.equal(await within(relay.exited, 8000), 0, JSON.stringify(relay.lines.map((l) => l.event)));
    assert.ok(relay.lines.some((l) => l.event === "stopped"));
  } finally {
    relay.kill();
  }
});

/** Starts the relay with `env` and expects it to refuse to start: exit 2 and a `refused-to-start` line matching `reason`. */
async function refuses(env: Record<string, string>, reason: RegExp) {
  const relay = await start(env);
  try {
    const code = await within(relay.exited, 10_000);
    assert.equal(code, 2, `${JSON.stringify(env)}: exit ${code} ${JSON.stringify(relay.lines)} ${relay.stderr()}`);
    const refused = relay.lines.find((l) => l.event === "refused-to-start");
    assert.ok(refused, `${JSON.stringify(env)}: ${JSON.stringify(relay.lines)}`);
    assert.match(refused.reason, reason, JSON.stringify(env));
    assert.ok(!relay.lines.some((l) => l.event === "listening"), "it never listened");
  } finally {
    relay.kill();
  }
}

test("F2: a RELAY_HOST with a zone id (fe80::1%lo0, ::1%lo0) refuses to start, even with an https origin", async () => {
  for (const host of ["fe80::1%lo0", "::1%lo0"]) await refuses({ RELAY_HOST: host }, /RELAY_HOST/);
});

test("F5: RELAY_PORT is digits only: empty, 1e3, 0x50, ' 80' and 65536 refuse to start", async () => {
  for (const port of ["", "1e3", "0x50", " 80", "65536"]) await refuses({ RELAY_PORT: port }, /RELAY_PORT/);
});

test("F5: a RELAY_HOST with a leading space refuses to start", async () => {
  await refuses({ RELAY_HOST: " 127.0.0.1" }, /RELAY_HOST/);
});

test("F5: a listen that fails (the port is taken) refuses to start with exit 2, not a crash", async () => {
  const taken = createTcpServer();
  await new Promise<void>((resolve) => taken.listen(0, "127.0.0.1", () => resolve()));
  try {
    await refuses({ RELAY_PORT: String((taken.address() as AddressInfo).port) }, /EADDRINUSE/);
  } finally {
    taken.close();
  }
});

test("F5: a RELAY_HOST that does not resolve refuses to start with exit 2, not a crash", async () => {
  await refuses({ RELAY_HOST: "no-such-host.invalid" }, /ENOTFOUND/);
});
