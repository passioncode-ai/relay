// The relay session (RLY-02) over the contract's vectors: the vector machine's auth frame was signed for the vector's
// relay origin and nonce, so a session handed that nonce must admit it — and refuse it for every reason DEC-0047 names.
// Every frame the relay sends is validated against the contract's relay-frame schema.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { test } from "node:test";
import validateEstateRecord from "../src/contract/estate-record.validate.js";
import type { AdmissionResult } from "../src/contract/relay.ts";
import { AdmissionHolder } from "../src/core/admission.ts";
import { EMPTY_DELTA_HEAD, RelaySession } from "../src/core/session.ts";

const root = path.resolve(import.meta.dirname, "..");
const json = (file: string) => JSON.parse(readFileSync(path.join(root, file), "utf8"));
const relay = json("tests/vectors/relay.json");
const estate = json("tests/vectors/estate-record.json");
const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020").default;
const ajv = new Ajv2020({ allErrors: true, strict: false });
require("ajv-formats").default(ajv);
const frameValid = ajv.compile(json("src/contract/schemas/relay-frame.schema.json"));

const T0 = Date.parse(relay.auth.context.now);
const admitted = (set: Map<string, unknown> = new Map([[relay.auth.frame.kid, relay.machineKey]])): AdmissionResult =>
  ({ ok: true, held: {}, revision: 3, set: set as Map<string, Uint8Array> });

function harness(admission: () => AdmissionResult = () => admitted(), nonce = relay.auth.context.nonce) {
  let now = T0;
  const sent: Array<Record<string, any>> = [];
  const closed: Array<{ code: number; reason: string }> = [];
  const log: Array<Record<string, unknown>> = [];
  const session = new RelaySession(
    { send: (text) => sent.push(JSON.parse(text)), close: (code, reason) => closed.push({ code, reason }) },
    { relay: relay.auth.context.relay, now: () => new Date(now), nonce: () => nonce, sessionId: () => "s-1", admission, log: (e) => log.push(e) },
  );
  session.open();
  return { session, sent, closed, log, advance: (ms: number) => { now += ms; } };
}
const auth = (over: Record<string, unknown> = {}) => JSON.stringify({ ...relay.auth.frame, ...over });

test("hello names the protocol, this relay and a nonce; every frame sent is schema-valid", async () => {
  const h = harness();
  assert.equal(h.sent[0]?.type, "hello");
  assert.deepEqual([h.sent[0]?.protocol, h.sent[0]?.relay, h.sent[0]?.nonce], ["fabric-relay/0.1", relay.auth.context.relay, relay.auth.context.nonce]);
  await h.session.receive(auth());
  await h.session.receive(JSON.stringify({ v: 1, type: "ping", id: "p1" }));
  await h.session.receive(JSON.stringify({ v: 1, type: "send", id: "s1", to: "x#sig", msgId: "m", body: "AA", ttl: 60 }));
  await h.session.receive(JSON.stringify({ v: 1, type: "teleport", id: "t1" }));
  for (const frame of h.sent) assert.ok(frameValid(frame), `${frame.type}: ${JSON.stringify(frameValid.errors)}`);
});

test("admits the vector machine and welcomes it with the verified revision and the empty delta head", async () => {
  const h = harness();
  await h.session.receive(auth());
  assert.equal(h.session.state, "admitted");
  assert.equal(h.session.kid, relay.auth.frame.kid);
  assert.deepEqual(h.sent[1], { v: 1, id: "r2", type: "welcome", session: "s-1", estateRevision: 3, deltaHead: EMPTY_DELTA_HEAD, heartbeat: null });
  assert.equal(h.closed.length, 0);
});

test("admits the same machine when the set holds its key as DEC-0053's SEC 1 octets", async () => {
  const h = harness(() => admitted(new Map([[relay.auth.frame.kid, Buffer.from(relay.machineKeyOctets, "base64")]])));
  await h.session.receive(auth());
  assert.equal(h.session.state, "admitted");
});

const refusals: Array<[string, () => ReturnType<typeof harness>, string, string, number]> = [
  ["a machine outside the admission set", () => harness(() => admitted(new Map())), auth(), "not-admitted", 4403],
  ["its own key filed under another machine's kid", () => harness(() => admitted(new Map([["urn:fabric:machine:other#sig", relay.machineKey]]))), auth(), "not-admitted", 4403],
  ["any machine while the relay holds no verified record", () => harness(() => ({ ok: false, refusal: "no-record" })), auth(), "not-admitted", 4403],
  ["any machine once the held record's window ended", () => harness(() => ({ ok: false, refusal: "expired" })), auth(), "not-admitted", 4403],
  ["a proof signed for another connection's nonce", () => harness(undefined, "BBECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"), auth(), "unauthenticated", 4401],
  ["another algorithm", () => harness(), auth({ alg: "EdDSA" }), "unsupported-alg", 4401],
  ["an Ed25519 participant", () => harness(() => admitted(new Map([[relay.auth.frame.kid, relay.ed25519.key]]))), auth(), "unsupported-alg", 4401],
  ["another protocol", () => harness(), auth({ protocol: "fabric-relay/9" }), "protocol-unsupported", 4401],
  ["a frame other than auth first", () => harness(), JSON.stringify({ v: 1, type: "ping", id: "p" }), "unauthenticated", 4401],
  ["text that is not a frame", () => harness(), "not json", "unauthenticated", 4401],
];
for (const [name, make, frame, code, close] of refusals) {
  test(`refuses ${name}: error ${code}, close ${close}`, async () => {
    const h = make();
    await h.session.receive(frame);
    assert.equal(h.sent.at(-1)?.type, "error");
    assert.equal(h.sent.at(-1)?.code, code);
    assert.ok(frameValid(h.sent.at(-1)), JSON.stringify(frameValid.errors));
    assert.deepEqual(h.closed.map((c) => c.code), [close]);
    assert.equal(h.session.state, "closed");
  });
}

test("a second auth on one connection is a replay: the nonce admits once", async () => {
  const h = harness();
  await h.session.receive(auth());
  await h.session.receive(auth());
  assert.equal(h.sent.at(-1)?.code, "replay");
  assert.deepEqual(h.closed.map((c) => c.code), [4401]);
});

test("after welcome: ping gets pong, a known frame not served yet a named refusal, an unknown type an error; the session stays open", async () => {
  const h = harness();
  await h.session.receive(auth());
  await h.session.receive(JSON.stringify({ v: 1, type: "ping", id: "p1" }));
  assert.deepEqual(h.sent.at(-1), { v: 1, id: "p1", type: "pong" });
  await h.session.receive(JSON.stringify({ v: 1, type: "send", id: "s1" }));
  assert.deepEqual([h.sent.at(-1)?.code, h.sent.at(-1)?.replyTo], ["internal", "s1"]);
  await h.session.receive(JSON.stringify({ v: 1, type: "teleport", id: "t1" }));
  assert.equal(h.sent.at(-1)?.code, "unknown-type");
  await h.session.receive("{");
  assert.equal(h.sent.at(-1)?.code, "unknown-type");
  assert.equal(h.closed.length, 0);
});

test("closes a binary frame with 1003 and a frame over 1 MiB with 1009", async () => {
  const binary = harness();
  await binary.session.receive(new Uint8Array([1, 2, 3]));
  assert.deepEqual(binary.closed.map((c) => c.code), [1003]);
  const large = harness();
  await large.session.receive(JSON.stringify({ v: 1, type: "ping", id: "x".repeat(1_048_577) }));
  assert.deepEqual([large.sent.at(-1)?.code, large.closed.map((c) => c.code)], ["too-large", [1009]]);
});

test("refuses a machine silent past the 10 s auth deadline, and closes an admitted one after 90 s of silence", async () => {
  const slow = harness();
  slow.advance(10_000);
  slow.session.tick();
  assert.equal(slow.closed.length, 0);
  slow.advance(1);
  slow.session.tick();
  assert.deepEqual([slow.sent.at(-1)?.code, slow.closed.map((c) => c.code)], ["unauthenticated", [4401]]);
  const idle = harness();
  await idle.session.receive(auth());
  idle.advance(90_000);
  idle.session.tick();
  assert.equal(idle.closed.length, 0);
  idle.advance(1);
  idle.session.tick();
  assert.deepEqual(idle.closed.map((c) => c.code), [1001]);
  await idle.session.receive(auth()); // a closed session ignores everything
  assert.equal(idle.closed.length, 1);
});

test("AdmissionHolder: holds what the contract accepted, refuses the rest unchanged, fails closed at the window's end", async () => {
  let at = new Date(estate.cases[0].trust.at);
  const holder = new AdmissionHolder({ pinned: [estate.keys.passkeyEs256.authority], schemaValid: (r) => validateEstateRecord(r) as boolean, now: () => at });
  assert.deepEqual(holder.current(), { ok: false, refusal: "no-record" });
  assert.equal(holder.offer({ ...estate.cases[0].record, schema: "x" }).ok, false);
  assert.equal(holder.revision, undefined);
  assert.equal(holder.offer(estate.cases[0].record).ok, true);
  assert.equal(holder.offer(estate.cases[0].record).ok, false); // revision 1 again: not a successor
  assert.equal(holder.revision, estate.cases[0].record);
  at = new Date(estate.cases[1].trust.at);
  const second = holder.offer(estate.cases[1].record);
  assert.ok(second.ok);
  assert.deepEqual([...second.set.keys()], ["m-4c1e#sig"]);
  at = new Date(Date.parse(estate.cases[1].record.validUntil) + 1000);
  assert.deepEqual(holder.current(), { ok: false, refusal: "expired" });
});
