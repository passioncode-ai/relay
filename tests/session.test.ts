// The relay session (RLY-02) over the contract's vectors: the vector machine's auth frame was signed for the vector's
// relay origin and nonce, so a session handed that nonce must admit it — and refuse it for every reason DEC-0047 names.
// Every frame the relay sends is validated against the contract's relay-frame schema.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { frameValid } from "./frame-schema.ts";
import validateEstateRecord from "../src/contract/estate-record.validate.js";
import type { AdmissionResult } from "../src/contract/relay.ts";
import { AdmissionHolder } from "../src/core/admission.ts";
import { P256_CURVE } from "../src/contract/p256.ts";
import { deltaGenesis } from "../src/contract/revocation-delta.ts";
import { RelaySession } from "../src/core/session.ts";

const root = path.resolve(import.meta.dirname, "..");
const json = (file: string) => JSON.parse(readFileSync(path.join(root, file), "utf8"));
const relay = json("tests/vectors/relay.json");
const estate = json("tests/vectors/estate-record.json");

const T0 = Date.parse(relay.auth.context.now);
const ESTATE = relay.auth.frame.estate as string;
const admitted = (set: Map<string, unknown> = new Map([[relay.auth.frame.kid, relay.machineKey]]), estate = ESTATE): AdmissionResult =>
  ({ ok: true, held: { estate }, revision: 3, set: set as Map<string, Uint8Array>, excluded: [] });
/** The vector signature in its high-S twin (r, n − s): plain ECDSA verifies it, a relay-family verifier refuses it. */
const highS = (() => {
  const raw = Buffer.from(relay.auth.frame.sig, "base64url");
  const s = BigInt(`0x${raw.subarray(32).toString("hex")}`);
  return Buffer.concat([raw.subarray(0, 32), Buffer.from((P256_CURVE.n - s).toString(16).padStart(64, "0"), "hex")]).toString("base64url");
})();

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

test("admits the vector machine and welcomes it with the verified revision and the delta head at its estate's genesis", async () => {
  const h = harness();
  await h.session.receive(auth());
  assert.equal(h.session.state, "admitted");
  assert.equal(h.session.kid, relay.auth.frame.kid);
  assert.deepEqual(h.sent[1], { v: 1, id: "r2", type: "welcome", session: "s-1", estateRevision: 3, deltaHead: { sequence: 0, sha256: deltaGenesis(ESTATE) }, heartbeat: null });
  assert.notEqual(deltaGenesis(ESTATE), deltaGenesis("urn:fabric:estate:other"), "the genesis head names its estate");
  assert.equal(h.closed.length, 0);
});

test("admits the same machine when the set holds its key as DEC-0053's SEC 1 octets", async () => {
  const h = harness(() => admitted(new Map([[relay.auth.frame.kid, Buffer.from(relay.machineKeyOctets, "base64")]])));
  await h.session.receive(auth());
  assert.equal(h.session.state, "admitted");
});

// DEC-0066: past the frame's own bytes and the nonce, every failure is one answer, `unauthenticated`, closed 4401; 4403
// is only ever sent to a session whose signer was proven.
const refusals: Array<[string, () => ReturnType<typeof harness>, string, string, number]> = [
  ["a machine outside the admission set", () => harness(() => admitted(new Map())), auth(), "unauthenticated", 4401],
  ["its own key filed under another machine's kid", () => harness(() => admitted(new Map([["urn:fabric:machine:other#sig", relay.machineKey]]))), auth(), "unauthenticated", 4401],
  ["any machine while the relay holds no verified record", () => harness(() => ({ ok: false, refusal: "no-record" })), auth(), "unauthenticated", 4401],
  ["any machine once the held record's window ended", () => harness(() => ({ ok: false, refusal: "expired" })), auth(), "unauthenticated", 4401],
  ["a proof for another estate than the held record's", () => harness(() => admitted(undefined, "urn:fabric:estate:other")), auth(), "unauthenticated", 4401],
  ["a high-S signature", () => harness(), auth({ sig: highS }), "unauthenticated", 4401],
  ["a proof signed for another connection's nonce", () => harness(undefined, "BBECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"), auth(), "unauthenticated", 4401],
  ["another algorithm", () => harness(), auth({ alg: "EdDSA" }), "unsupported-alg", 4401],
  ["an Ed25519 key in the set", () => harness(() => admitted(new Map([[relay.auth.frame.kid, relay.ed25519.key]]))), auth(), "unauthenticated", 4401],
  ["another protocol", () => harness(), auth({ protocol: "fabric-relay/9" }), "protocol-unsupported", 4401],
  ["an auth frame that fails the schema", () => harness(), auth({ sig: 7 }), "unauthenticated", 4401],
  ["an auth frame whose members are not strings", () => harness(), auth({ kid: {}, estate: [], sig: null }), "unauthenticated", 4401],
  ["an auth frame with no alg (admit's answer, not the schema's)", () => harness(), auth({ alg: undefined }), "unsupported-alg", 4401],
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

test("an auth refusal's message is fixed per code; why goes to the relay's log only", async () => {
  const none = harness(() => ({ ok: false, refusal: "no-record" }));
  const other = harness(() => admitted(new Map()));
  await none.session.receive(auth());
  await other.session.receive(auth());
  assert.equal(none.sent.at(-1)?.message, other.sent.at(-1)?.message);
  assert.deepEqual(none.log.filter((e) => e.event === "auth-refused").map((e) => [e.code, e.admission]), [["unauthenticated", "no-record"]]);
  assert.deepEqual(other.log.filter((e) => e.event === "auth-refused").map((e) => [e.code, e.admission]), [["unauthenticated", "held"]]);
});

test("a second auth on one connection is a replay: the nonce admits once", async () => {
  const h = harness();
  await h.session.receive(auth());
  await h.session.receive(auth());
  assert.equal(h.sent.at(-1)?.code, "replay");
  assert.deepEqual(h.closed.map((c) => c.code), [4401]);
});

test("after welcome: every answer names the frame it answers in replyTo; unknown and relay-only types are unknown-type, a known type that fails the schema or FAC-SEM-071 malformed; the session stays open", async () => {
  const h = harness();
  await h.session.receive(auth());
  await h.session.receive(JSON.stringify({ v: 1, type: "ping", id: "p1" }));
  assert.deepEqual(h.sent.at(-1), { v: 1, id: "r3", type: "pong", replyTo: "p1" });
  await h.session.receive(JSON.stringify({ v: 1, type: "send", id: "s1" }));
  assert.deepEqual([h.sent.at(-1)?.code, h.sent.at(-1)?.replyTo], ["malformed", "s1"]);
  await h.session.receive(JSON.stringify({ v: 1, type: "send", id: "s2", to: "x#sig", msgId: "m", body: "AA", ttl: 0 }));
  assert.deepEqual([h.sent.at(-1)?.code, h.sent.at(-1)?.replyTo], ["malformed", "s2"]);
  await h.session.receive(JSON.stringify({ v: 1, type: "teleport", id: "t1" }));
  assert.deepEqual([h.sent.at(-1)?.code, h.sent.at(-1)?.replyTo], ["unknown-type", "t1"]);
  for (const type of ["hello", "welcome", "accepted", "deliver", "presence", "presence-result", "error"]) {
    await h.session.receive(JSON.stringify({ v: 1, type, id: `x-${type}` }));
    assert.deepEqual([h.sent.at(-1)?.code, h.sent.at(-1)?.replyTo], ["unknown-type", `x-${type}`], type);
  }
  await h.session.receive("{");
  assert.deepEqual([h.sent.at(-1)?.code, h.sent.at(-1)?.replyTo], ["malformed", undefined]);
  await h.session.receive(JSON.stringify({ v: 1, type: "ping", id: "" }));
  assert.deepEqual([h.sent.at(-1)?.code, h.sent.at(-1)?.replyTo], ["malformed", undefined], "an unusable id is never echoed");
  await h.session.receive(JSON.stringify({ v: 1, type: "delta-query", id: "d1", fromSeq: 1 }));
  assert.deepEqual([h.sent.at(-1)?.code, h.sent.at(-1)?.replyTo], ["internal", "d1"], "known, not served yet (H-2)");
  await h.session.receive(JSON.stringify({ v: 1, type: "delta-query", id: "d2", after: 0 }));
  assert.deepEqual([h.sent.at(-1)?.code, h.sent.at(-1)?.replyTo], ["malformed", "d2"], "a known type failing its schema");
  await h.session.receive(JSON.stringify({ v: 1, type: "ping", id: "p2", extra: { ignored: true } }));
  assert.deepEqual([h.sent.at(-1)?.type, h.sent.at(-1)?.replyTo], ["pong", "p2"], "unknown members are ignored");
  for (const frame of h.sent) assert.ok(frameValid(frame), `${frame.type}: ${JSON.stringify(frameValid.errors)}`);
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

test("restore(snapshot()) mid-session keeps the outbound ids and the delivered seq, and the session goes on", async () => {
  const { MemoryMailbox } = await import("../src/core/mailbox.ts");
  const mailbox = new MemoryMailbox();
  await mailbox.append(relay.auth.frame.kid, "urn:fabric:machine:other#sig", "m-1", "AA", 600, new Date(T0));
  const sent: Array<Record<string, any>> = [];
  const records: unknown[] = [];
  const env = { relay: relay.auth.context.relay, now: () => new Date(T0), nonce: () => relay.auth.context.nonce, sessionId: () => "s-1", admission: () => admitted(), mailbox };
  const first = new RelaySession({ send: (text) => sent.push(JSON.parse(text)), close: () => assert.fail("closed"), persist: (r) => records.push(r) }, env);
  first.open();
  await first.receive(auth());
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent.map((f) => [f.type, f.id]), [["hello", "r1"], ["welcome", "r2"], ["deliver", "r3"]]);
  const record = first.snapshot();
  assert.deepEqual(records.at(-1), record, "the session persists its record after every change");
  assert.ok(JSON.stringify(record).length < 1024, "a record fits a WebSocket attachment many times over");
  const closed: number[] = [];
  const again = RelaySession.restore({ send: (text) => sent.push(JSON.parse(text)), close: (code) => closed.push(code) }, env, JSON.parse(JSON.stringify(record)));
  assert.deepEqual([again.state, again.kid], ["admitted", relay.auth.frame.kid]);
  await again.wake();
  assert.equal(sent.filter((f) => f.type === "deliver").length, 1, "what was delivered is not delivered again");
  await again.receive(JSON.stringify({ v: 1, type: "teleport", id: "t1" }));
  assert.deepEqual([sent.at(-1)!.code, sent.at(-1)!.id], ["unknown-type", "r4"]);
  await again.receive(JSON.stringify({ v: 1, type: "ping", id: "p1" }));
  assert.deepEqual(sent.at(-1), { v: 1, id: "r5", type: "pong", replyTo: "p1" });
  await again.receive(auth());
  assert.deepEqual([sent.at(-1)!.code, closed], ["replay", [4401]], "the restored nonce is still used");
});

test("nextDeadline is the first instant past the 10 s auth deadline, then past 90 s of silence; none once closed", async () => {
  const h = harness();
  assert.equal(h.session.nextDeadline(), T0 + 10_001);
  h.advance(4000);
  await h.session.receive(auth());
  assert.equal(h.session.nextDeadline(), T0 + 4000 + 90_001);
  h.advance(90_001);
  h.session.tick();
  assert.deepEqual([h.closed.map((c) => c.code), h.session.nextDeadline()], [[1001], undefined]);
});

test("fault: a relay fault is answered error internal, logged, and closes 1011", async () => {
  const h = harness();
  h.session.fault(new TypeError("boom"));
  assert.deepEqual([h.sent.at(-1)?.type, h.sent.at(-1)?.code], ["error", "internal"]);
  assert.ok(frameValid(h.sent.at(-1)), JSON.stringify(frameValid.errors));
  assert.deepEqual(h.closed.map((c) => c.code), [1011]);
  assert.deepEqual(h.log.filter((e) => e.event === "session-fault").map((e) => [e.error, e.message]), [["TypeError", "boom"]]);
  h.session.fault(new Error("again"));
  assert.equal(h.closed.length, 1, "a closed session is not closed twice");
});
