// How the relay classifies a node's frame (src/core/frames.ts, DEC-0066 "Frames"): the per-type validators compiled
// ahead of time answer what the whole relay-frame schema answers, and ids are counted in code points as JSON Schema
// counts them.
import assert from "node:assert/strict";
import { test } from "node:test";
import validators from "../src/contract/relay-frame.validate.js";
import { FRAME_TYPES } from "../src/contract/relay.ts";
import { classifyFrame, codePoints } from "../src/core/frames.ts";
import { frameValid } from "./frame-schema.ts";

const SIG = "urn:fabric:machine:a#sig";
const body = Buffer.from("hello").toString("base64url");
// One valid frame per type a node sends, then variants that break the schema in each way the relay meets.
const valid: Array<Record<string, unknown>> = [
  { v: 1, type: "ping", id: "p1" },
  { v: 1, type: "pong", id: "p2" },
  { v: 1, type: "send", id: "s1", to: SIG, msgId: "m-1", body, ttl: 60 },
  { v: 1, type: "ack", id: "k1", seq: 3 },
  { v: 1, type: "presence-query", id: "q1", kids: [SIG] },
  { v: 1, type: "delta-query", id: "d1", fromSeq: 1 },
];
const broken: Array<Record<string, unknown>> = [
  { v: 1, type: "send", id: "s1" },
  { v: 1, type: "send", id: "s1", to: SIG, msgId: "", body, ttl: 60 },
  { v: 1, type: "send", id: "s1", to: SIG, msgId: "m", body: "not base64url!", ttl: 60 },
  { v: 1, type: "send", id: "s1", to: SIG, msgId: "m", body, ttl: 1.5 },
  { v: 1, type: "ack", id: "k1", seq: -1 },
  { v: 1, type: "presence-query", id: "q1", kids: "everyone" },
  { v: 1, type: "presence-query", id: "q1", kids: Array.from({ length: 257 }, (_, i) => `k${i}#sig`) },
  { v: 1, type: "ping", id: "x".repeat(129) },
  { v: 1, type: "ping", id: "\u{1F600}".repeat(129) },
  { v: 2, type: "ping", id: "p" },
];

test("each type's ahead-of-time validator answers what the whole relay-frame schema answers", () => {
  for (const frame of [...valid, ...broken, { ...valid[0], extra: true }, { v: 1, type: "ping", id: "\u{1F600}".repeat(128) }]) {
    const own = validators[frame.type as string];
    assert.ok(own, `${frame.type} has a validator`);
    assert.equal(own(frame), frameValid(frame), JSON.stringify(frame).slice(0, 100));
    assert.equal(validators.frame(frame), frameValid(frame), `the bundled whole schema: ${JSON.stringify(frame).slice(0, 100)}`);
  }
  for (const frame of valid) assert.equal(validators[frame.type as string]!(frame), true, frame.type as string);
});

test("every frame type the contract names has a validator, and only those", () => {
  assert.deepEqual(Object.keys(validators).filter((k) => k !== "frame").sort(), [...FRAME_TYPES].sort());
});

test("classifyFrame: not a frame, unknown or relay-only type, malformed, or a frame", () => {
  assert.equal(classifyFrame(undefined).kind, "not-frame");
  assert.equal(classifyFrame([]).kind, "not-frame");
  assert.equal(classifyFrame({ v: 1, type: "ping", id: "" }).kind, "not-frame");
  assert.equal(classifyFrame({ v: 1, type: "ping", id: "\u{1F600}".repeat(129) }).kind, "not-frame");
  assert.equal(classifyFrame({ v: 1, type: "ping", id: "\u{1F600}".repeat(128) }).kind, "frame");
  assert.equal(classifyFrame({ v: 1, type: "teleport", id: "t" }).kind, "unknown-type");
  assert.equal(classifyFrame({ v: 1, type: "welcome", id: "w" }).kind, "unknown-type");
  assert.equal(classifyFrame({ v: 1, type: "toString", id: "t" }).kind, "unknown-type");
  assert.equal(classifyFrame({ v: 1, type: "send", id: "s", to: SIG, msgId: "m", body, ttl: 0 }).kind, "malformed");
  assert.equal(classifyFrame({ v: 1, type: "auth", id: "a" }).kind, "frame", "an auth frame is admit's to judge");
  for (const frame of valid) assert.equal(classifyFrame(frame).kind, "frame", frame.type as string);
});

test("codePoints counts as JSON Schema's maxLength does: a surrogate pair is one, a lone surrogate one", () => {
  for (const [text, n] of [["", 0], ["abc", 3], ["\u{1F600}", 1], ["\u{1F600}\u{1F600}", 2], ["\uD800", 1], ["\uDC00\uD800", 2], ["a\uD83Db", 3], ["􏿿", 1]] as const) {
    assert.equal(codePoints(text), n, JSON.stringify(text));
    assert.equal(codePoints(text), [...text].length, JSON.stringify(text));
  }
});
