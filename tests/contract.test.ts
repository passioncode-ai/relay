// The contract this relay runs (DEC-0047, DEC-0055), vendored byte for byte at the commit fabric-contract.lock.json pins,
// and the contract's own vectors run against it here. The relay never re-implements a check the contract owns.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import validateEstateRecord from "../src/contract/estate-record.validate.js";
import type { AdmissionResult } from "../src/contract/relay.ts";
import { envelopeVectorResults, placementVectorResults, relayVectorResults, vectorKey, type VectorResult } from "../src/contract/relay-vectors.ts";
import { RelaySession, type SessionRecord } from "../src/core/session.ts";

const root = path.resolve(import.meta.dirname, "..");
const json = (file: string) => JSON.parse(readFileSync(path.join(root, file), "utf8"));
const lock = json("fabric-contract.lock.json") as { commit: string; repository: string };
const vendored = json("src/contract/VENDORED.json") as { commit: string; files: Record<string, string> };

test("every vendored file is the contract's own, at the pinned commit", () => {
  assert.match(lock.commit, /^[0-9a-f]{40}$/);
  assert.equal(lock.repository, "https://github.com/passioncode-ai/fabric-agent-contract");
  assert.equal(vendored.commit, lock.commit);
  assert.ok(Object.keys(vendored.files).length >= 30);
  for (const [file, sha256] of Object.entries(vendored.files)) {
    assert.equal(createHash("sha256").update(readFileSync(path.join(root, file))).digest("hex"), sha256, `${file} drifted from the contract`);
  }
});

const relay = json("tests/vectors/relay.json");
const envelopes = json("tests/vectors/secret-envelope.json");

/** One test per case group: every case's actual against its expected, with the case named on a mismatch. */
function runGroups(results: VectorResult[]): void {
  const groups = new Map<string, VectorResult[]>();
  for (const r of results) groups.set(r.group, [...(groups.get(r.group) ?? []), r]);
  for (const [group, rs] of groups) {
    test(`shared vectors: ${group} (${rs.length} cases) through the vendored runner`, () => {
      for (const r of rs) assert.deepEqual(r.actual, r.expected, `${group}: ${r.name}`);
    });
  }
}

// DEC-0066 "Shared vectors": a port runs every case the contract runs, through the contract's own runner.
const relayResults = relayVectorResults(relay);
const envelopeResults = [...envelopeVectorResults(envelopes), ...placementVectorResults(envelopes)];
test("shared vectors: every case group the contract ships is present and non-empty", () => {
  const groups = new Set([...relayResults, ...envelopeResults].map((r) => r.group));
  for (const group of ["instant", "relayOrigin", "admissionSet", "admit", "messageBody", "replay", "blobRequest", "envelope", "placement"]) {
    assert.ok(groups.has(group), `no ${group} cases`);
  }
});
runGroups(relayResults);
runGroups(envelopeResults);

// The admit group again, through the relay's own session path (RP exit): a session greeted with the case's nonce, at
// the case's clock, admitting from a held record of the case's estate and admitted keys, answers what `admit` answers —
// a welcome naming the kid, or an error with the refusal's code, closed 4401.
type Case = { name: string; frame: Record<string, unknown>; context: { relay: string; nonce: string; nonceUsed: boolean; estate?: string | null; admitted?: Record<string, string | Record<string, unknown>>; now: string }; expect: { ok: boolean; kid?: string; code?: string } };
for (const c of (relay.admit.cases as Case[])) {
  test(`shared vectors: admit "${c.name}" through RelaySession`, async () => {
    const ctx = c.context;
    const set = new Map(Object.entries(ctx.admitted ?? {}).map(([kid, key]) => [kid, vectorKey(key)]));
    const admission = (): AdmissionResult => (typeof ctx.estate === "string"
      ? { ok: true, held: { estate: ctx.estate }, revision: 1, set: set as unknown as Map<string, Uint8Array>, excluded: [] }
      : { ok: false, refusal: "no-record" });
    const sent: Array<Record<string, any>> = [];
    const closed: number[] = [];
    const io = { send: (t: string) => sent.push(JSON.parse(t)), close: (code: number) => closed.push(code) };
    const env = { relay: ctx.relay, now: () => new Date(ctx.now), nonce: () => ctx.nonce, sessionId: () => "s-1", admission };
    const at = Date.parse(ctx.now);
    const record: SessionRecord = { v: 1, phase: "awaiting-auth", relay: ctx.relay, nonce: ctx.nonce, nonceUsed: ctx.nonceUsed, openedAt: at, lastFrameAt: at, outbound: 0, delivered: 0, connection: "s-1", lastTouch: 0 };
    const session = RelaySession.restore(io, env, record);
    await session.receive(JSON.stringify(c.frame));
    const last = sent.at(-1)!;
    if (c.expect.ok) {
      assert.deepEqual([last.type, session.kid, closed], ["welcome", c.expect.kid, []], JSON.stringify(last));
    } else {
      assert.deepEqual([last.type, last.code, closed], ["error", c.expect.code, [4401]], JSON.stringify(last));
    }
  });
}

