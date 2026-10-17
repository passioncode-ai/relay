// The estate fixture builds real chains (RLY-025): revise() makes revision n+1 with its parent's digest, a later
// window or fewer machines, signed by a passkey the parent lists; forge() makes one signed by a stranger passkey. The
// contract's own verifier decides: a revised successor is accepted, a forged one refused. Module A's walk tests
// (tests/admission.test.ts) build on these.
import assert from "node:assert/strict";
import { test } from "node:test";
import validateEstateRecord from "../src/contract/estate-record.validate.js";
import { AdmissionHolder } from "../src/core/admission.ts";
import { estate, forge, revise } from "./estate-fixture.ts";

const holder = (e: ReturnType<typeof estate>, at = new Date()) =>
  new AdmissionHolder({ pinned: e.pinned, schemaValid: (record) => validateEstateRecord(record) as boolean, now: () => at });

test("revise() builds revision n+1 over its parent's digest that the contract accepts, signed by either listed passkey", () => {
  const first = estate(new Date(), "ES256");
  for (const signer of ["EdDSA", "ES256"] as const) {
    const h = holder(first);
    assert.ok(h.offer(first.record).ok);
    const second = revise(first, { signer });
    assert.deepEqual([second.record.revision, second.record.parent], [2, first.record.digest]);
    const result = h.offer(second.record);
    assert.ok(result.ok, JSON.stringify(result));
    assert.deepEqual([...result.set.keys()].sort(), [first.machine.kid, first.second.kid].sort());
    const third = revise(second, { signer });
    assert.ok(h.offer(third.record).ok, "a chain goes on");
  }
});

test("revise({dropKids}) leaves a machine out of the next set; revise({validUntil}) moves the window", () => {
  const first = estate(new Date(), "ES256");
  const h = holder(first);
  assert.ok(h.offer(first.record).ok);
  const until = new Date(Date.now() + 2 * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const second = revise(first, { dropKids: [first.machine.kid], validUntil: until });
  const result = h.offer(second.record);
  assert.ok(result.ok, JSON.stringify(result));
  assert.deepEqual([...result.set.keys()], [first.second.kid]);
  assert.equal(second.record.validUntil, until);
});

test("forge() signs with a stranger passkey: the contract refuses it, and the holder keeps its parent", () => {
  const first = estate(new Date(), "ES256");
  const h = holder(first);
  assert.ok(h.offer(first.record).ok);
  const forged = forge(first);
  assert.deepEqual([forged.record.revision, forged.record.parent], [2, first.record.digest]);
  const result = h.offer(forged.record);
  assert.deepEqual(result, { ok: false, refusal: "unverified", problem: "unknown-authority" }, "refused for its signer, nothing else");
  assert.equal(h.revision, first.record);
  // A real revision 2 still goes in after the forged one was refused.
  assert.ok(h.offer(revise(first).record).ok);
});
