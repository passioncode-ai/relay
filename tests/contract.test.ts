// The contract this relay runs (DEC-0047, DEC-0055), vendored byte for byte at the commit fabric-contract.lock.json pins,
// and the contract's own vectors run against it here. The relay never re-implements a check the contract owns.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import validateEstateRecord from "../src/contract/estate-record.validate.js";
import { admit, relayAdmissionSet, verifyMessageBody, type AuthFrame } from "../src/contract/relay.ts";
import { openEnvelope, type SecretEnvelope } from "../src/contract/secret-envelope.ts";

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
const auth = relay.auth as { context: { relay: string; nonce: string; now: string }; frame: AuthFrame };
const authCtx = (admittedKey: (kid: string) => unknown) => ({
  relay: auth.context.relay, nonce: auth.context.nonce, nonceUsed: false, now: new Date(auth.context.now),
  admittedKey: admittedKey as never
});

test("relay.json: the vector machine is admitted, by JWK and by SEC 1 octets; an Ed25519 participant is refused", () => {
  assert.deepEqual(admit(auth.frame, authCtx(() => relay.machineKey)), { ok: true, kid: auth.frame.kid });
  assert.deepEqual(admit(auth.frame, authCtx(() => Buffer.from(relay.machineKeyOctets, "base64"))), { ok: true, kid: auth.frame.kid });
  assert.deepEqual(admit(relay.ed25519.frame, authCtx(() => relay.ed25519.key)), { ok: false, code: relay.ed25519.expect });
});

test("relay.json: the message body verifies against its frame", () => {
  const { from, to, msgId } = relay.message.frame;
  const result = verifyMessageBody(relay.message.body, { from, to, msgId }, () => relay.machineKey, new Date(relay.message.now));
  assert.equal(result.ok, true);
});

test("secret-envelope.json: the vector envelope opens with what its recipient holds", () => {
  const v = json("tests/vectors/secret-envelope.json");
  const envelope = v.envelope as SecretEnvelope;
  const result = openEnvelope(envelope, {
    ownKemKid: v.open.ownKemKid, ownKemPrivateKey: Buffer.from(v.recipientKemPrivateKey, "hex"),
    senderKey: (kid) => (kid === envelope.header.sender ? v.senderKey : undefined),
    mayHold: (kid, agentRef, slot) => kid === envelope.header.sender && agentRef === envelope.header.agentRef && slot === envelope.header.slot,
    currentPlacement: () => v.open.placement, now: new Date(v.open.now)
  });
  assert.deepEqual(result, { ok: true, secret: Buffer.from(v.open.secret) });
});

test("estate-record.json: the bundled schema validator and relayAdmissionSet agree with the contract", () => {
  const estate = json("tests/vectors/estate-record.json");
  const [first, second] = [estate.cases[0], estate.cases[1]];
  const schemaValid = (record: unknown) => validateEstateRecord(record) as boolean;
  assert.equal(schemaValid(first.record), true);
  assert.equal(schemaValid({ ...first.record, schema: "estate-record/9" }), false);
  const pinned = [estate.keys.passkeyEs256.authority];
  const one = relayAdmissionSet({ candidate: first.record, pinned, at: new Date(first.trust.at), schemaValid });
  assert.ok(one.ok);
  assert.deepEqual([...one.set.keys()].sort(), ["m-4c1e#sig", "m-9a07#sig"]);
  const two = relayAdmissionSet({ held: one.held, candidate: second.record, pinned, at: new Date(second.trust.at), schemaValid });
  assert.ok(two.ok);
  assert.deepEqual([...two.set.keys()], ["m-4c1e#sig"]);
});
