// #region relay-vectors — docs: docs/specification/relay.md#shared-vectors
/**
 * The runner of the relay family's shared vectors (`fixtures/vectors/relay.json`, `fixtures/vectors/secret-envelope.json`).
 * Every case is data: one complete context, the input, and exactly what the reference returns. This module turns the
 * data into the functional contexts the reference takes and returns `{group, name, actual, expected}` for every case,
 * with no test framework, so a port vendors it and runs the same cases the contract runs (DEC-0066).
 *
 * A key in a case is a JWK object or a string of base64 SEC 1 octets; a time is RFC 3339.
 */
import {
  admit, checkReplay, decideBlobAccess, instant, isRelayOrigin, relayAdmissionSet, sessionStands, verifyBlobRequest, verifyMessageBody,
  type AuthFrame, type RelayMessagePayload
} from "./relay.js";
import type { JsonObject } from "./findings.js";
import { estateEnvelopeContext, openEnvelope, type OpenContext } from "./secret-envelope.js";
import type { P256Key } from "./p256.js";

export interface VectorResult { group: string; name: string; actual: unknown; expected: unknown }

type Json = Record<string, unknown>;
type KeyData = string | Json;
const cases = (group: unknown): Json[] => ((group as { cases?: Json[] } | undefined)?.cases ?? []);

/** A case's key: base64 SEC 1 octets as bytes, a JWK object as it is. */
export function vectorKey(key: KeyData): P256Key {
  return typeof key === "string" ? new Uint8Array(Buffer.from(key, "base64")) : (key as P256Key);
}
/** A case's keys by kid, as a Map: a kid such as `__proto__` or `constructor` is a key like any other. */
const keyring = (keys: unknown) => {
  const map = new Map(Object.entries((keys ?? {}) as Record<string, KeyData>).map(([kid, key]) => [kid, vectorKey(key)] as const));
  return (kid: string): P256Key | undefined => map.get(kid);
};
/** A refusal or a result as plain JSON, so a result with bytes compares by value. */
const plain = (value: unknown): unknown => JSON.parse(JSON.stringify(value));

/** Every case of `relay.json`'s case groups, run through the reference. */
export function relayVectorResults(vectors: Json): VectorResult[] {
  const out: VectorResult[] = [];
  for (const c of cases(vectors.instant)) out.push({ group: "instant", name: c.name as string, actual: instantResult(c.value), expected: c.expect });
  for (const c of cases(vectors.relayOrigin)) out.push({ group: "relayOrigin", name: c.name as string, actual: isRelayOrigin(c.value), expected: c.expect });
  for (const c of cases(vectors.admissionSet)) {
    // A held record only: no candidate is offered, so the schema check is never called.
    const result = relayAdmissionSet({
      ...(c.held ? { held: c.held as JsonObject } : {}), pinned: [], at: new Date(c.at as string), schemaValid: () => false,
      extraRevocations: (c.extraRevocations ?? []) as JsonObject[]
    });
    const actual = result.ok ? { ok: true, revision: result.revision, kids: [...result.set.keys()].sort(), excluded: result.excluded, ...(result.unread.length > 0 ? { unread: result.unread } : {}) } : result;
    out.push({ group: "admissionSet", name: c.name as string, actual, expected: c.expect });
  }
  for (const c of cases(vectors.session)) {
    // A session proven under a key, against the set the relay holds now (DEC-0084).
    const set = relayAdmissionSet({
      ...(c.held ? { held: c.held as JsonObject } : {}), pinned: [], at: new Date(c.at as string), schemaValid: () => false,
      extraRevocations: (c.extraRevocations ?? []) as JsonObject[]
    });
    const session = c.session as { kid: string; key: string };
    out.push({ group: "session", name: c.name as string, actual: sessionStands({ kid: session.kid, key: new Uint8Array(Buffer.from(session.key, "base64")) }, set), expected: c.expect });
  }
  for (const c of cases(vectors.admit)) {
    const ctx = c.context as Json;
    const actual = admit(c.frame as AuthFrame, {
      relay: ctx.relay as string, nonce: ctx.nonce as string, nonceUsed: ctx.nonceUsed as boolean, estate: (ctx.estate ?? undefined) as string | undefined,
      admittedKey: keyring(ctx.admitted), now: new Date(ctx.now as string)
    });
    out.push({ group: "admit", name: c.name as string, actual, expected: c.expect });
  }
  for (const c of cases(vectors.messageBody)) {
    // A recipient checks the body against the deliver frame's from and msgId, and against its own kid as `to`.
    const frame = c.frame as { from: string; msgId: string };
    const actual = verifyMessageBody(c.body as string, { from: frame.from, msgId: frame.msgId, to: c.self as string }, keyring(c.senders), new Date(c.now as string));
    out.push({ group: "messageBody", name: c.name as string, actual: plain(actual), expected: c.expect });
  }
  for (const c of cases(vectors.replay)) {
    const seen = new Set<string>();
    const steps = (c.steps ?? []) as Array<{ body: string; now: string; expect: unknown }>;
    const actual = steps.map((step) => {
      const payload = JSON.parse(Buffer.from(step.body.split(".")[1] as string, "base64url").toString("utf8")) as RelayMessagePayload;
      const result = checkReplay((from, msgId) => seen.has(`${from}\n${msgId}`), payload, new Date(step.now));
      if (result.ok) seen.add(`${payload.from}\n${payload.msgId}`);
      return result;
    });
    out.push({ group: "replay", name: c.name as string, actual, expected: steps.map((step) => step.expect) });
  }
  const blob = (vectors.blobRequest ?? {}) as Json;
  for (const c of cases(blob)) {
    // The signer first, then the state: `expect` is what the two give together.
    const method = c.method as "PUT" | "GET";
    const verified = verifyBlobRequest(c.header as string | null, {
      relay: blob.relay as string, method, digest: blob.digest as string, now: new Date((c.now ?? blob.now) as string), admittedKey: keyring(c.admitted)
    });
    const decided = verified.ok ? decideBlobAccess(method, verified, c.stored as { recipients: string[] } | undefined) : verified;
    const actual = decided.ok && verified.ok ? { ...verified, repeat: decided.repeat } : decided;
    out.push({ group: "blobRequest", name: c.name as string, actual, expected: c.expect });
  }
  return out;
}

/** Every case of `secret-envelope.json`'s `cases`, run through `openEnvelope`. A secret is compared as UTF-8 text. */
export function envelopeVectorResults(vectors: Json): VectorResult[] {
  return cases(vectors).map((c) => {
    const ctx = c.context as Json;
    const holders = (ctx.holders ?? []) as Array<{ sender: string; agentRef: string; slot: string }>;
    const placements = (ctx.placements ?? []) as Array<{ agentRef: string; slot: string; since: number }>;
    const applied = ctx.appliedRevision as number | null;
    const context: OpenContext = {
      ownKemKid: ctx.ownKemKid as string,
      ownKemPrivateKey: Buffer.from(ctx.ownKemPrivateKey as string, "hex"),
      senderKey: keyring(ctx.senders),
      mayHold: (sender, agentRef, slot) => holders.some((h) => h.sender === sender && h.agentRef === agentRef && h.slot === slot),
      currentPlacement: (agentRef, slot) => placements.find((p) => p.agentRef === agentRef && p.slot === slot)?.since,
      appliedRevision: () => (applied === null ? undefined : applied),
      lastOpened: (agentRef, slot) => {
        const found = ((ctx.marks ?? []) as Array<{ agentRef: string; slot: string; since: number; sequence: number; digest: string }>)
          .find((m) => m.agentRef === agentRef && m.slot === slot);
        return found && { since: found.since, sequence: found.sequence, digest: found.digest };
      },
      now: new Date(ctx.now as string)
    };
    const result = openEnvelope(c.envelope, context);
    const actual = result.ok ? { ...result, secret: result.secret.toString("utf8") } : result;
    return { group: "envelope", name: c.name as string, actual, expected: c.expect };
  });
}

/**
 * Every case of `secret-envelope.json`'s `placement` group (DEC-0082), run through `estateEnvelopeContext` with the case's
 * `extraRevocations` (DEC-0084): whether each sender kid may hold the slot and whether `senderKey` knows its key, and the
 * revision its placement run starts at (null for none).
 */
export function placementVectorResults(vectors: Json): VectorResult[] {
  return cases(vectors.placement).map((c) => {
    const ctx = estateEnvelopeContext(c.applied as JsonObject[], c.machine as string, (c.extraRevocations ?? []) as JsonObject[]);
    const agentRef = c.agentRef as string, slot = c.slot as string;
    const holds = ((c.expect as Json).holds as Array<{ sender: string }>).map((h) => ({ sender: h.sender, mayHold: ctx.mayHold(h.sender, agentRef, slot), senderKnown: ctx.senderKey(h.sender) !== undefined }));
    const actual = { holds, currentPlacement: ctx.currentPlacement(agentRef, slot) ?? null };
    return { group: "placement", name: c.name as string, actual, expected: c.expect };
  });
}

/** The `instant` of a value as the vectors write it: an ISO string with milliseconds, or null. */
export function instantResult(value: unknown): string | null {
  const t = instant(value);
  return t === undefined ? null : new Date(t).toISOString();
}
// #endregion relay-vectors
