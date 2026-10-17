// The one signer of the relay's tests (RP exit, DEC-0066): every test machine signs `relay-auth/1` and `relay-blob/1`
// through the contract's own `signEs256`, which emits the low-S form a relay-family verifier admits. A raw
// `crypto.sign` signature is high-S half the time and `admit` refuses it, so no test may sign any other way.
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { p256Point, signEs256 } from "../src/contract/p256.ts";
import { relayAuthSigningInput, relayBlobSigningInput, relayRequestHeader, type AdmissionResult } from "../src/contract/relay.ts";

/** The estate every test record and every test `auth` frame names, unless a test says otherwise. */
export const TEST_ESTATE = "urn:fabric:estate:test";

export interface TestMachine {
  kid: string;
  privateKey: KeyObject;
  jwk: Record<string, string>;
  /** The `#sig` key as SEC 1 octets, the form an admission set holds. */
  octets: Uint8Array;
}

/** A P-256 machine key under `kid`. */
export function machine(kid: string): TestMachine {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" }) as Record<string, string>;
  return { kid, privateKey: pair.privateKey, jwk, octets: new Uint8Array(p256Point(jwk)) };
}

/** An RFC 3339 UTC instant to whole seconds, the form `iat` takes. */
export const iatOf = (at: Date | number = Date.now()): string => new Date(at).toISOString().replace(/\.\d{3}Z$/, "Z");

/** A verified admission naming `machines`, held for `estate`, as `relayAdmissionSet` answers it. */
export function admittedSet(machines: readonly TestMachine[], options: { revision?: number; estate?: string } = {}): AdmissionResult {
  return {
    ok: true,
    held: { estate: options.estate ?? TEST_ESTATE },
    revision: options.revision ?? 1,
    set: new Map(machines.map((m) => [m.kid, m.octets])),
    excluded: [],
  };
}

/** A machine's `auth` frame (as an object) for `nonce`, signed for `relay` with the machine's own key. */
export function authFrame(
  m: Pick<TestMachine, "kid" | "privateKey">,
  options: { relay: string; nonce: string; estate?: string; at?: Date | number; id?: string },
): Record<string, unknown> {
  const fields = { relay: options.relay, nonce: options.nonce, estate: options.estate ?? TEST_ESTATE, kid: m.kid, iat: iatOf(options.at) };
  const sig = signEs256(m.privateKey, relayAuthSigningInput(fields));
  return { v: 1, type: "auth", id: options.id ?? "a1", protocol: "fabric-relay/0.1", alg: "ES256", ...fields, sig };
}

/** A `Fabric-Relay-Request` header for a blob request, signed with the machine's own key. */
export function blobHeader(
  m: Pick<TestMachine, "kid" | "privateKey">,
  options: { relay: string; method: "PUT" | "GET"; digest: string; recipients: string[]; at?: Date | number },
): string {
  const iat = iatOf(options.at);
  const sig = signEs256(m.privateKey, relayBlobSigningInput({ relay: options.relay, method: options.method, digest: options.digest, recipients: options.recipients, iat }));
  return relayRequestHeader({ alg: "ES256", kid: m.kid, recipients: options.recipients, iat, sig });
}
