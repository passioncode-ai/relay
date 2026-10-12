// An estate record the relay's tests can admit from: the contract's revision 1 with machine m-4c1e's #sig replaced by
// a key the test holds, its window around now, re-signed by the contract's EdDSA test passkey (whose seed the vectors
// publish as test data). The contract's own verifier then accepts it — nothing here bypasses a check. `revise()` builds
// the next revision over its parent's digest, and `forge()` one signed by a passkey nobody listed (RLY-025).
import { createHash, createPrivateKey, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { estateChallenge, estateRecordDigest } from "../src/contract/estate-record-rules.ts";

const vectors = JSON.parse(readFileSync(path.resolve(import.meta.dirname, "vectors/estate-record.json"), "utf8"));
const sha = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest();

export const MACHINE_KID = "m-4c1e#sig";
export const SECOND_KID = "m-9a07#sig";
export type Passkey = "EdDSA" | "ES256";

export interface Estate {
  record: Record<string, any>;
  pinned: unknown[];
  machine: { kid: string; privateKey: KeyObject; jwk: Record<string, string> };
  second: { kid: string; privateKey: KeyObject; jwk: Record<string, string> };
}

function key(kid: string) {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" }) as Record<string, string>;
  const octets = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x!, "base64url"), Buffer.from(jwk.y!, "base64url")]).toString("base64");
  return { kid, privateKey: pair.privateKey, jwk, octets };
}

export function estate(now = new Date(), passkey: Passkey = "EdDSA"): Estate {
  const first = key(MACHINE_KID), second = key(SECOND_KID);
  const { digest: _digest, signature: _signature, ...body } = structuredClone(vectors.cases[0].record) as Record<string, any>;
  // m-9a07's #sig is Ed25519 in the vectors; a relay participant signs ES256 (DEC-0047 item 8), so both become P-256.
  for (const m of body.machines) for (const k of m.deviceKeys) for (const own of [first, second]) if (k.kid === own.kid) Object.assign(k, { alg: "es256", publicKey: own.octets });
  body.issuedAt = stamp(new Date(now.getTime() - 3_600_000));
  body.validUntil = stamp(new Date(now.getTime() + 86_400_000));
  const strip = ({ kid, privateKey, jwk }: ReturnType<typeof key>) => ({ kid, privateKey, jwk });
  return { record: seal(body, passkey), pinned: [authorityOf(passkey)], machine: strip(first), second: strip(second) };
}

/** Who signs a revision: one of the two test passkeys every fixture record lists, or a passkey nobody listed. */
export type Signer = Passkey | "stranger";

export interface Revision {
  /** The passkey that signs it (default EdDSA). */
  signer?: Signer;
  /** Machines (named by their `#sig` kid) that leave the record: they are not in the next admission set. */
  dropKids?: readonly string[];
  /** The new window's end (RFC 3339, whole seconds); default the parent's. */
  validUntil?: string;
  /** When it was issued; default one second after its parent, so a chain of revisions stays ordered. */
  issuedAt?: string;
}

/**
 * Revision n+1 of `prev`: the parent's digest in `parent`, the same estate, machines and authorities, re-signed. Nothing
 * here decides validity — the contract's verifier does, so a forged or broken successor is refused for real.
 */
export function revise(prev: Estate, options: Revision = {}): Estate {
  const { digest: _digest, signature: _signature, ...body } = structuredClone(prev.record) as Record<string, any>;
  body.revision = Number(prev.record.revision) + 1;
  body.parent = prev.record.digest;
  body.issuedAt = options.issuedAt ?? stamp(new Date(Date.parse(prev.record.issuedAt) + 1000));
  if (options.validUntil) body.validUntil = options.validUntil;
  const drop = new Set(options.dropKids ?? []);
  if (drop.size > 0) {
    // A machine has exactly one #sig key (FAC-SEM-073), so dropping it drops the machine, and what names it as a source.
    const gone = new Set(body.machines.filter((m: any) => m.deviceKeys.some((k: { kid: string }) => drop.has(k.kid))).map((m: any) => m.id));
    body.machines = body.machines.filter((m: any) => !gone.has(m.id));
    for (const m of body.machines) if (Array.isArray(m.secrets)) m.secrets = m.secrets.filter((secret: { from?: string }) => !gone.has(secret.from));
  }
  return { ...prev, record: seal(body, options.signer ?? "EdDSA") };
}

/** Revision n+1 signed by a passkey the parent does not list: the contract must refuse it. */
export function forge(prev: Estate, options: Omit<Revision, "signer"> = {}): Estate {
  return revise(prev, { ...options, signer: "stranger" });
}

const stamp = (at: Date) => at.toISOString().replace(/\.\d{3}Z$/, "Z");

function authorityOf(passkey: Passkey) {
  return passkey === "EdDSA" ? vectors.keys.passkeyEdDSA.authority : vectors.keys.passkeyEs256.authority;
}

/** The record's digest and a WebAuthn assertion over its challenge, by `signer`. */
function seal(body: Record<string, any>, signer: Signer): Record<string, any> {
  let authority: { credentialId: string; rpId: string; origins: string[] };
  let key: KeyObject;
  let alg: Passkey;
  if (signer === "stranger") {
    // A passkey of the same RP that no record lists: same shape, unknown credential, its own key.
    const pair = generateKeyPairSync("ed25519");
    authority = { ...vectors.keys.passkeyEdDSA.authority, credentialId: "c3RyYW5nZXItcGFzc2tleQ" };
    key = pair.privateKey;
    alg = "EdDSA";
  } else {
    authority = authorityOf(signer);
    key = signer === "EdDSA"
      ? createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(vectors.keys.passkeyEdDSA.seed, "hex")]), format: "der", type: "pkcs8" })
      : createPrivateKey({ key: vectors.keys.passkeyEs256.privateJwk, format: "jwk" });
    alg = signer;
  }
  const digest = estateRecordDigest(body);
  const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: estateChallenge(digest).toString("base64url"), origin: authority.origins[0] }));
  const authData = Buffer.concat([sha(authority.rpId), Buffer.from([0x05]), Buffer.alloc(4)]);
  // EdDSA signs the bytes; ES256 an ASN.1 DER Ecdsa-Sig-Value over their SHA-256 (WebAuthn §6.5.5).
  const signature = sign(alg === "EdDSA" ? null : "sha256", Buffer.concat([authData, sha(clientData)]), key);
  return { ...body, digest, signature: { format: "webauthn-assertion", credentialId: authority.credentialId, alg,
    authenticatorData: authData.toString("base64url"), clientDataJSON: clientData.toString("base64url"), sig: signature.toString("base64url") } };
}
