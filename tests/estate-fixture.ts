// An estate record the relay's tests can admit from: the contract's revision 1 with machine m-4c1e's #sig replaced by
// a key the test holds, its window around now, re-signed by the contract's EdDSA test passkey (whose seed the vectors
// publish as test data). The contract's own verifier then accepts it — nothing here bypasses a check.
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
  body.issuedAt = new Date(now.getTime() - 3_600_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  body.validUntil = new Date(now.getTime() + 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const authority = passkey === "EdDSA" ? vectors.keys.passkeyEdDSA.authority : vectors.keys.passkeyEs256.authority;
  const signer = passkey === "EdDSA"
    ? createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(vectors.keys.passkeyEdDSA.seed, "hex")]), format: "der", type: "pkcs8" })
    : createPrivateKey({ key: vectors.keys.passkeyEs256.privateJwk, format: "jwk" });
  const digest = estateRecordDigest(body);
  const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: estateChallenge(digest).toString("base64url"), origin: authority.origins[0] }));
  const authData = Buffer.concat([sha(authority.rpId), Buffer.from([0x05]), Buffer.alloc(4)]);
  // EdDSA signs the bytes; ES256 an ASN.1 DER Ecdsa-Sig-Value over their SHA-256 (WebAuthn §6.5.5).
  const signature = sign(passkey === "EdDSA" ? null : "sha256", Buffer.concat([authData, sha(clientData)]), signer);
  const record = { ...body, digest, signature: { format: "webauthn-assertion", credentialId: authority.credentialId, alg: passkey,
    authenticatorData: authData.toString("base64url"), clientDataJSON: clientData.toString("base64url"), sig: signature.toString("base64url") } };
  const strip = ({ kid, privateKey, jwk }: ReturnType<typeof key>) => ({ kid, privateKey, jwk });
  return { record, pinned: [authority], machine: strip(first), second: strip(second) };
}
