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
export type Passkey = "EdDSA" | "ES256";

export interface Estate {
  record: Record<string, any>;
  pinned: unknown[];
  machine: { kid: string; privateKey: KeyObject; jwk: Record<string, string> };
}

export function estate(now = new Date(), passkey: Passkey = "EdDSA"): Estate {
  const machine = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = machine.publicKey.export({ format: "jwk" }) as Record<string, string>;
  const octets = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x!, "base64url"), Buffer.from(jwk.y!, "base64url")]).toString("base64");
  const { digest: _digest, signature: _signature, ...body } = structuredClone(vectors.cases[0].record) as Record<string, any>;
  for (const m of body.machines) for (const key of m.deviceKeys) if (key.kid === MACHINE_KID) key.publicKey = octets;
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
  return { record, pinned: [authority], machine: { kid: MACHINE_KID, privateKey: machine.privateKey, jwk } };
}
