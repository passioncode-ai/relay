import { createHash } from "node:crypto";
import { rfc8785 } from "./canonical.js";
import { type Finding, type JsonObject, isObject, show } from "./findings.js";
import { strictTime } from "./rfc3339.js";
import { type AssertionVerdict, type PasskeyCredential, verifyAssertion } from "./webauthn.js";

// #region signing-challenges — docs: docs/specification/signing.md
/**
 * The register of signed statements (DEC-0063): every statement a passkey or a key signs is the UTF-8 RFC 8785 form
 * (DEC-0043) of `{type, ...fields}`, with `type` one of the names below and the other members exactly that type's
 * fields. A passkey signs the SHA-256 of those bytes as its WebAuthn challenge; a key signs the bytes themselves. The
 * type inside keeps one signature from standing for another over the same digest. A changed field list is a new type
 * (`/2`), never a new reading of an old one, except DEC-0119's: a type no party adopted, as the backlog records, may
 * change its list by a decision that names the narrowing (DEC-0129, `org-key-set/1`).
 */
export type Signer = "passkey" | "key";

export interface StatementSpec {
  /** Who signs: a passkey assertion over the challenge, or a key over the statement's bytes. */
  signer: Signer;
  /** The members beside `type`, exactly. */
  fields: readonly string[];
  /** The decision that defines the statement. */
  decision: string;
  /** The values each field admits, where this register defines them; otherwise the defining module checks them. */
  check?: (fields: JsonObject) => boolean;
}

const SHA256 = /^sha256:[a-f0-9]{64}$/;
/** `activity-common#/$defs/opaqueId`: no spaces and no `@`. */
const OPAQUE = /^[A-Za-z0-9][A-Za-z0-9._:~-]{0,127}$/;
/** A grant reference, `<meta.id>#<meta.revision>` (DEC-0041). */
const GRANT_REF = /^[^\s#]{1,200}#[1-9][0-9]{0,15}$/;
/** RFC 9449 §6.1 `jkt`: the base64url (unpadded) RFC 7638 SHA-256 thumbprint of a JWK, 32 bytes. */
const JKT = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
/** Whose limits a `limits/1` statement approves: an estate's or an organization's. */
const LIMITS_SCOPE = /^(estate|organization):[A-Za-z0-9][A-Za-z0-9._:~-]{0,127}$/;
/** Whose machines an `enroll-token/1` lets join: an estate's (DEC-0084). */
const ESTATE_SCOPE = /^estate:[A-Za-z0-9][A-Za-z0-9._:~-]{0,127}$/;
/** 32 random bytes as unpadded base64url, the same 43-character form as `jkt`. */
const NONCE32 = JKT;
const isString = (value: unknown): value is string => typeof value === "string";
const positive = (value: unknown) => Number.isSafeInteger(value) && (value as number) >= 1;
const matches = (pattern: RegExp, value: unknown) => isString(value) && pattern.test(value);

/** The window lease's members beside `type`: the lease without `sig` (DEC-0062). */
export const WINDOW_LEASE_FIELDS = [
  "leaseId", "sequence", "estate", "estateRevision", "machine", "scope", "window", "period", "amount", "unit", "issuedAt", "expiresAt", "alg", "kid"
] as const;

/** The enroll token's members beside `type` (DEC-0084), one list for good. */
export const ENROLL_TOKEN_FIELDS = ["scope", "genesis", "purpose", "ceiling", "notBefore", "expiresAt", "nonce", "uses"] as const;

/** The entitlement's members beside `type`: the document without `sig` (DEC-0085). */
export const ENTITLEMENT_FIELDS = [
  "issuer", "subject", "estate", "order", "issuedAt", "notBefore", "expiresAt", "licence", "hosting", "support", "agents", "alg", "kid"
] as const;

/** The entitlement key set's members beside `type`: the set without `sig` (DEC-0085). */
export const ENTITLEMENT_KEY_SET_FIELDS = ["issuer", "revision", "issuedAt", "keys", "revoked", "alg", "kid"] as const;

/** The membership attestation's members beside `type`: the document without `sig` (DEC-0127). */
export const ORG_MEMBERSHIP_FIELDS = [
  "issuer", "org", "audience", "subject", "role", "external", "status", "revision", "membershipEndsAt", "issuedAt", "notBefore", "expiresAt", "extensions", "alg", "kid"
] as const;

/** An organization key set's members beside `type`: the set without `sig` (DEC-0127; `administrators`, DEC-0129). */
export const ORG_KEY_SET_FIELDS = ["issuer", "org", "revision", "issuedAt", "keys", "revoked", "administrators", "alg", "kid"] as const;

/** A Map, so a type named like an Object.prototype member reads nothing. */
export const SIGNING_STATEMENTS: ReadonlyMap<string, StatementSpec> = new Map<string, StatementSpec>([
  ["estate-revision/1", { signer: "passkey", fields: ["digest"], decision: "DEC-0055", check: (f) => matches(SHA256, f.digest) }],
  [
    "org-countersign/1",
    {
      signer: "passkey",
      fields: ["organization", "digest", "audience", "grant", "revision"],
      decision: "DEC-0063",
      check: (f) => matches(OPAQUE, f.organization) && matches(SHA256, f.digest) && matches(OPAQUE, f.audience) && matches(GRANT_REF, f.grant) && positive(f.revision)
    }
  ],
  [
    "share-grant/1",
    {
      signer: "passkey",
      fields: ["estate", "grant", "jkt", "expiresAt"],
      decision: "DEC-0063",
      check: (f) => matches(OPAQUE, f.estate) && matches(GRANT_REF, f.grant) && matches(JKT, f.jkt) && Number.isFinite(strictTime(f.expiresAt))
    }
  ],
  ["limits/1", { signer: "passkey", fields: ["scope", "digest"], decision: "DEC-0063", check: (f) => matches(LIMITS_SCOPE, f.scope) && matches(SHA256, f.digest) }],
  [
    "enroll-token/1",
    {
      signer: "passkey",
      fields: ENROLL_TOKEN_FIELDS,
      decision: "DEC-0084",
      // The values only; the window's length (at most 900 s) is FAC-SEM-113's and the verifier's (src/enroll-token.ts).
      check: (f) =>
        matches(ESTATE_SCOPE, f.scope) && matches(SHA256, f.genesis) && f.purpose === "agent-host" && (f.ceiling === null || matches(SHA256, f.ceiling)) &&
        Number.isFinite(strictTime(f.notBefore)) && Number.isFinite(strictTime(f.expiresAt)) && matches(NONCE32, f.nonce) && f.uses === 1
    }
  ],
  [
    "fabric-package-signature/1",
    { signer: "key", fields: ["role", "digest"], decision: "DEC-0051", check: (f) => (f.role === "publisher" || f.role === "organization") && matches(SHA256, f.digest) }
  ],
  ["enroll-join/1", { signer: "key", fields: ["digest", "nonce"], decision: "DEC-0084", check: (f) => matches(SHA256, f.digest) && matches(NONCE32, f.nonce) }],
  ["window-lease/1", { signer: "key", fields: WINDOW_LEASE_FIELDS, decision: "DEC-0062" }],
  ["relay-auth/1", { signer: "key", fields: ["alg", "relay", "nonce", "estate", "kid", "iat"], decision: "DEC-0047" }],
  ["relay-blob/1", { signer: "key", fields: ["alg", "relay", "method", "digest", "recipients", "iat"], decision: "DEC-0047" }],
  ["entitlement/1", { signer: "key", fields: ENTITLEMENT_FIELDS, decision: "DEC-0085" }],
  ["entitlement-key-set/1", { signer: "key", fields: ENTITLEMENT_KEY_SET_FIELDS, decision: "DEC-0085" }],
  ["org-membership/1", { signer: "key", fields: ORG_MEMBERSHIP_FIELDS, decision: "DEC-0127" }],
  ["org-key-set/1", { signer: "key", fields: ORG_KEY_SET_FIELDS, decision: "DEC-0127" }],
  // DEC-0129: an administrator's passkey signs the organization's member list by its digest, as estate-revision/1 does a record.
  ["org-authority/1", { signer: "passkey", fields: ["digest"], decision: "DEC-0129", check: (f) => matches(SHA256, f.digest) }]
]);

/**
 * The bytes of a registered statement: the UTF-8 RFC 8785 form of `{type, ...fields}`. `undefined` when the type is not
 * registered, the fields are not exactly the type's, a value is outside what the register admits, or a value has no
 * RFC 8785 form. A verifier rebuilds the statement from the values it checks, never from bytes it was handed.
 */
export function signingStatement(type: string, fields: unknown): Buffer | undefined {
  const spec = SIGNING_STATEMENTS.get(type);
  if (!spec || !isObject(fields)) return undefined;
  const names = Object.keys(fields);
  if (names.length !== spec.fields.length || !spec.fields.every((name) => Object.hasOwn(fields, name))) return undefined;
  if (spec.check && !spec.check(fields)) return undefined;
  try {
    return Buffer.from(rfc8785({ ...fields, type }), "utf8");
  } catch {
    return undefined;
  }
}

/**
 * The WebAuthn challenge a signer passes to `navigator.credentials.get()` for a passkey statement: SHA-256 of
 * `signingStatement`. `undefined` for a key-signed type, which has no challenge, or for a statement that has no bytes.
 */
export function signingChallenge(type: string, fields: unknown): Buffer | undefined {
  if (SIGNING_STATEMENTS.get(type)?.signer !== "passkey") return undefined;
  const statement = signingStatement(type, fields);
  return statement && createHash("sha256").update(statement).digest();
}

const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
/** `sign.` and at least two more labels, lower-case: a signing RP ID is never a bare `sign.<tld>`. */
const SIGNING_RP = new RegExp(`^sign(?:\\.${LABEL}){2,}$`);

/**
 * Whether an RP ID is a dedicated signing RP (v4 §7, DEC-0063): its first label is `sign`, followed by the domain of the
 * organization or of PassionCode, in lower case. A credential under any other RP ID is a sign-in credential and never
 * signs a statement.
 */
export function isSigningRpId(rpId: unknown): boolean {
  return isString(rpId) && rpId.length <= 253 && SIGNING_RP.test(rpId);
}

/**
 * Whether a pinned origin may run a signing ceremony for `rpId`: `https://`, no port and no path, its host the RP ID or
 * a subdomain of it, in lower case (WebAuthn Level 3 §4, *RP ID*: a registrable suffix of the origin's effective domain).
 * Related origins (WebAuthn Level 3 §5.11) are never used for signing.
 */
export function originWithin(origin: unknown, rpId: string): boolean {
  const host = isString(origin) ? /^https:\/\/([a-z0-9.-]{1,253})$/.exec(origin)?.[1] : undefined;
  return host !== undefined && (host === rpId || host.endsWith(`.${rpId}`));
}

/**
 * Verify a passkey's signature over a registered statement (DEC-0063). The credential is checked first: an RP ID that is
 * not a signing RP is `wrong-rp` before the assertion is read; an origin outside the RP ID is not pinned, so a ceremony
 * that ran in it is `wrong-origin`. Then WebAuthn Level 3 §7.2 as `verifyAssertion` runs it, over the challenge rebuilt
 * from `type` and `fields`; a statement that has no challenge is `malformed`.
 */
export function verifySigningAssertion(assertion: unknown, credential: PasskeyCredential, type: string, fields: unknown): AssertionVerdict {
  const challenge = signingChallenge(type, fields);
  if (!challenge) return { ok: false, problem: "malformed" };
  if (!isSigningRpId(credential.rpId)) return { ok: false, problem: "wrong-rp" };
  return verifyAssertion(assertion, { ...credential, origins: credential.origins.filter((origin) => originWithin(origin, credential.rpId)) }, challenge);
}

/**
 * FAC-SEM-092 on one signing credential: its RP ID is a signing RP and every origin it pins is within that RP ID. `path`
 * is the credential's instance path.
 */
export function signingCredentialFindings(credential: unknown, path: string): Finding[] {
  const findings: Finding[] = [];
  const flag = (instancePath: string, message: string) => findings.push({ code: "FAC-SEM-092", instancePath, message });
  const value = isObject(credential) ? credential : {};
  if (!isSigningRpId(value.rpId)) {
    flag(`${path}/rpId`, "a passkey signs only under a dedicated signing RP, sign.<domain>, never under the RP ID it signs in with");
    return findings;
  }
  const origins = Array.isArray(value.origins) ? value.origins : [];
  origins.forEach((origin, index) => {
    if (!originWithin(origin, value.rpId as string)) flag(`${path}/origins/${index}`, `a signing ceremony runs only on ${show(value.rpId)} or a host under it, over https without a port`);
  });
  return findings;
}

export function signingRules(kind: string, value: JsonObject): Finding[] | undefined {
  if (kind === "signing-credential") return signingCredentialFindings(value, "");
  return undefined;
}
// #endregion signing-challenges
