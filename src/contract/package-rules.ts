import { createHash, createPublicKey, verify as verifySignature, type KeyObject } from "node:crypto";
import { rfc8785 } from "./canonical.js";
import { isSmallOrderKey } from "./ed25519.js";
import { type Finding, type JsonObject, isObject, jsonEqual } from "./findings.js";
import { secretArgument, secretValue } from "./secret-shape.js";

// #region package-rules — docs: docs/specification/package.md#semantic-rules
/**
 * `fabric-package/1` (DEC-0050, DEC-0051): one version of an agent or a skill set, as `fabric.package.json` at the root
 * of its folder. The digest covers the document without `digest` and `signatures`, and through `files[]` every other
 * file of the folder; a publisher signs the digest and an organization countersigns it, each naming its algorithm.
 */
const list = (value: unknown): JsonObject[] => (Array.isArray(value) ? value.filter(isObject) : []);
const isString = (value: unknown): value is string => typeof value === "string";

/** The file that carries the package; it cannot list its own digest, so it is never in `files[]`. */
export const PACKAGE_FILE = "fabric.package.json";
/** The Claude Code plugin manifest a folder carries; its `name` and `version` are the package's (D-SK1). */
export const PLUGIN_MANIFEST = ".claude-plugin/plugin.json";
/** The statement type every package signature covers (DEC-0051). */
export const SIGNATURE_STATEMENT = "fabric-package-signature/1";
/**
 * The algorithms a package signature may name (DEC-0051). `ES256` joins when Fabric records its decision D2 (ES256
 * beside EdDSA); until then a verifier of this version refuses it as `unknown-algorithm`.
 */
export const PACKAGE_ALGORITHMS: readonly string[] = ["EdDSA"];

/** `urn:fabric:agent:<publisher>:<id>` — the name of one agent across its versions (FAC-SEM-066, DEC-0050). */
export function agentRefOf(publisher: string, id: string): string {
  return `urn:fabric:agent:${publisher}:${id}`;
}

/** `sha256:` and the hex SHA-256 of some bytes, the form `files[]` and `digest` use. */
export function sha256Of(bytes: Uint8Array | string): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

/**
 * The package digest (DEC-0050): SHA-256 over the UTF-8 bytes of the RFC 8785 form (DEC-0043) of the package without
 * `digest` and `signatures`. Throws a `TypeError` for a value RFC 8785 has no form for.
 */
export function packageDigest(pkg: JsonObject): string {
  const { digest: _digest, signatures: _signatures, ...covered } = pkg;
  return sha256Of(Buffer.from(rfc8785(covered), "utf8"));
}

/**
 * The bytes a package signature covers (DEC-0051): the UTF-8 RFC 8785 form of
 * `{type: "fabric-package-signature/1", role, digest}`. The role is signed, so a publisher's signature never stands
 * for an organization's countersignature.
 */
export function packageSigningInput(digest: string, role: string): Buffer {
  return Buffer.from(rfc8785({ type: SIGNATURE_STATEMENT, role, digest }), "utf8");
}

export type PackageProblem =
  | "malformed"
  | "digest-mismatch"
  | "unsigned"
  | "no-publisher-signature"
  | "unknown-algorithm"
  | "unknown-key"
  | "duplicate-kid"
  | "key-algorithm-mismatch"
  | "unusable-key"
  | "small-order-key"
  | "bad-signature"
  | "no-countersignature";

export type PackageVerdict =
  | { ok: true; digest: string; signers: Array<{ role: string; kid: string }>; unverified?: Array<{ role: string; kid: string }> }
  | { ok: false; problem: PackageProblem; signature?: number };

/** The keys a verifier trusts, per role: JWKs (`kty`, `crv`, `x`, `kid`, `alg`), as the installing machine pinned them. */
export interface PackageTrust {
  publisher: readonly unknown[];
  organization?: readonly unknown[];
}

const B64URL = /^[A-Za-z0-9_-]+$/;

type KeyLookup = { key: KeyObject } | { problem: "unknown-key" | "duplicate-kid" | "key-algorithm-mismatch" | "unusable-key" | "small-order-key" };

/** PK-4…PK-7: the one key a signature's `kid` names in its role's set, for the signature's algorithm. */
function keyFor(keys: readonly unknown[], kid: string, alg: string): KeyLookup {
  const matches = keys.filter((candidate) => isObject(candidate) && candidate.kid === kid) as JsonObject[];
  if (matches.length > 1) return { problem: "duplicate-kid" };
  const jwk = matches[0];
  if (!jwk) return { problem: "unknown-key" };
  // v4 rule 12: every key names its alg, and a verifier accepts only that alg for that kid.
  if (jwk.alg !== alg) return { problem: "key-algorithm-mismatch" };
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !isString(jwk.x) || !B64URL.test(jwk.x) || jwk.d !== undefined || (jwk.use !== undefined && jwk.use !== "sig")) return { problem: "unusable-key" };
  const raw = Buffer.from(jwk.x, "base64url");
  if (raw.length !== 32) return { problem: "unusable-key" };
  // DEC-0045 (CT-29): a small-order key verifies forged signatures on Node 20 and 22; it is refused before any use.
  if (isSmallOrderKey(raw)) return { problem: "small-order-key" };
  return { key: createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" }) };
}

/**
 * The reference verifier (DEC-0051), in the order of package.md's PK table: the digest is recomputed first, then
 * exactly one publisher signature, then every signature — its algorithm admitted, its key found in its role's set
 * under that algorithm, of full order, the signature verifying over `packageSigningInput`. Shape and PK-5…PK-9 are
 * checked per signature, in array order, after PK-4. A signature under a pinned key must verify: a bad countersignature
 * refuses the package, it is never skipped. An organization countersignature whose `kid` this machine does not pin is
 * set aside, listed as `unverified`, unless `countersigned` is asked — then at least one countersignature must verify,
 * so a publisher's own machines keep installing a package after an organization countersigns it.
 */
export function verifyPackage(pkg: unknown, trust: PackageTrust, options: { countersigned?: boolean } = {}): PackageVerdict {
  if (!isObject(pkg) || !isString(pkg.digest)) return { ok: false, problem: "malformed" };
  let digest: string;
  try {
    digest = packageDigest(pkg);
  } catch {
    return { ok: false, problem: "malformed" };
  }
  if (digest !== pkg.digest) return { ok: false, problem: "digest-mismatch" };
  if (pkg.signatures === undefined || (Array.isArray(pkg.signatures) && pkg.signatures.length === 0)) return { ok: false, problem: "unsigned" };
  if (!Array.isArray(pkg.signatures)) return { ok: false, problem: "malformed" };
  const signatures: unknown[] = pkg.signatures;
  if (signatures.filter((entry) => isObject(entry) && entry.role === "publisher").length !== 1) return { ok: false, problem: "no-publisher-signature" };
  const signers: Array<{ role: string; kid: string }> = [];
  const unverified: Array<{ role: string; kid: string }> = [];
  for (const [index, entry] of signatures.entries()) {
    if (!isObject(entry) || (entry.role !== "publisher" && entry.role !== "organization") || !isString(entry.alg) || !isString(entry.kid) || !isString(entry.sig) || !B64URL.test(entry.sig)) {
      return { ok: false, problem: "malformed", signature: index };
    }
    if (!PACKAGE_ALGORITHMS.includes(entry.alg)) return { ok: false, problem: "unknown-algorithm", signature: index };
    const found = keyFor((entry.role === "publisher" ? trust.publisher : trust.organization) ?? [], entry.kid, entry.alg);
    if ("problem" in found && found.problem === "unknown-key" && entry.role === "organization" && options.countersigned !== true) {
      unverified.push({ role: entry.role, kid: entry.kid });
      continue;
    }
    if ("problem" in found) return { ok: false, problem: found.problem, signature: index };
    const signature = Buffer.from(entry.sig, "base64url");
    // RFC 8032 §5.1.7: an Ed25519 signature is 64 bytes; checked here for a port whose library is laxer than Node's.
    if (signature.length !== 64 || !verifySignature(null, packageSigningInput(digest, entry.role), found.key, signature)) {
      return { ok: false, problem: "bad-signature", signature: index };
    }
    signers.push({ role: entry.role, kid: entry.kid });
  }
  if (options.countersigned === true && !signers.some((signer) => signer.role === "organization")) return { ok: false, problem: "no-countersignature" };
  return unverified.length ? { ok: true, digest, signers, unverified } : { ok: true, digest, signers };
}

export type FolderProblem = "file-missing" | "file-unlisted" | "file-digest" | "plugin-manifest" | "provider-manifest";

const parsed = (bytes: Uint8Array | undefined): JsonObject | undefined => {
  if (bytes === undefined) return undefined;
  try {
    const value: unknown = JSON.parse(Buffer.from(bytes).toString("utf8"));
    return isObject(value) ? value : undefined;
  } catch {
    return undefined;
  }
};

/**
 * The folder check (DEC-0050): what makes the digest cover the folder. Every listed file is present with the listed
 * SHA-256, no other file is present but `fabric.package.json`, a plugin manifest names the package's id and version,
 * and an agent's provider manifest carries the package's cost presets or none. `files` maps each path, relative to the
 * folder with forward slashes, to its bytes.
 */
export function checkPackageFolder(pkg: JsonObject, files: ReadonlyMap<string, Uint8Array>): Array<{ problem: FolderProblem; path: string }> {
  const problems: Array<{ problem: FolderProblem; path: string }> = [];
  const listed = new Map(list(pkg.files).map((entry) => [String(entry.path), entry.sha256] as const));
  for (const [path, sha256] of listed) {
    const bytes = files.get(path);
    if (bytes === undefined) problems.push({ problem: "file-missing", path });
    else if (sha256Of(bytes) !== sha256) problems.push({ problem: "file-digest", path });
  }
  for (const path of files.keys()) if (path !== PACKAGE_FILE && !listed.has(path)) problems.push({ problem: "file-unlisted", path });
  if (files.has(PLUGIN_MANIFEST)) {
    const plugin = parsed(files.get(PLUGIN_MANIFEST));
    if (!plugin || plugin.name !== pkg.id || plugin.version !== pkg.version) problems.push({ problem: "plugin-manifest", path: PLUGIN_MANIFEST });
  }
  if (isString(pkg.provider)) {
    const provider = parsed(files.get(pkg.provider));
    if (files.has(pkg.provider) && (!provider || (provider.costPresets !== undefined && !jsonEqual(provider.costPresets, pkg.costPresets)))) {
      problems.push({ problem: "provider-manifest", path: pkg.provider });
    }
  }
  return problems;
}

/**
 * FAC-SEM-064: a package is whole — its digest is its own, each path is listed once and never `fabric.package.json`,
 * every file it names (the provider manifest, the service's entry, the evals suite, a vendored dependency) is listed,
 * with the same SHA-256 where it repeats one, a state path is declared once, and a skill set carries its plugin
 * manifest.
 */
function whole(value: JsonObject): Finding[] {
  const findings: Finding[] = [];
  const flag = (instancePath: string, message: string) => findings.push({ code: "FAC-SEM-064", instancePath, message });
  try {
    const digest = packageDigest(value);
    if (digest !== value.digest) flag("/digest", `the digest is ${digest}: the package changed after it was packed, or was packed over another form than RFC 8785`);
  } catch {
    flag("/digest", "the package has no RFC 8785 form, so it has no digest");
  }
  const sha = new Map<string, unknown>();
  list(value.files).forEach((entry, index) => {
    const path = String(entry.path);
    if (sha.has(path)) flag(`/files/${index}/path`, `${path} is listed twice`);
    if (path === PACKAGE_FILE) flag(`/files/${index}/path`, `${PACKAGE_FILE} carries the digest and is never listed in files[]`);
    sha.set(path, entry.sha256);
  });
  const named = (instancePath: string, path: unknown, what: string) => {
    if (isString(path) && !sha.has(path)) flag(instancePath, `${what} ${path} is not listed in files[], so the digest does not cover it`);
  };
  named("/provider", value.provider, "the provider manifest");
  if (isObject(value.service) && Array.isArray(value.service.entry)) named("/service/entry/0", value.service.entry[0], "the service's entry");
  if (isObject(value.evals)) {
    named("/evals/suite", value.evals.suite, "the evals suite");
    const receipt = isObject(value.evals.receipt) ? value.evals.receipt : undefined;
    if (receipt && isString(value.evals.suite) && sha.has(value.evals.suite) && receipt.suite !== sha.get(value.evals.suite)) {
      flag("/evals/receipt/suite", "the receipt was written for another suite than the one packed");
    }
  }
  list(value.dependencies).forEach((dependency, index) => {
    if (!isString(dependency.path)) return;
    named(`/dependencies/${index}/path`, dependency.path, "the vendored dependency");
    if (sha.has(dependency.path) && sha.get(dependency.path) !== dependency.sha256) flag(`/dependencies/${index}/sha256`, `the vendored ${String(dependency.name)} is not the file packed at ${dependency.path}`);
  });
  const paths = new Set<unknown>();
  list(value.state).forEach((entry, index) => {
    if (paths.has(entry.path)) flag(`/state/${index}/path`, `state ${String(entry.path)} is declared twice`);
    paths.add(entry.path);
  });
  if (value.kind === "skill-set" && !sha.has(PLUGIN_MANIFEST)) flag("/files", `a skill set is one Claude Code plugin folder and lists ${PLUGIN_MANIFEST}`);
  return findings;
}

/**
 * FAC-SEM-065 (DEC-0013): a package carries no secret — a secret slot is a name and a purpose, each slot named once,
 * and neither looks like a credential; the service's entry passes none on its command line.
 */
function noSecret(value: JsonObject): Finding[] {
  const findings: Finding[] = [];
  const flag = (instancePath: string, message: string) => findings.push({ code: "FAC-SEM-065", instancePath, message });
  const names = new Set<unknown>();
  list(value.secrets).forEach((slot, index) => {
    if (names.has(slot.name)) flag(`/secrets/${index}/name`, `secret slot ${String(slot.name)} is declared twice`);
    names.add(slot.name);
    // The message never repeats the value.
    for (const field of ["name", "purpose"] as const) {
      const text = slot[field];
      if (isString(text) && secretValue(text)) flag(`/secrets/${index}/${field}`, "a secret slot is named, never filled: this looks like a credential");
    }
  });
  if (isObject(value.service) && Array.isArray(value.service.entry)) {
    value.service.entry.forEach((arg, index) => {
      if (isString(arg) && secretArgument(arg)) flag(`/service/entry/${index}`, "a launch argument never carries a credential: the secret reaches the service from its slot");
    });
  }
  return findings;
}

/** FAC-SEM-066: an agent package's `agentRef` is `urn:fabric:agent:<publisher>:<id>`, derived and never chosen. */
function agentRef(value: JsonObject): Finding[] {
  if (value.kind !== "agent" || !isString(value.publisher) || !isString(value.id)) return [];
  const expected = agentRefOf(value.publisher, value.id);
  if (value.agentRef === expected) return [];
  return [{ code: "FAC-SEM-066", instancePath: "/agentRef", message: `the agent is ${expected}: agentRef is derived from publisher and id` }];
}

export function packageRules(kind: string, value: JsonObject): Finding[] | undefined {
  if (kind === "package") return [...whole(value), ...noSecret(value), ...agentRef(value)];
  return undefined;
}
// #endregion package-rules
