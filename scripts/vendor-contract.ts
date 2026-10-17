// Copies the contract's reference code and vectors this relay runs, at the commit fabric-contract.lock.json pins, and
// records each file's SHA-256 in src/contract/VENDORED.json. The copies are byte for byte: tests/contract.test.ts refuses
// a vendored file whose hash drifted from the manifest, or a manifest naming another commit than the lock.
//
//   node --import tsx scripts/vendor-contract.ts <path to a fabric-agent-contract checkout>
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { buildSync } from "esbuild";

// Ajv ships CommonJS; `require` gives the same objects under Node whatever the module mode.
const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020").default as new (options: object) => {
  addSchema(schema: object): void; getSchema(id: string): unknown;
};
const addFormats = require("ajv-formats").default as (ajv: unknown) => unknown;
const standaloneCode = require("ajv/dist/standalone").default as (ajv: unknown, validate: unknown) => string;

/** The relay's closure of the contract: `src/relay.ts`, `src/secret-envelope.ts`, `src/relay-rules.ts` (FAC-SEM-070/071) and what they import. */
export const SOURCES = [
  "canonical.ts", "ed25519.ts", "estate-record-rules.ts", "findings.ts", "p256.ts", "package-rules.ts",
  "relay.ts", "relay-rules.ts", "secret-envelope.ts", "secret-shape.ts", "webauthn.ts",
  // Reached by the closure since bf3fd6b (DEC-0066): strict RFC 3339 times, contexts, identifiers, signing challenges.
  "rfc3339.ts", "context-route.ts", "context-rules.ts", "identifiers.ts", "signing-challenges.ts", "revocation-delta.ts",
  // The runner of the shared vectors (DEC-0066 "Shared vectors"): a port runs every case the contract runs.
  "relay-vectors.ts",
] as const;
export const VECTORS = ["relay.json", "secret-envelope.json", "estate-record.json", "p256.json"] as const;
/** The estate record's schema and every schema it reaches by `$ref`: a relay applies a revision only when it is valid. */
export const SCHEMA_ROOT = "estate-record.schema.json";
/** The frame schema: the relay classifies every frame a node sends with its validator, compiled ahead of time too. */
export const FRAME_SCHEMA = "relay-frame.schema.json";

const root = path.resolve(import.meta.dirname, "..");
const checkout = process.argv[2];
if (!checkout) throw new Error("usage: vendor-contract.ts <fabric-agent-contract checkout>");
const lock = JSON.parse(readFileSync(path.join(root, "fabric-contract.lock.json"), "utf8")) as { commit: string };
const show = (file: string) => execFileSync("git", ["-C", checkout, "show", `${lock.commit}:${file}`]);
const sha256 = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

const files: Record<string, string> = {};
mkdirSync(path.join(root, "src/contract"), { recursive: true });
mkdirSync(path.join(root, "tests/vectors"), { recursive: true });
for (const name of SOURCES) {
  const bytes = show(`src/${name}`);
  writeFileSync(path.join(root, "src/contract", name), bytes);
  files[`src/contract/${name}`] = sha256(bytes);
}
for (const name of VECTORS) {
  const bytes = show(`fixtures/vectors/${name}`);
  writeFileSync(path.join(root, "tests/vectors", name), bytes);
  files[`tests/vectors/${name}`] = sha256(bytes);
}
// The schemas, and one validator compiled ahead of time: Ajv compiles with `new Function`, which a Worker forbids, so
// the relay ships Ajv's standalone code and runs no compiler at all.
// Each schema root with every schema it reaches by `$ref`, vendored once, and one standalone validator per root.
const vendorSchemas = (rootName: string): Record<string, unknown> => {
  const schemas: Record<string, unknown> = {};
  const pending = [rootName];
  while (pending.length) {
    const name = pending.pop() as string;
    if (schemas[name]) continue;
    const bytes = show(`schemas/${name}`);
    schemas[name] = JSON.parse(bytes.toString("utf8"));
    mkdirSync(path.join(root, "src/contract/schemas"), { recursive: true });
    writeFileSync(path.join(root, "src/contract/schemas", name), bytes);
    files[`src/contract/schemas/${name}`] = sha256(bytes);
    for (const match of bytes.toString("utf8").matchAll(/"\$ref":\s*"([a-z0-9-]+\.schema\.json)/g)) pending.push(match[1] as string);
  }
  return schemas;
};
// `byType`: the root is a `oneOf` of one branch per frame `type` (each with its own `type` const), and the module's
// default export is then an object of one validator per type plus `frame`, the whole schema. A relay validates a frame
// against its own type's branch only, failing fast: under `allErrors` a whole-schema `oneOf` runs all sixteen branches
// to the end, about 200 µs for a ping with a 128-code-point id, which a flood of pings turns into the relay's bottleneck.
// With distinct `type` consts a frame can pass no branch but its own type's, so the answer is the same.
const compile = (rootName: string, out: string, options: { byType?: boolean } = {}) => {
  const schemas = vendorSchemas(rootName);
  const ajv = new Ajv2020({ allErrors: !options.byType, strict: true, code: { source: true } });
  addFormats(ajv);
  for (const schema of Object.values(schemas)) ajv.addSchema(schema as object);
  const top = schemas[rootName] as { $id: string; oneOf?: Array<{ properties?: { type?: { const?: unknown } } }> };
  const rootId = top.$id;
  let source: string;
  if (options.byType) {
    const refs: Record<string, string> = { frame: rootId };
    for (const [i, branch] of (top.oneOf ?? []).entries()) {
      const type = branch.properties?.type?.const;
      if (typeof type !== "string" || type in refs) throw new Error(`${rootName}: oneOf/${i} has no distinct type const`);
      refs[type] = `${rootId}#/oneOf/${i}`;
    }
    source = standaloneCode(ajv, refs);
  } else {
    source = standaloneCode(ajv, ajv.getSchema(rootId));
  }
  // Ajv's standalone code `require`s its runtime helpers; esbuild bundles them in, so the module has no import at all
  // and loads the same way under Node and in a Worker.
  const bundled = buildSync({
    stdin: { contents: source, resolveDir: root, loader: "js" },
    bundle: true, format: "esm", platform: "neutral", mainFields: ["main"], write: false, legalComments: "inline"
  }).outputFiles[0]!.text;
  const validator = Buffer.from(`// Generated by scripts/vendor-contract.ts from ${rootName} at ${lock.commit} (Ajv 8.17.1 standalone, bundled); do not edit.\n${bundled}`);
  writeFileSync(path.join(root, "src/contract", out), validator);
  files[`src/contract/${out}`] = sha256(validator);
};
compile(SCHEMA_ROOT, "estate-record.validate.js");
compile(FRAME_SCHEMA, "relay-frame.validate.js", { byType: true });

writeFileSync(path.join(root, "src/contract/VENDORED.json"), `${JSON.stringify({ commit: lock.commit, files }, null, 2)}\n`);
console.log(`vendored ${Object.keys(files).length} files at ${lock.commit}`);
