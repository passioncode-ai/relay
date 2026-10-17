// The contract's relay-frame schema compiled at test time, with every vendored schema it references, as an independent
// check of what the relay sends: the relay itself validates with the ahead-of-time copy (src/contract/relay-frame.validate.js).
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

const require = createRequire(import.meta.url);
const SCHEMAS = path.resolve(import.meta.dirname, "../src/contract/schemas");
const ajv = new (require("ajv/dist/2020").default)({ allErrors: true, strict: false });
require("ajv-formats").default(ajv);
for (const file of readdirSync(SCHEMAS).filter((name) => name.endsWith(".schema.json")).sort()) {
  if (file !== "relay-frame.schema.json") ajv.addSchema(JSON.parse(readFileSync(path.join(SCHEMAS, file), "utf8")));
}

/** Whether a frame is valid under the contract's relay-frame schema; `.errors` names why not. */
export const frameValid: ((value: unknown) => boolean) & { errors?: unknown } =
  ajv.compile(JSON.parse(readFileSync(path.join(SCHEMAS, "relay-frame.schema.json"), "utf8")));
