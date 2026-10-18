// Types for the bundled validators scripts/vendor-contract.ts generates (Ajv standalone, esbuild-bundled) from the
// contract's relay-frame schema, with the revocation-delta and heartbeat schemas it references: `frame` is the whole
// schema; every other member validates one frame `type` against that type's branch, failing fast.
type Validate = ((value: unknown) => boolean) & { errors?: unknown[] | null };
declare const validators: { frame: Validate } & Record<string, Validate | undefined>;
export default validators;
