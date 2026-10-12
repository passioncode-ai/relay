import { isObject } from "./findings.js";

// #region canonical-forms — docs: docs/specification/conformance.md#canonical-forms
/**
 * The contract's two canonical JSON forms (DEC-0043). Every signed or hashed document names one of them, and a
 * new document picks one of these two, never a third. They give different bytes for the same value — separators,
 * key order above U+FFFF, fractions — so a signer and a verifier that pick different ones disagree on every
 * signature. The vectors both are tested against are `fixtures/vectors/canonical.json`.
 */

/** Unicode code-point order, which is how the settings form sorts keys. JavaScript's default
 *  string order compares UTF-16 code units and differs above U+FFFF. */
function byCodePoint(a: string, b: string): number {
  const x = Array.from(a), y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i += 1) {
    // Each element of `Array.from(string)` is one whole code point, so `codePointAt(0)` is defined.
    const d = x[i]!.codePointAt(0)! - y[i]!.codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

/**
 * The settings form (DEC-0025, `docs/specification/service.md#settings-backup`): object keys sorted by Unicode
 * code point at every level, `", "` between members and elements, `": "` after a key, strings escaped as
 * `JSON.stringify` escapes them (`"`, `\` and the control characters; every other character written as itself),
 * integers in decimal. It equals Python's `json.dumps(value, sort_keys=True, ensure_ascii=False)`.
 * Refuses a non-finite number, a fraction, an integer outside ±(2^53 − 1), `undefined`, a function, a bigint, and a
 * lone surrogate in any string or key (CT-25, DEC-0052): `JSON.stringify` would write it as `\udxxx`, where Python
 * writes the raw code unit and its UTF-8 encoding fails, so the two would never agree on the bytes.
 * It takes parsed JSON and does not check prototypes: a date or a map reads as `{}`.
 * Signs and hashes settings backups, device policies and key sets, activity `eventId` and `sourceKey`.
 */
/** A string or key of the settings form; with the `u` flag `\p{Surrogate}` matches only a lone surrogate, never a pair. */
function settingsString(text: string): string {
  if (/\p{Surrogate}/u.test(text)) throw new TypeError("a lone surrogate has no canonical form: Python cannot encode it as UTF-8");
  return JSON.stringify(text);
}

export function settingsCanonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError(`${value} has no canonical form: a settings backup stores a fraction as a string`);
    return String(value);
  }
  if (typeof value === "string") return settingsString(value);
  if (Array.isArray(value)) return `[${value.map(settingsCanonicalJson).join(", ")}]`;
  if (isObject(value)) {
    const keys = Object.keys(value).sort(byCodePoint);
    return `{${keys.map((key) => `${settingsString(key)}: ${settingsCanonicalJson(value[key])}`).join(", ")}}`;
  }
  throw new TypeError(`${typeof value} is not a JSON value`);
}

/**
 * RFC 8785, the JSON Canonicalization Scheme (DEC-0039): object members sorted by UTF-16 code units at every
 * level, no whitespace, numbers in ECMAScript form (`1e+30`, `0.002`, `-0` as `0`), strings escaped as
 * `JSON.stringify` escapes them. Refuses what has no canonical form: a non-finite number, a lone surrogate, a
 * value JSON cannot carry — a date, a map, a class instance or an `undefined` member, which would otherwise read
 * as `{}` and let two values share a digest.
 * Digests the approval's action (`actionDigest`) and, restricted to integers, the board's idempotency digest
 * (`commsDigest`, DEC-0022).
 */
export function rfc8785(value: unknown): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("a non-finite number has no canonical form");
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    if (/\p{Surrogate}/u.test(value)) throw new TypeError("a lone surrogate has no canonical form");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${Array.from(value, (item) => rfc8785(item)).join(",")}]`;
  if (isObject(value)) {
    // JSON values only: a Date, a Map or a class instance would otherwise read as {} and two different
    // actions would share a digest.
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("only plain JSON objects have a canonical form");
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${rfc8785(key)}:${rfc8785(value[key])}`).join(",")}}`;
  }
  throw new TypeError(`${typeof value} has no canonical form`);
}
// #endregion canonical-forms
