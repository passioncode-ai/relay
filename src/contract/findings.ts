/**
 * A semantic-rule finding. `severity: "accepted"` marks a rule that classifies rather than rejects. `help` links the
 * row that defines the rule (`docs/specification/<page>.md#fac-sem-nnn`, REQ-05); rules leave it out and the checker
 * adds it with `withHelp`.
 */
export interface Finding {
  code: string;
  instancePath: string;
  message: string;
  severity?: "rejected" | "accepted";
  help?: string;
}

/** The findings with each one's `help` link from `help` (code to link, as `ruleHelp` builds it); a code it lacks keeps none. */
export const withHelp = (findings: readonly Finding[], help: ReadonlyMap<string, string>): Finding[] =>
  findings.map((finding) => {
    const link = help.get(finding.code);
    return link === undefined ? { ...finding } : { ...finding, help: link };
  });

export type JsonObject = Record<string, unknown>;
export const isObject = (value: unknown): value is JsonObject => typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * The object items of an array with their index in the array as written, so an instancePath names the item it flags
 * even when a non-object precedes it (DEC-0082; shared by every rule module since DEC-0083).
 */
export const indexed = (value: unknown): Array<[JsonObject, number]> =>
  Array.isArray(value) ? value.flatMap((item, index): Array<[JsonObject, number]> => (isObject(item) ? [[item, index]] : [])) : [];

/**
 * A value as text for a finding's message or a key, as `String()` writes it, without its throw on an object whose
 * `toString` is not a function (`{"toString": 1}`, valid JSON): such a value reads as its JSON.
 */
export function show(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return String(value);
  } catch {
    return JSON.stringify(value) ?? typeof value;
  }
}

/** A number as `Number()` reads it, without its throw on an object such as `{"toString": 1}`, which reads as no number. */
export function toNumber(value: unknown): number {
  try {
    return Number(value);
  } catch {
    return Number.NaN;
  }
}

/** Structural equality of JSON values; object key order does not matter. */
export function jsonEqual(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((item, index) => jsonEqual(item, b[index]));
  }
  if (isObject(a) || isObject(b)) {
    if (!isObject(a) || !isObject(b)) return false;
    const keys = Object.keys(a);
    return keys.length === Object.keys(b).length && keys.every((key) => Object.hasOwn(b, key) && jsonEqual(a[key], b[key]));
  }
  return a === b;
}
