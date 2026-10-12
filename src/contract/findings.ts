/** A semantic-rule finding. `severity: "accepted"` marks a rule that classifies rather than rejects. */
export interface Finding {
  code: string;
  instancePath: string;
  message: string;
  severity?: "rejected" | "accepted";
}

export type JsonObject = Record<string, unknown>;
export const isObject = (value: unknown): value is JsonObject => typeof value === "object" && value !== null && !Array.isArray(value);

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
