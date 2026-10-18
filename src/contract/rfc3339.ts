// #region rfc3339 — docs: docs/specification/estate-record.md#the-verifier
/**
 * How far ahead of the verifier's clock a signed time may be before it is `not-yet-valid` (60 s): a relay's `iat`, a
 * message body's and an envelope's `iat`, and an estate record's `issuedAt` (DEC-0047, DEC-0066).
 */
export const CLOCK_SKEW_SECONDS = 60;

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

/**
 * An RFC 3339 date-time as milliseconds since the epoch, or NaN: `T` (or `t`), an offset (`Z`, `z` or `±hh:mm`) and a day
 * that exists in its month are required. This is stricter than JSON Schema's `date-time`, which also admits a space
 * separator and a leap second `:60`; both are refused (estate-record.md ER-10). `Date.parse` alone reads 2026-02-30 as
 * 2 March and a missing offset as local time, so a rule that compares times reads them through this function, and refuses
 * NaN before it compares: every comparison with NaN is false and would let anything through.
 */
export function strictTime(value: unknown): number {
  const match = typeof value === "string" ? RFC3339.exec(value) : null;
  if (!match) return Number.NaN;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  if (date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day || hour > 23 || minute > 59 || second > 59) return Number.NaN;
  return Date.parse(value as string);
}
// #endregion rfc3339
