import { type Finding, type JsonObject, isObject } from "./findings.js";
import { PERSONAL_CONTEXT } from "./context-route.js";
import { shareGrantIdFindings } from "./share-registration.js";

// #region context-rules — docs: docs/specification/contexts.md#semantic-rules
/**
 * FAC-SEM-110 (DEC-0082): a grant's `context` is the context in which its principal uses it. A grant to a principal
 * outside the estate (`principalKind: external`, a share grant) is used in that principal's organization, so it is never
 * `personal`. An absent `context` is allowed and means not stated. Checked on a grant (kind `grant`) and on each of an
 * estate record's `shareGrants[]` (kind `estate-record`, through `src/estate-record-rules.ts`).
 */
export function grantContextFindings(grant: unknown, at: string): Finding[] {
  if (!isObject(grant) || grant.principalKind !== "external" || grant.context !== PERSONAL_CONTEXT) return [];
  return [{ code: "FAC-SEM-110", instancePath: `${at}/context`, message: "a grant to a principal outside the estate is used in that principal's organization, never in the personal context: name the organization's org:<orgId>, or leave context out" }];
}

export function contextRules(kind: string, value: JsonObject): Finding[] | undefined {
  // A grant into an organization is also named by a share grant id (DEC-0086, src/share-registration.ts).
  if (kind === "grant") return [...grantContextFindings(value, ""), ...shareGrantIdFindings(value, "")];
  return undefined;
}
// #endregion context-rules
