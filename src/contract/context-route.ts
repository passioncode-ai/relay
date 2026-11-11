import { isObject } from "./findings.js";

// #region context-route — docs: docs/specification/contexts.md#routing
/**
 * Contexts (DEC-0082, the RM-28 pilot slice of N20): a context is `personal` or `org:<orgId>`, where `orgId` is the
 * organization server's opaque id of the organization. No event carries its session's context and no check-in carries
 * a context, except a node summary's own `org:<org.id>` (DEC-0102): an organization server knows the organization from the device certificate (DEC-0031's attribution), and a
 * field would add nothing while it could leak `personal` or another organization's id (unlinkability). Only a
 * `grant.usage` and a share registration carry their grant's own `org:<orgId>`, which the receiver checks against the
 * certificate (DEC-0086). Instead a collector routes:
 * `routeTarget` answers where an event of a session in a given context may be sent, `routeGrantUsage` where a
 * `grant.usage` goes, and the shared vectors
 * `fixtures/vectors/context-route.json` are what a port runs.
 */

/** The personal context: the person's own work, which never goes to an organization server. */
export const PERSONAL_CONTEXT = "personal";
/** The prefix of an organization's context. */
export const ORG_CONTEXT_PREFIX = "org:";
/**
 * An organization's id inside a context: a letter or digit, then up to 127 of `[A-Za-z0-9_-]` — the ids an enrollment's
 * `org.id` (an opaque id) can hold that a context names too (informative: the first organization server issues
 * `org_<base32>`).
 * No `m` flag, so `$` is the end of the text and `org:abc\n` is not a context.
 */
const ORG_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

export type Context = { kind: "personal" } | { kind: "org"; org: string };

/**
 * The context `value` names, or `undefined` when it names none: `personal` exactly, or `org:` and an id of 1–128 of
 * `[A-Za-z0-9_-]` starting with a letter or digit — the same set as `common.schema.json#/$defs/contextId`. Compared as written: `Personal`, `ORG:x`, a
 * surrounding space or a trailing newline name no context. Never throws.
 */
export function parseContext(value: unknown): Context | undefined {
  if (typeof value !== "string") return undefined;
  if (value === PERSONAL_CONTEXT) return { kind: "personal" };
  if (!value.startsWith(ORG_CONTEXT_PREFIX)) return undefined;
  const org = value.slice(ORG_CONTEXT_PREFIX.length);
  return ORG_ID.test(org) ? { kind: "org", org } : undefined;
}

/** One of the device's enrollments (DEC-0031): the `org.id` it enrolled with, which its certificate binds. */
export interface Enrollment { org: string }

/**
 * Where a collector may send an event of a session in a context (a check-in goes to its own enrollment's server, never by
 * a session):
 * - `{route: "enrollment", org, index}`: to the organization server of the one enrollment whose `org` is exactly the
 *   context's id (`index` in the list given);
 * - `{route: "none", reason}`: nowhere. `personal`: the session is personal, which never leaves for an organization
 *   server. `not-a-context`: the session's context is not one (the collector fails closed and sends nothing).
 *   `not-enrolled`: the device holds no enrollment in that organization. `ambiguous`: it holds two, which a device never
 *   should (a re-enrollment replaces the earlier one), so it sends to neither. `no-context`: a `grant.usage` event of a
 *   grant that states no context (`routeGrantUsage`).
 */
export type RouteAnswer =
  | { route: "enrollment"; org: string; index: number }
  | { route: "none"; reason: "personal" | "not-a-context" | "not-enrolled" | "ambiguous" | "no-context" };

/** An object's own member, or `undefined`: an inherited one (`constructor`, a `__proto__` chain) is never read. */
const own = (value: unknown, key: string): unknown => (isObject(value) && Object.hasOwn(value, key) ? value[key] : undefined);

/**
 * The routing function (DEC-0082 item 5). Total: malformed input answers `none`, never throws. Ids compare as written —
 * never case-folded, never by prefix — and an enrollment that is not an object with an own string `org` is skipped.
 */
export function routeTarget(sessionContext: unknown, enrollments: unknown): RouteAnswer {
  const context = parseContext(sessionContext);
  if (context === undefined) return { route: "none", reason: "not-a-context" };
  if (context.kind === "personal") return { route: "none", reason: "personal" };
  const list: unknown[] = Array.isArray(enrollments) ? enrollments : [];
  const matches = list.flatMap((entry, index) => (own(entry, "org") === context.org ? [index] : []));
  if (matches.length === 0) return { route: "none", reason: "not-enrolled" };
  if (matches.length > 1) return { route: "none", reason: "ambiguous" };
  return { route: "enrollment", org: context.org, index: matches[0] as number };
}

/**
 * Where a collector may send a `grant.usage` event (DEC-0082): only to the organization server of the grant's own
 * `context`, the grant's member as the device holds the grant. A grant that states no context (`undefined`) answers
 * `{route: "none", reason: "no-context"}`, and a personal one `personal`: neither produces a `grant.usage` toward any
 * organization. Otherwise exactly as `routeTarget`, with the grant's context in place of the session's.
 */
export function routeGrantUsage(grantContext: unknown, enrollments: unknown): RouteAnswer {
  if (grantContext === undefined) return { route: "none", reason: "no-context" };
  return routeTarget(grantContext, enrollments);
}
// #endregion context-route
