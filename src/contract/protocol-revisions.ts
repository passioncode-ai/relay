import { type Finding, type JsonObject, isObject } from "./findings.js";

// #region protocol-revisions — docs: docs/specification/versioning.md#protocol-revisions
/**
 * Protocol revisions and the N and N−1 rule (DEC-0067, CON-OE-07; DEC-0009). Every document of the contract names its
 * protocol revision as `<name>/<revision>`; this register lists each name's published revisions, oldest first. A
 * receiver accepts the newest revision it implements (N) and the one before it in this register (N−1), refuses any
 * other before reading further with `schema-unsupported`, and never translates one revision into another.
 */

/**
 * Each contract protocol's published revisions, oldest first. A new revision is appended here by its decision. Most are
 * pinned by a schema `const`; `NAMED_ONLY` lists those a specification names without a schema pin.
 */
export const PROTOCOL_REVISIONS: ReadonlyMap<string, readonly string[]> = new Map([
  ["access-log", ["1"]],
  ["approval", ["1"]],
  ["activity-summary", ["1"]],
  ["agent-directory", ["1"]],
  ["call-record", ["1"]],
  ["channel-agent-standard", ["1"]],
  ["coding-agents", ["1"]],
  ["credential-decision", ["1"]],
  ["credential-request", ["1"]],
  ["credential-revocation", ["1"]],
  ["enroll-token", ["1"]],
  ["entitlement", ["1"]],
  ["entitlement-key-set", ["1"]],
  ["estate-record", ["1"]],
  ["execution-packet", ["1"]],
  ["fabric-actions", ["0.1"]],
  ["fabric-activity", ["0.1"]],
  ["fabric-agent-call", ["1"]],
  ["fabric-connections", ["0.1"]],
  ["fabric-credential-envelope", ["1"]],
  ["fabric-load", ["0.1"]],
  ["fabric-ops-digest", ["0.1"]],
  ["fabric-dashboard", ["0.1"]],
  ["fabric-delegation", ["0.1"]],
  ["fabric-device", ["0.1"]],
  ["fabric-interop", ["0.1", "0.2"]],
  ["fabric-local-channel", ["0.1"]],
  ["fabric-local-runner", ["0.1"]],
  ["fabric-machine-report", ["1"]],
  ["fabric-operator-channel", ["0.1"]],
  ["fabric-package", ["1"]],
  ["fabric-peer-share", ["1"]],
  ["fabric-peer-share-envelope", ["1"]],
  ["fabric-peer-share-report", ["1"]],
  ["fabric-project-comms", ["0.1"]],
  ["fabric-proposal", ["1"]],
  ["fabric-provider", ["0.1"]],
  ["fabric-relay", ["0.1"]],
  ["fabric-secret-envelope", ["1"]],
  ["fabric-service", ["0.1"]],
  ["fabric-settings-backup", ["1"]],
  ["fabric-source", ["1"]],
  ["heartbeat", ["1"]],
  ["learning-note", ["1"]],
  ["machine-report", ["1"]],
  ["mandate", ["1"]],
  ["memory", ["0.1"]],
  ["node-summary", ["1"]],
  ["operator-source", ["1"]],
  ["org-adaptation", ["1"]],
  ["org-adaptation-receipt", ["1"]],
  ["org-authority", ["1"]],
  ["org-authority-draft", ["1"]],
  ["org-key-set", ["1"]],
  ["org-key-set-draft", ["1"]],
  ["org-membership", ["1"]],
  ["org-root-registration", ["1"]],
  ["pairing-message", ["1"]],
  ["peer-share-deletion", ["1"]],
  ["peer-share-frame", ["1"]],
  ["peer-share-revocation", ["1"]],
  ["pipeline", ["0.1"]],
  ["repair-request", ["1"]],
  ["repair-result", ["1"]],
  ["revocation-delta", ["1"]],
  ["session-handoff", ["1"]],
  ["service-load", ["1"]],
  ["share-registration", ["1"]],
  ["share-registration-receipt", ["1"]],
  ["support-quality-daily", ["1"]],
  ["window-lease", ["1"]],
]);

/** Protocols the contract names in a specification's title but no schema pins with `const` (DEC-0067). */
export const NAMED_ONLY: readonly string[] = ["approval/1", "fabric-actions/0.1", "fabric-connections/0.1", "fabric-dashboard/0.1", "fabric-delegation/0.1", "fabric-interop/0.1", "fabric-interop/0.2", "fabric-load/0.1", "fabric-local-channel/0.1", "fabric-ops-digest/0.1", "fabric-peer-share/1", "operator-source/1", "pipeline/0.1"];

/** At most this many revisions of one protocol are accepted at once: N and N−1. */
export const MAX_REVISIONS_PER_PROTOCOL = 2;

const REVISION = /^([a-z][a-z0-9.-]{0,63})\/([0-9]{1,4}(?:\.[0-9]{1,4}){0,2})$/;

export type ParsedRevision = { name: string; revision: string };

/** `<name>/<revision>` split, or undefined for anything else. */
export function parseRevision(value: unknown): ParsedRevision | undefined {
  const match = typeof value === "string" ? REVISION.exec(value) : null;
  return match ? { name: match[1] as string, revision: match[2] as string } : undefined;
}

/** The revisions a receiver implementing `name` up to `newest` accepts: N and, when the register has one, N−1. */
export function acceptedRevisions(name: string, newest?: string): string[] {
  const known = PROTOCOL_REVISIONS.get(name);
  if (!known?.length) return [];
  const top = newest === undefined ? known.length - 1 : known.indexOf(newest);
  if (top < 0) return [];
  return known.slice(Math.max(0, top - 1), top + 1).reverse().map((revision) => `${name}/${revision}`);
}

export type SchemaUnsupported = { error: { code: "schema-unsupported"; message: string; data: { protocol: string; accepted: string[] } } };
/** A receiver that accepts no well-formed revision is misconfigured: the fault is its own, and no refusal is sent. */
export type NoAcceptedRevisions = { fault: "no-accepted-revisions" };

/** The longest list `protocols` and a refusal's `accepted` carry. */
export const MAX_PROTOCOLS = 64;
/** A refusal names at most this many characters (code points) of what it received. */
export const MAX_RECEIVED_CHARS = 80;

/**
 * A receiver's answer to a document naming `received`, given the revisions it accepts: accepted, or the
 * `schema-unsupported` refusal naming what was received and the accepted revisions of that protocol (all of them when
 * the received value names no protocol a receiver can read). `accepted` is read as a `protocols` list — malformed
 * entries and repeats dropped, at most 64 kept — so the refusal is always a valid `schema-unsupported` document; a
 * receiver left with none answers its own fault instead.
 */
export function negotiateRevision(received: unknown, accepted: readonly unknown[]): { ok: true } | SchemaUnsupported | NoAcceptedRevisions {
  const usable = [...new Set((Array.isArray(accepted) ? accepted : []).filter((entry): entry is string => parseRevision(entry) !== undefined))].slice(0, MAX_PROTOCOLS);
  if (!usable.length) return { fault: "no-accepted-revisions" };
  if (typeof received === "string" && usable.includes(received)) return { ok: true };
  const parsed = parseRevision(received);
  const sameName = parsed ? usable.filter((entry) => parseRevision(entry)?.name === parsed.name) : [];
  return {
    error: {
      code: "schema-unsupported",
      message: "this receiver does not read that protocol revision",
      data: { protocol: typeof received === "string" ? Array.from(received).slice(0, MAX_RECEIVED_CHARS).join("") : "", accepted: sameName.length ? sameName : usable },
    },
  };
}

/**
 * FAC-SEM-099 (kind `protocols`, a list or `{protocols}`): 1 to 64 entries, each `<name>/<revision>` once; at most two
 * revisions of one protocol (an unpublished revision is refused and not counted); a contract protocol's revisions
 * are in the register, and two of them are N and N−1, the register's consecutive pair.
 */
export function protocolsFindings(value: unknown): Finding[] {
  const list = Array.isArray(value) ? value : isObject(value) && Array.isArray(value.protocols) ? value.protocols : undefined;
  return listFindings(list, Array.isArray(value) ? "" : "/protocols");
}

/**
 * FAC-SEM-099 on a document that carries `protocols` at `prefix` (the service well-known document, the device check-in,
 * the enrollment response): nothing when the member is absent, the rule's findings when it is present.
 */
export function embeddedProtocolsFindings(list: unknown, prefix: string): Finding[] {
  return list === undefined ? [] : listFindings(Array.isArray(list) ? list : undefined, prefix);
}

function listFindings(list: unknown[] | undefined, prefix: string): Finding[] {
  if (!list) return [{ code: "FAC-SEM-099", instancePath: prefix, message: "protocols is a list of protocol revisions" }];
  if (list.length === 0 || list.length > MAX_PROTOCOLS) return [{ code: "FAC-SEM-099", instancePath: prefix, message: `protocols lists 1 to ${MAX_PROTOCOLS} revisions` }];
  const findings: Finding[] = [];
  const flag = (instancePath: string, message: string): void => {
    findings.push({ code: "FAC-SEM-099", instancePath, message });
  };
  const byName = new Map<string, number[]>();
  const seen = new Set<string>();
  list.forEach((entry: unknown, i: number) => {
    const at = `${prefix}/${i}`;
    const parsed = parseRevision(entry);
    if (!parsed) return flag(at, "a protocol revision is <name>/<revision>, such as fabric-service/0.1");
    if (seen.has(entry as string)) return flag(at, "each protocol revision once");
    seen.add(entry as string);
    const known = PROTOCOL_REVISIONS.get(parsed.name);
    if (known && !known.includes(parsed.revision)) return flag(at, `${parsed.name} has no published revision ${parsed.revision}`);
    const indices = byName.get(parsed.name) ?? [];
    indices.push(known ? known.indexOf(parsed.revision) : -1);
    byName.set(parsed.name, indices);
    if (indices.length > MAX_REVISIONS_PER_PROTOCOL) flag(at, `at most ${MAX_REVISIONS_PER_PROTOCOL} revisions of one protocol: N and N−1`);
    else if (known && indices.length === 2 && Math.abs((indices[0] as number) - (indices[1] as number)) !== 1) flag(at, "two revisions of one protocol are N and N−1, consecutive in the register");
  });
  return findings;
}

export function protocolRules(kind: string, value: JsonObject): Finding[] | undefined {
  if (kind === "protocols") return protocolsFindings(value);
  if (kind === "device-check-in") return embeddedProtocolsFindings(value.protocols, "/protocols");
  return undefined;
}
// #endregion protocol-revisions
