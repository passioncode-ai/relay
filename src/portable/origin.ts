// #region portable-origin — docs: docs/protocol/sessions.md#the-two-adapters
// The portable relay's one public origin (RLY-017): the value machines sign into relay-auth/1 and relay-blob/1, the
// same for sessions and for blob routes.
//
// - RELAY_ORIGIN set: parsed with the URL parser; it must be a bare origin (no path beyond "/", no query, fragment or
//   credentials) and https:, or http: on a loopback literal served from a loopback-literal RELAY_HOST. The answer is `url.origin`: the host lowercased, the
//   default port dropped. Its host must mean what it says: an IPv4 address as four decimal parts (127.010.0.1 is
//   127.8.0.1 to a URL), no trailing dot, no empty label (.relay.test), and no port 0. Anything else refuses to start, naming the problem (the value
//   is not a secret).
// - RELAY_ORIGIN unset: allowed only when RELAY_HOST is a loopback literal; the origin is the URL parser's origin of
//   http://<host>:<bound port>, computed after listen, and the relay is local-only. It is canonical, never RELAY_HOST
//   verbatim: 0:0:0:0:0:0:0:1 gives http://[::1]:<port>, 127.000.000.001 gives http://127.0.0.1:<port>. A spelling the
//   URL parser reads as another address (127.010.0.1, whose parts it takes as octal) or cannot read is refused.
// - RELAY_HOST is a bare address or name the URL parser can carry, checked whether RELAY_ORIGIN is set or not: a
//   zone id (fe80::1%lo0), a space, a port or a path, or an IPv4 address not written as four decimal parts, refuses to
//   start. A bracketed one ([::1]) is refused, since brackets belong in a URL and
//   `listen` cannot take them.
//
// http:// is allowed only on loopback literals — 127.0.0.0/8 and [::1] — never on the name "localhost", which resolves
// where a literal cannot (fabric-agent-contract owner's answer to P9, 2026-10-12).

import { isRelayOrigin } from "../contract/relay.ts";

export type OriginRule =
  | { ok: true; localOnly: boolean; defaulted: boolean; at(boundPort: number): string }
  | { ok: false; reason: string };

/** Thrown by `serve()` for an origin the rules refuse; `main.ts` turns it into `refused-to-start` and exit 2. */
export class OriginRefused extends Error {
  override name = "OriginRefused";
}

/**
 * 127.0.0.0/8 as four decimal parts, or any spelling of ::1 (with or without brackets), written as an address: a name
 * never counts.
 */
export function isLoopbackLiteral(host: string): boolean {
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(bare)) return bare.split(".").every((part) => Number(part) <= 255);
  if (!bare.includes(":")) return false;
  try {
    return new URL(`http://[${bare}]`).hostname === "[::1]";
  } catch {
    return false;
  }
}

const IPV4 = /^\d+\.\d+\.\d+\.\d+$/;

/**
 * Whether `written`, a host as the operator wrote it, means the address the URL parser read from it (`parsed`). An IPv4
 * address must be written as four decimal parts: the URL parser reads a part with a leading zero as octal, a 0x part as
 * hex, and fewer parts as a shorthand, so `127.010.0.1` would silently become 127.8.0.1.
 */
function meansWhatItSays(written: string, parsed: string): boolean {
  if (!IPV4.test(parsed)) return true;
  return IPV4.test(written) && written.split(".").map(Number).join(".") === parsed;
}

/**
 * The URL parser's host for a bare RELAY_HOST (IPv6 in brackets, IPv4 in plain decimal), or undefined when it cannot
 * parse it (a zone id, a space, a port, a user or a path in it) or reads an address other than the one written.
 */
function canonicalHost(host: string): string | undefined {
  if (host === "" || /[/?#@\\\s]/.test(host)) return undefined;
  let parsed: string;
  try {
    parsed = new URL(`http://${hostPart(host)}`).hostname;
  } catch {
    return undefined;
  }
  return meansWhatItSays(host, parsed) ? parsed : undefined;
}

/** The host part of an origin as it was written (before the URL parser normalised it), lowercased. */
function writtenHost(raw: string): string {
  let authority = /^[a-z][a-z0-9+.-]*:[/\\]*([^/?#\\]*)/i.exec(raw.trim())?.[1] ?? "";
  authority = authority.slice(authority.lastIndexOf("@") + 1);
  if (authority.startsWith("[")) return authority.slice(0, authority.indexOf("]") + 1).toLowerCase();
  const colon = authority.lastIndexOf(":");
  return (colon >= 0 ? authority.slice(0, colon) : authority).toLowerCase();
}

/** Whether an origin only a local machine can reach (an http loopback origin); `/healthz` reports it (A-6). */
export function isLocalOnly(origin: string): boolean {
  return origin.startsWith("http://");
}

const hostPart = (host: string) => (host.includes(":") && !host.startsWith("[") ? `[${host}]` : host);

export function relayOrigin(raw: string | undefined, host: string): OriginRule {
  if (host.startsWith("[") || host.endsWith("]")) {
    return { ok: false, reason: `RELAY_HOST ${host} is bracketed: give the bare address (${host.replace(/^\[|\]$/g, "")}); brackets belong only in a URL` };
  }
  // Every RELAY_HOST, set origin or not: one the URL parser cannot carry (a zone id such as fe80::1%lo0, a space) or
  // reads as another address refuses to start here, rather than listening and then failing on each request.
  if (canonicalHost(host) === undefined) {
    return { ok: false, reason: `RELAY_HOST ${JSON.stringify(host)} is not an address or name a URL can carry (no zone id, space, port or path; IPv4 as four decimal parts)` };
  }
  if (raw === undefined || raw === "") {
    if (!isLoopbackLiteral(host)) {
      return { ok: false, reason: `RELAY_ORIGIN is not set and RELAY_HOST ${host} is not a loopback literal (127.0.0.0/8 or ::1): set RELAY_ORIGIN to the public https:// origin` };
    }
    const canonical = canonicalHost(host);
    if (canonical === undefined || !isLoopbackLiteral(canonical)) {
      return { ok: false, reason: `RELAY_ORIGIN is not set and RELAY_HOST ${host} does not read as one loopback address (a part with a leading zero is octal in a URL): write it in plain decimal, such as 127.0.0.1` };
    }
    return { ok: true, localOnly: true, defaulted: true, at: (boundPort) => new URL(`http://${canonical}:${boundPort}`).origin };
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: `RELAY_ORIGIN ${JSON.stringify(raw)} is not a URL` };
  }
  if (url.username || url.password) return { ok: false, reason: "RELAY_ORIGIN carries credentials; it must be a bare origin" };
  const written = writtenHost(raw);
  if (!meansWhatItSays(written, url.hostname)) {
    return { ok: false, reason: `RELAY_ORIGIN host ${written} reads as ${url.hostname} in a URL; write the address as four decimal parts` };
  }
  if (url.hostname.endsWith(".")) return { ok: false, reason: `RELAY_ORIGIN host ${url.hostname} has a trailing dot; write the name without it` };
  if (!url.hostname.startsWith("[") && url.hostname.split(".").includes("")) {
    return { ok: false, reason: `RELAY_ORIGIN host ${url.hostname} has an empty label; every part between dots must be a name` };
  }
  if (url.port === "0") return { ok: false, reason: "RELAY_ORIGIN names port 0, which no machine can reach; name the port it is served on" };
  if (url.protocol === "http:") {
    if (!isLoopbackLiteral(url.hostname)) {
      return { ok: false, reason: `RELAY_ORIGIN ${url.origin} is http:// but not on a loopback literal (127.0.0.0/8 or [::1]); use https://` };
    }
    if (!isLoopbackLiteral(host)) {
      return { ok: false, reason: `RELAY_ORIGIN ${url.origin} is http:// but RELAY_HOST ${host} is not a loopback literal: other machines could reach a local-only origin; use https://` };
    }
  } else if (url.protocol !== "https:") {
    return { ok: false, reason: `RELAY_ORIGIN must be https:// (it is ${url.protocol})` };
  }
  if (url.pathname !== "/") return { ok: false, reason: `RELAY_ORIGIN has a path (${url.pathname}); it must be a bare origin` };
  // An empty query or fragment ("https://relay.test?") leaves url.search and url.hash empty; the raw value still has it.
  if (url.search || raw.includes("?")) return { ok: false, reason: "RELAY_ORIGIN has a query; it must be a bare origin" };
  if (url.hash || raw.includes("#")) return { ok: false, reason: "RELAY_ORIGIN has a fragment; it must be a bare origin" };
  const origin = url.origin;
  // Last, the contract's own rule for what `hello.relay` may be (DEC-0066, RELAY_ORIGIN_PATTERN): an origin that passes
  // the checks above and that the contract would still refuse (a last label that is a number, a name over 253
  // characters, an IPv6 address with leading zeros) refuses to start rather than greet with a relay no node accepts.
  if (!isRelayOrigin(origin)) return { ok: false, reason: `RELAY_ORIGIN ${origin} is not an origin fabric-relay/0.1 accepts in hello.relay (DEC-0066)` };
  return { ok: true, localOnly: isLocalOnly(origin), defaulted: false, at: () => origin };
}
// #endregion portable-origin
