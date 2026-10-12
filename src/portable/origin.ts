// #region portable-origin — docs: docs/protocol/sessions.md#the-two-adapters
// The portable relay's one public origin (RLY-017): the value machines sign into relay-auth/1 and relay-blob/1, the
// same for sessions and for blob routes.
//
// - RELAY_ORIGIN set: parsed with the URL parser; it must be a bare origin (no path beyond "/", no query, fragment or
//   credentials) and https:, or http: on a loopback literal. The answer is `url.origin`: the host lowercased, the
//   default port dropped. Anything else refuses to start, naming the problem (the value is not a secret).
// - RELAY_ORIGIN unset: allowed only when RELAY_HOST is a loopback literal; the origin is http://<host>:<bound port>,
//   computed after listen, and the relay is local-only.
//
// http:// is allowed only on loopback literals — 127.0.0.0/8 and [::1] — never on the name "localhost", which resolves
// where a literal cannot (fabric-agent-contract owner's answer to P9, 2026-10-12).

export type OriginRule =
  | { ok: true; localOnly: boolean; defaulted: boolean; at(boundPort: number): string }
  | { ok: false; reason: string };

/** Thrown by `serve()` for an origin the rules refuse; `main.ts` turns it into `refused-to-start` and exit 2. */
export class OriginRefused extends Error {
  override name = "OriginRefused";
}

/** 127.0.0.0/8 or ::1 (with or without brackets), written as an address: a name never counts. */
export function isLoopbackLiteral(host: string): boolean {
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(bare)) return bare.split(".").every((part) => Number(part) <= 255);
  return bare === "::1" || bare === "0:0:0:0:0:0:0:1";
}

/** Whether an origin only a local machine can reach (an http loopback origin); `/healthz` reports it (A-6). */
export function isLocalOnly(origin: string): boolean {
  return origin.startsWith("http://");
}

const hostPart = (host: string) => (host.includes(":") && !host.startsWith("[") ? `[${host}]` : host);

export function relayOrigin(raw: string | undefined, host: string): OriginRule {
  if (raw === undefined || raw === "") {
    if (!isLoopbackLiteral(host)) {
      return { ok: false, reason: `RELAY_ORIGIN is not set and RELAY_HOST ${host} is not a loopback literal (127.0.0.0/8 or ::1): set RELAY_ORIGIN to the public https:// origin` };
    }
    return { ok: true, localOnly: true, defaulted: true, at: (boundPort) => `http://${hostPart(host)}:${boundPort}` };
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: `RELAY_ORIGIN ${JSON.stringify(raw)} is not a URL` };
  }
  if (url.username || url.password) return { ok: false, reason: "RELAY_ORIGIN carries credentials; it must be a bare origin" };
  if (url.protocol === "http:") {
    if (!isLoopbackLiteral(url.hostname)) {
      return { ok: false, reason: `RELAY_ORIGIN ${url.origin} is http:// but not on a loopback literal (127.0.0.0/8 or [::1]); use https://` };
    }
  } else if (url.protocol !== "https:") {
    return { ok: false, reason: `RELAY_ORIGIN must be https:// (it is ${url.protocol})` };
  }
  if (url.pathname !== "/") return { ok: false, reason: `RELAY_ORIGIN has a path (${url.pathname}); it must be a bare origin` };
  if (url.search) return { ok: false, reason: "RELAY_ORIGIN has a query; it must be a bare origin" };
  if (url.hash) return { ok: false, reason: "RELAY_ORIGIN has a fragment; it must be a bare origin" };
  const origin = url.origin;
  return { ok: true, localOnly: isLocalOnly(origin), defaulted: false, at: () => origin };
}
// #endregion portable-origin
