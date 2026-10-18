// #region identifiers — docs: docs/specification/identifiers.md
/**
 * Identifier equality (DEC-0076): two identifiers are the same when their normal forms are equal.
 *
 * The normal form of a URI is RFC 3986 §6.2.2 syntax-based normalization — the scheme and the host lower-cased and
 * percent-encoding hex upper-cased (§6.2.2.1), percent-encoded unreserved characters decoded (§6.2.2.2), dot segments
 * removed from a hierarchical path (§6.2.2.3), and only the leading ones from a rootless path — and nothing scheme-based (§6.2.3: no default port removed, no empty path
 * made "/"). A `urn:` URI follows RFC 8141 §3.1 instead: the scheme and the NID lower-cased, percent-encoding hex
 * upper-cased, nothing decoded, the NSS's case kept, and the r-, q- and f-components ignored. A string that is not a URI
 * by RFC 3986's `URI` production is its own normal form. Nothing here throws, and nothing is keyed by input in a plain
 * object. This module holds no rule code (G-13): the rules that compare identifiers call it.
 */

const UNRESERVED = "A-Za-z0-9\\-._~";
const SUB_DELIMS = "!$&'()*+,;=";
const PCT = "%[0-9A-Fa-f]{2}";
/** `*( <chars> / pct-encoded )` — each a single character class beside one fixed triplet, so the match is linear. */
const run = (chars: string) => new RegExp(`^(?:[${chars}]|${PCT})*$`);
const USERINFO = run(`${UNRESERVED}${SUB_DELIMS}:`);
const REG_NAME = run(`${UNRESERVED}${SUB_DELIMS}`);
const PATH = run(`${UNRESERVED}${SUB_DELIMS}:@/`);
const QUERY = run(`${UNRESERVED}${SUB_DELIMS}:@/?`);
const PORT = /^[0-9]*$/;
const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*$/;

// RFC 3986 §3.2.2: IP-literal = "[" ( IPv6address / IPvFuture ) "]".
const H16 = "[0-9A-Fa-f]{1,4}";
const DEC_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
const IPV4 = `${DEC_OCTET}(?:\\.${DEC_OCTET}){3}`;
const LS32 = `(?:${H16}:${H16}|${IPV4})`;
const IPV6 = [
  `(?:${H16}:){6}${LS32}`,
  `::(?:${H16}:){5}${LS32}`,
  `(?:${H16})?::(?:${H16}:){4}${LS32}`,
  `(?:(?:${H16}:){0,1}${H16})?::(?:${H16}:){3}${LS32}`,
  `(?:(?:${H16}:){0,2}${H16})?::(?:${H16}:){2}${LS32}`,
  `(?:(?:${H16}:){0,3}${H16})?::${H16}:${LS32}`,
  `(?:(?:${H16}:){0,4}${H16})?::${LS32}`,
  `(?:(?:${H16}:){0,5}${H16})?::${H16}`,
  `(?:(?:${H16}:){0,6}${H16})?::`,
].join("|");
const IP_LITERAL = new RegExp(`^\\[(?:${IPV6}|[Vv][0-9A-Fa-f]+\\.[${UNRESERVED}${SUB_DELIMS}:]+)\\]$`);

// RFC 8141 §2: NID = (alphanum) 0*30(ldh) (alphanum), then ":" and a non-empty NSS.
const URN_NAME = /^([A-Za-z0-9][A-Za-z0-9-]{0,30}[A-Za-z0-9]):(.+)$/s;

/** Percent-encoding hex upper-cased (§6.2.2.1), and unreserved characters decoded unless `keepEncoded` (§6.2.2.2). */
function percent(text: string, keepEncoded = false): string {
  return text.replace(/%([0-9A-Fa-f]{2})/g, (_, hex: string) => {
    const char = String.fromCharCode(Number.parseInt(hex, 16));
    return !keepEncoded && /^[A-Za-z0-9\-._~]$/.test(char) ? char : `%${hex.toUpperCase()}`;
  });
}

/**
 * A rootless path (`agent:./x`) loses its leading "./" and "../" segments — §5.2.4's step A — while what is left stays
 * rootless: not empty and not beginning with "/". Dot segments further in are kept, because removing them by §5.2.4 can
 * turn a rootless path into an absolute one (`a/../b` → `/b`). That narrowing is the contract's own, under RFC 3986
 * §6.1's aim of no false positives (DEC-0076).
 */
function stripLeadingDots(path: string): string {
  let start = 0;
  while (path.startsWith("./", start) || path.startsWith("../", start)) start += path.startsWith("./", start) ? 2 : 3;
  const rest = path.slice(start);
  return rest === "" || rest.startsWith("/") ? path : rest;
}

/**
 * RFC 3986 §5.2.4 remove_dot_segments, over a path whose `.` and `..` are already decoded. Its input buffer is read
 * segment by segment: the path split on "/" gives the same steps without copying the rest of the input at each one.
 */
function removeDotSegments(path: string): string {
  const absolute = path.startsWith("/");
  const segments = (absolute ? path.slice(1) : path).split("/");
  const output: string[] = [];
  segments.forEach((segment, index) => {
    const last = index === segments.length - 1;
    if (segment === "." || segment === "..") {
      if (segment === ".." && output.length > 0) output.pop();
      // A dot segment that ends the path leaves the path ending in "/" (§5.2.4 steps B and C on "/." and "/..").
      if (last) output.push("");
      return;
    }
    output.push(segment);
  });
  return (absolute ? "/" : "") + output.join("/");
}

type Parts = { scheme: string; authority: string | undefined; path: string; query: string | undefined; fragment: string | undefined };
type Authority = { userinfo: string | undefined; host: string; port: string | undefined };

/** RFC 3986 Appendix B's split, then each component checked against its §3 production; undefined when one fails. */
function parse(text: string): Parts | undefined {
  const match = /^([^:/?#]+):(?:\/\/([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/s.exec(text);
  if (!match) return undefined;
  const [, scheme, authority, path, query, fragment] = match as unknown as [string, string, string | undefined, string, string | undefined, string | undefined];
  if (!SCHEME.test(scheme) || !PATH.test(path)) return undefined;
  if (query !== undefined && !QUERY.test(query)) return undefined;
  if (fragment !== undefined && !QUERY.test(fragment)) return undefined;
  if (authority !== undefined && !authorityParts(authority)) return undefined;
  // An empty path with no authority (`x:`, RFC 3986's path-empty) is left as it is: the schema's `format: uri` refuses
  // it, so no admitted value has it. (A path never begins with "//" here: Appendix B's split reads that as an authority.)
  if (authority === undefined && path === "") return undefined;
  return { scheme, authority, path, query, fragment };
}

function authorityParts(authority: string): Authority | undefined {
  const at = authority.lastIndexOf("@");
  const userinfo = at === -1 ? undefined : authority.slice(0, at);
  const hostPort = at === -1 ? authority : authority.slice(at + 1);
  const bracket = hostPort.startsWith("[") ? hostPort.indexOf("]") : -1;
  const colon = hostPort.indexOf(":", bracket === -1 ? 0 : bracket);
  const host = colon === -1 ? hostPort : hostPort.slice(0, colon);
  const port = colon === -1 ? undefined : hostPort.slice(colon + 1);
  if (userinfo !== undefined && !USERINFO.test(userinfo)) return undefined;
  if (port !== undefined && !PORT.test(port)) return undefined;
  if (host.startsWith("[") ? !IP_LITERAL.test(host) : !REG_NAME.test(host)) return undefined;
  return { userinfo, host, port };
}

/** RFC 8141 §3.1: `urn` and the NID lower-cased, hex upper-cased, nothing decoded; r-, q- and f-components ignored. */
function urnForm(parts: Parts): string {
  const name = URN_NAME.exec(parts.path);
  const path = name ? `${(name[1] as string).toLowerCase()}:${percent(name[2] as string, true)}` : percent(parts.path, true);
  // A "?" not followed by "+" or "=" is no URN component (RFC 8141 §2): it is kept, never dropped unread.
  const query = parts.query !== undefined && !/^[+=]/.test(parts.query) ? `?${percent(parts.query, true)}` : "";
  const authority = parts.authority !== undefined ? `//${percent(parts.authority, true)}` : "";
  return `urn:${authority}${path}${query}`;
}

function genericForm(parts: Parts): string {
  let authority = "";
  if (parts.authority !== undefined) {
    const { userinfo, host, port } = authorityParts(parts.authority) as Authority;
    // The host is case-insensitive (§3.2.2); its remaining percent triplets keep upper-case hex.
    const lowered = percent(host).toLowerCase().replace(/%[0-9a-f]{2}/g, (triplet) => triplet.toUpperCase());
    authority = `//${userinfo !== undefined ? `${percent(userinfo)}@` : ""}${lowered}${port !== undefined ? `:${port}` : ""}`;
  }
  const decoded = percent(parts.path);
  const hierarchical = parts.authority !== undefined || decoded.startsWith("/");
  let path = hierarchical ? removeDotSegments(decoded) : stripLeadingDots(decoded);
  // A path left starting with "//" and no authority would read as one: keep the decoded path instead.
  if (parts.authority === undefined && path.startsWith("//")) path = decoded;
  const query = parts.query !== undefined ? `?${percent(parts.query)}` : "";
  const fragment = parts.fragment !== undefined ? `#${percent(parts.fragment)}` : "";
  return `${parts.scheme.toLowerCase()}:${authority}${path}${query}${fragment}`;
}

/**
 * The normal form of an identifier: a URI's syntax-normalized form (RFC 3986 §6.2.2; RFC 8141 §3.1 for `urn:`), any
 * other string as it is, and undefined for a value that is not a string.
 */
export function normalIdentifier(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const parts = parse(value);
  if (!parts) return value;
  return parts.scheme.toLowerCase() === "urn" ? urnForm(parts) : genericForm(parts);
}

/**
 * Two identifiers are the same when their normal forms are equal (DEC-0076). A value that is not a string is no
 * identifier and is compared as it is (`===`), so a rule reads a schema-invalid member exactly as it did before.
 */
export function sameIdentifier(a: unknown, b: unknown): boolean {
  if (typeof a !== "string" || typeof b !== "string") return a === b;
  return normalIdentifier(a) === normalIdentifier(b);
}
// #endregion identifiers
