// #region secret-shape — docs: docs/specification/profiles.md#no-secret-in-a-command-line
/**
 * The one credential detector of this kit (DEC-0044): a name that can only carry a credential (DEC-0041, FL-4), a
 * value shaped like one, a launch argument that carries one (session-handoff/1 SH-10) and a URL that does (LC-21).
 * `fabric://` links (`src/fabric-links.ts`, FAC-SEM-052) and declared command lines (`src/semantic-rules.ts`,
 * FAC-SEM-057) use it. `src/session-handoff.ts` keeps a copy, because its vendors take that file alone and run it
 * without this kit; `test/session-handoff-review.test.ts` checks that the copy agrees with this module. Vendors that
 * re-sync on a change (DEC-0151) include: the Fabric Agent Adapter kit's detector ports (its Python and JS secrets
 * modules, its dashboard-link checkers, its connection ports and its dashboard button), its vendored vector files that
 * change answer (`connections-extra`, `feed-protocols`, and `estate-vectors.json` and `package-vectors.json`, re-vendored
 * from the two changed semantic fixtures), Fabric Switchboard's folder-attribution port (it has neither look-ahead nor
 * look-behind, so it checks the `sk-` strength outside its regex, and on a rejected run it retries at every inner - or _ boundary inside it, the strength checked within 256 characters from that sk-, and re-syncs
 * `folder-attribution.json` at the merge commit), the adapter's dashboard-link test sample (its lower-case `sk-` sample stops being a key under DEC-0151 and
 * becomes one DEC-0151 reads, built from pieces), the adapter's profiles test case (its query of `%zz`, a raw
 * control character and `KIA` with 16 more characters stops being found, since its `AKIA` borrowed the `A` of the
 * encoded `%1A`; it is rebuilt with a boundary before `AKIA`, from pieces) and any template or agent that copies the kit; a port that copies
 * `fixtures/vectors/folder-attribution.json` re-syncs it only together with the detector, since six of its nine new AT-15 cases fail under the earlier detector (three did before DEC-0151's round 14), and the percent-escape case fails under a port that takes the boundary without its escapes. Project Observatory's folder-attribution port (with its attribution-vectors pin) and its estate-record
 * port (FAC-SEM-075) re-sync together with that file. Whole-file vendors that pin this file by hash take DEC-0151 at
 * their next re-pin, with their vectors. Fabric vendors this file twice, one copy under a sha256 `pin.json` together with
 * `fixtures/vectors/folder-attribution.json`; Fabric Dashboards vendors `src/session-handoff.ts` and
 * `src/fabric-links.ts`, and its service host's connections hold a port; Fabric Dashboards' sample-service kit copies
 * hold the earlier pattern. Every port drops its case-insensitive flag (`re.I`, `(?i)`) and reads digits as ASCII (`re.ASCII`, `[0-9]` or `(?-u:\d)`): Project Observatory's folder-attribution and estate-record ports and Fabric Switchboard's folder-attribution port compile it case-insensitively today. A port derives the files whose answers change by patching SECRET_VALUE in its twins and
 * running its suite, never by scanning literals (the CT-210 handoff names every adapter test such a run failed). A repository-name check must not compose this source after a
 * separator look-behind with an `i` flag: the boundary group consumes one character, so a key right after `-`, `.`
 * or `_` goes unfound and `i` undoes the canonical case and the `sk-` strength; it keeps its own boundary-free key
 * shapes, case-sensitive, with no `i` flag.
 */

/**
 * A name's words: split at `.`, `_`, `-` and camelCase humps, lowercased — `refreshToken_v2-Id` is
 * `refresh token v2 id` and `APIKey` is `api key`. A credential word must be a whole word of the name, so
 * `themeCode`, `sortKey` and `tokenizer` are harmless (DEC-0041, CO-260).
 */
export function nameWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[\s._-]+/)
    .filter(Boolean)
    .map((word) => word.toLowerCase());
}
/**
 * A name holding one of these words can only carry a credential (FL-4): the words, and the glued forms a name
 * written in one case (`accesstoken`, `sessionid`) leaves unsplit.
 */
export const CREDENTIAL_WORDS = [
  "token", "secret", "password", "passwd", "pass", "passphrase", "credential", "credentials", "cookie", "authorization",
  "bearer", "jwt", "otp", "apikey", "signature", "sig",
  "accesstoken", "idtoken", "authtoken", "refreshtoken", "sessionid", "sessiontoken", "logincode", "authcode", "privatekey",
  "clientsecret", "secretkey", "accesskey"
] as const;
/**
 * Words that carry a credential only beside a partner word in the same name (`api_key`, `authCode`, `sessionId`),
 * or as the whole name (`key`, `auth`, `session`, `code`): `sortKey`, `authorName` and `sessionLength` pass.
 */
export const CREDENTIAL_PAIRS: Readonly<Record<string, readonly string[]>> = {
  key: ["private", "api", "access", "secret", "session", "auth", "signing", "encryption", "master", "client", "login", "refresh"],
  auth: ["token", "code", "header"],
  session: ["token", "id"],
  code: ["login", "auth", "access", "session"]
};
/** A name's words, each also in the singular when it ends in `s`: `apiKeys` is `api key`, `secrets` is `secret`. */
const withSingulars = (words: string[]): string[] => [...words, ...words.filter((word) => word.length > 2 && word.endsWith("s")).map((word) => word.slice(0, -1))];
/** Whether a name — a parameter, a header, an environment variable, a config key — can only carry a credential. */
export function credentialName(name: string): boolean {
  const split = nameWords(name);
  const words = withSingulars(split);
  if (words.some((word) => (CREDENTIAL_WORDS as readonly string[]).includes(word))) return true;
  if (split.length === 1 && words.some((word) => Object.hasOwn(CREDENTIAL_PAIRS, word))) return true;
  return Object.entries(CREDENTIAL_PAIRS).some(([word, partners]) => words.includes(word) && partners.some((partner) => words.includes(partner)));
}

/** A JWT or JWS anywhere in a value: three base64url segments, the first a JSON object's `eyJ`. */
export const JWT_SHAPE = /eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*/;
/** A base64url character: what the three segments of `JWT_SHAPE` are made of. */
const isUrlBase64 = (code: number): boolean =>
  (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a) || (code >= 0x30 && code <= 0x39) || code === 0x2d || code === 0x5f;
/** The end of the run of base64url characters starting at `from`. */
const runEnd = (text: string, from: number): number => {
  let end = from;
  while (end < text.length && isUrlBase64(text.charCodeAt(end))) end += 1;
  return end;
};
/**
 * The spans `JWT_SHAPE` matches in a text, leftmost and not overlapping as a global regex finds them, read in one pass
 * (the regex backtracks from every `eyJ` of a long run, quadratic in it): every `eyJ` of one run shares that run's end,
 * so only its first is tried, and a match ends where its third segment's run ends. `first` stops at the first match.
 */
export function jwtSpans(text: string, first = false): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  let from = 0;
  for (let at = text.indexOf("eyJ", from); at >= 0; at = text.indexOf("eyJ", from)) {
    const one = runEnd(text, at + 3);
    from = one;
    if (one - at - 3 < 2 || text[one] !== ".") continue;
    const two = runEnd(text, one + 1);
    if (two - one - 1 < 2 || text[two] !== ".") continue;
    const three = runEnd(text, two + 1);
    spans.push([at, three]);
    if (first) break;
    from = three;
  }
  return spans;
}
/** Whether `JWT_SHAPE` matches anywhere in a text, read in one pass. */
export const hasJwt = (text: string): boolean => jwtSpans(text, true).length > 0;
/**
 * A value that says it is a credential (`Bearer ` at its start, in any case), or a provider key's shape (OpenAI,
 * GitHub, Slack, AWS, GitLab) with its prefix in its canonical case only: `SK-` or `GHP_` is no key (DEC-0151 item 7);
 * the `AKIA` body is read in upper case only, as an AWS key id is written.
 * A prefix counts only at the start of a value, after a character that is no ASCII letter or digit, or after an
 * escape: a percent-escape (`%22`) or a double one (`%2522`), a backslash escape (`\n`, `\t`, `\r`, `\"`, `\'`, `\b`,
 * `\f`, `\v`, `\0`, `\a`, `\e`), an octal (`\042`), `\x` with two hex digits, `\u` with four, or an ESC colour
 * sequence, raw or escaped (`\u001b[`, `\x1b[`, `\e[`, `\033[`, digits and `;`, `m`). It is matched as a consuming
 * group so a port without look-behind reads it the same; a key glued right after a letter or digit is knowingly not
 * found. An `sk-` key holds what `src/connections.ts` asks of one, within 256 characters: a digit and an upper-case
 * letter with 16 or more characters, or a digit with 32 or more. Its two look-aheads are bounded to 255 characters,
 * read lazily, so a long run of `sk-` prefixes is read in linear time. So `project:helpdesk-customer-support`,
 * `project:sk-learn-experiments` and `sk-learn-experiments-2026` are no keys, and `sk-or-v1-` with 64 lower-case hex
 * digits is one. A port whose regex has no look-ahead (Rust's `regex` crate) checks that strength outside the regex.
 * Knowingly not found: a key after a triple percent-escape (`%252522`), an eight-digit `\U00000022` escape, a `%u0022` escape, a CSI
 * sequence that is not a colour sequence (`ESC[K`, `ESC[2J`), or a colour sequence opened by the 8-bit CSI (U+009B), a
 * brace escape (`\x{1b}`, `\u{1b}`), `\E` or the caret `^[`. A colour sequence's parameters may hold `:` (ITU T.416),
 * and `\33` is an escaped ESC too.
 * A match includes its boundary character, so a caller uses `.test` only, never the matched text or its index.
 */
export const SECRET_VALUE = /(^[Bb][Ee][Aa][Rr][Ee][Rr]\s.+|(?:^|[^A-Za-z0-9]|%[0-9A-Fa-f]{2}|\\[nrt"']|\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}|\\[bfv0ae]|\\[0-7]{1,3}|%25[0-9A-Fa-f]{2}|\x1b\[[0-9;:]*m|(?:\\u001[bB]|\\x1[bB]|\\e|\\033|\\33)\[[0-9;:]*m)(?:sk-(?=[A-Za-z0-9_-]{0,255}?\d)(?:(?=[A-Za-z0-9_-]{0,255}?[A-Z])[A-Za-z0-9_-]{16,}|[A-Za-z0-9_-]{32,})|gh[pousr]_[A-Za-z0-9]{20,}|xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|glpat-[A-Za-z0-9_-]{20,}))/;
/**
 * A long secret: 40 or more characters of base64 or base64url (`+`, `/`, `=`, `-`, `_` included), mixing upper case,
 * lower case and digits. A hex digest is lower case and passes.
 */
const LONG_RUN = /[A-Za-z0-9+/=_-]{40,}/g;
export const longSecret = (value: string) => (value.match(LONG_RUN) ?? []).some((run) => /[a-z]/.test(run) && /[A-Z]/.test(run) && /[0-9]/.test(run));
/** Whether a value could be a credential: a JWT anywhere, a provider key or `Bearer …`, or a long secret-shaped run. */
export const secretValue = (value: string): boolean => hasJwt(value) || SECRET_VALUE.test(value) || longSecret(value);

/**
 * `Bearer <token>` inside a longer value (`--header=Authorization: Bearer …`): a token of 12 or more token characters
 * holding a digit, so prose ("the Bearer token refresh bug", "the Bearer authentication scheme") passes.
 */
export const BEARER_INSIDE = /\bbearer\s+(?=[A-Za-z0-9._~+/-]*\d)[A-Za-z0-9._~+/-]{12,}=*/i;
/** A path or a URL by its start: `/…`, `~/…`, `./…`, `C:\…`, `scheme://…`. */
const PATH_LIKE = /^(?:[/~.]|[A-Za-z]:[\\/]|[a-z][a-z0-9+.-]*:\/\/)/i;
/**
 * Whether a piece is a path or a URL, whose separators split it: it starts like one, or it holds a separator and
 * either ends with a file extension or has a lower-case word for a segment (`sessions/…`, `apps/Desktop/src`). A
 * base64 secret's segments are mixed-case runs, so `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` stays one value.
 */
const pathLike = (piece: string): boolean =>
  PATH_LIKE.test(piece) ||
  (/[\\/]/.test(piece) && (/\.[A-Za-z0-9]{1,8}$/.test(piece) || piece.split(/[\\/]/).some((segment) => /^[a-z][a-z0-9_-]{2,}$/.test(segment))));
/**
 * The same, for a launch argument or a server's command and URL, which carry paths: a long run is looked for
 * between path separators, so a folder path holding a session id is not taken for a key.
 */
export const secretArgument = (value: string): boolean =>
  hasJwt(value) || SECRET_VALUE.test(value) || BEARER_INSIDE.test(value) ||
  value.split(/[\s=]/).some((piece) => (pathLike(piece) ? piece.split(/[\\/]/).some((part) => longSecret(part)) : longSecret(piece)));

/** Percent-decode and keep `+` as `+`: `URLSearchParams` turns a raw `+` into a space, which would split a base64 run. */
const decodeKeepingPlus = (raw: string): string => {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
};
/** Each query or fragment piece's raw value, by its decoded name: what `URLSearchParams` hands over, with `+` kept. */
export function rawValues(query: string): Map<string, string[]> {
  const values = new Map<string, string[]>();
  for (const piece of query.split("&")) {
    if (piece === "") continue;
    const at = piece.indexOf("=");
    const name = [...new URLSearchParams(at < 0 ? piece : piece.slice(0, at)).keys()][0] ?? "";
    const value = at < 0 ? "" : decodeKeepingPlus(piece.slice(at + 1));
    const list = values.get(name);
    // Appended in place: a query of many pieces under one name costs one pass, not a copy per piece.
    if (list === undefined) values.set(name, [value]);
    else list.push(value);
  }
  return values;
}
/**
 * Whether a URL an MCP entry or a launch names carries a credential (LC-21): anything `secretArgument` finds in it,
 * a password in its user information, or a query or fragment parameter whose name can only carry a credential and
 * has a value, or whose value is shaped like one. `?api_key=…` is refused whatever the value, `?key=` left empty
 * and `?sort=key` are not. A string that is not an absolute URL is checked as an argument only.
 */
export function secretUrl(value: string): boolean {
  if (secretArgument(value)) return true;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.password !== "") return true;
  for (const part of [url.search, url.hash]) {
    for (const [name, values] of rawValues(part.slice(1))) {
      if (values.some((raw) => (raw !== "" && credentialName(name)) || secretValue(raw))) return true;
    }
  }
  return false;
}
// #endregion secret-shape
