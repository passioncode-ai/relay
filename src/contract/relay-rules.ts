// #region relay-rules — docs: docs/specification/relay.md#semantic-rules
/**
 * Document rules of the relay protocol (DEC-0047) that a schema cannot say. Signatures, admission and the opening of
 * an envelope are stateful and live in `relay.ts` and `secret-envelope.ts`; these rules check one document alone.
 *
 * - FAC-SEM-070: a secret envelope is sealed to a key-agreement key (`#kem`) by a signing key (`#sig`) under ES256, with
 *   the one admitted suite, a life of more than zero and at most 24 hours, and an encapsulated key that is a valid
 *   P-256 point.
 * - FAC-SEM-071: a relay frame keeps its limits — `auth` names a signing key, ES256 and this protocol; `send` addresses
 *   a signing key, with a `ttl` of 1 s to 7 days and a body of at most 765 KiB decoded (MAX_BODY_BYTES).
 */
import { type Finding, type JsonObject, isObject } from "./findings.js";
import { p256KeyRefusal } from "./p256.js";
import { ENVELOPE_SUITE, MAX_ENVELOPE_LIFETIME_SECONDS } from "./secret-envelope.js";
import { MAX_BODY_BYTES, MAX_MESSAGE_TTL_SECONDS, RELAY_ALG, RELAY_PROTOCOL } from "./relay.js";

const ends = (value: unknown, suffix: string) => typeof value === "string" && value.endsWith(suffix);

function envelope(value: JsonObject): Finding[] {
  const out: Finding[] = [];
  const h = isObject(value.header) ? value.header : {};
  const add = (at: string, message: string) => out.push({ code: "FAC-SEM-070", instancePath: `/header/${at}`, message });
  if (!ends(h.recipient, "#kem")) add("recipient", "an envelope is sealed to a key-agreement key (#kem), never to a signing key");
  if (!ends(h.sender, "#sig")) add("sender", "an envelope is signed by a signing key (#sig), never by a key-agreement key");
  if (h.alg !== RELAY_ALG) add("alg", "an envelope is signed with ES256, the only algorithm a relay participant uses (unsupported-alg)");
  if (JSON.stringify(h.suite) !== JSON.stringify(ENVELOPE_SUITE)) add("suite", "the only admitted suite is DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM");
  const iat = typeof h.iat === "string" ? Date.parse(h.iat) : Number.NaN;
  const exp = typeof h.exp === "string" ? Date.parse(h.exp) : Number.NaN;
  if (!(exp > iat) || (exp - iat) / 1000 > MAX_ENVELOPE_LIFETIME_SECONDS) add("exp", "an envelope lives more than zero and at most 24 hours");
  if (typeof h.enc !== "string" || p256KeyRefusal(Buffer.from(h.enc, "base64url")) !== null) add("enc", "the encapsulated key is a valid uncompressed P-256 point");
  return out;
}

function frame(value: JsonObject): Finding[] {
  const add = (at: string, message: string): Finding => ({ code: "FAC-SEM-071", instancePath: `/${at}`, message });
  if (value.type === "auth") {
    return [
      ...(ends(value.kid, "#sig") ? [] : [add("kid", "a machine proves itself with its signing key (#sig)")]),
      ...(value.alg === RELAY_ALG ? [] : [add("alg", "a machine proves itself with ES256, the only algorithm admitted (unsupported-alg)")]),
      ...(value.protocol === RELAY_PROTOCOL ? [] : [add("protocol", `auth speaks ${RELAY_PROTOCOL}`)])
    ];
  }
  if (value.type === "send") {
    const out: Finding[] = [];
    if (!ends(value.to, "#sig")) out.push(add("to", "a message is addressed to a machine's signing key (#sig)"));
    if (!Number.isSafeInteger(value.ttl) || (value.ttl as number) < 1 || (value.ttl as number) > MAX_MESSAGE_TTL_SECONDS) out.push(add("ttl", "ttl is 1 s to 7 days"));
    if (typeof value.body !== "string" || Buffer.from(value.body, "base64url").length > MAX_BODY_BYTES) out.push(add("body", "a body is at most 765 KiB decoded"));
    return out;
  }
  return [];
}

export function relayRules(kind: string, value: unknown): Finding[] | undefined {
  if (!isObject(value)) return undefined;
  if (kind === "secret-envelope") return envelope(value);
  if (kind === "relay-frame") return frame(value);
  return undefined;
}
// #endregion relay-rules
