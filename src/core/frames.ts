// #region relay-frames — docs: docs/protocol/sessions.md#frames
// What a frame from a node is, before a session acts on it (DEC-0047 as amended by DEC-0066, contract relay.md
// "Frames"): not a fabric-relay/0.1 frame at all; a type a node never sends or no type the protocol knows
// (`unknown-type`); a known node type that fails the frame schema or FAC-SEM-071 (`malformed`); or a valid frame. The
// schema check is the contract's relay-frame schema, compiled ahead of time (src/contract/relay-frame.validate.js), so a
// Worker runs no compiler: a frame is checked against its own type's branch of the schema's `oneOf`, failing fast,
// which answers what the whole schema answers (each branch has its own `type` const) at a small fraction of the cost.

import validators from "../contract/relay-frame.validate.js";
import { relayRules } from "../contract/relay-rules.ts";
import { FRAME_TYPES } from "../contract/relay.ts";

/** The longest frame `id` (the relay-frame schema's maxLength, in code points as JSON Schema counts them). */
export const MAX_ID_LENGTH = 128;

/** Frame types only the relay sends: a node that sends one is answered `unknown-type`. */
export const RELAY_ONLY_TYPES = ["hello", "welcome", "accepted", "deliver", "presence", "presence-result", "error"] as const;

/** A string's length in code points, as JSON Schema's maxLength counts it (an emoji is one, not two UTF-16 units). */
export const codePoints = (text: string): number => {
  // A surrogate pair is one code point; a lone surrogate counts as one, as string iteration and Ajv's ucs2length count
  // it. A loop over char codes, not the string iterator: this runs on every frame's id.
  let n = text.length;
  for (let i = 0; i < text.length - 1; i += 1) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = text.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) { n -= 1; i += 1; }
    }
  }
  return n;
};

export type Frame = { v: 1; type: string; id: string } & Record<string, unknown>;

export type Classified =
  | { kind: "not-frame" } // not `{v: 1, type, id}` with a usable id: answered with no replyTo, the id never echoed
  | { kind: "unknown-type"; frame: Frame }
  | { kind: "malformed"; frame: Frame; where: string }
  | { kind: "frame"; frame: Frame };

/** Classifies the parsed text of one frame. `parsed` is `undefined` for text that is not JSON. */
export function classifyFrame(parsed: unknown): Classified {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { kind: "not-frame" };
  const value = parsed as Record<string, unknown>;
  if (value.v !== 1 || typeof value.type !== "string" || typeof value.id !== "string" || value.id.length < 1
    || codePoints(value.id) > MAX_ID_LENGTH) {
    return { kind: "not-frame" };
  }
  const frame = value as Frame;
  if (!(FRAME_TYPES as readonly string[]).includes(frame.type) || (RELAY_ONLY_TYPES as readonly string[]).includes(frame.type)) {
    return { kind: "unknown-type", frame };
  }
  // An `auth` frame is `admit`'s to judge, schema and FAC-SEM-071 alike, in its own order and with its own codes
  // (`protocol-unsupported`, `unsupported-alg`, `unauthenticated`; DEC-0066 "Admission"), never `malformed`: an auth
  // with no `alg` is `unsupported-alg`, one with no `sig` `unauthenticated`. `admit` reads every member defensively.
  if (frame.type === "auth") return { kind: "frame", frame };
  const validate = Object.hasOwn(validators, frame.type) ? validators[frame.type] : undefined;
  if (!validate) return { kind: "unknown-type", frame }; // a type in FRAME_TYPES the schema has no branch for
  if (!validate(frame)) {
    const errors = (validate.errors ?? []) as Array<{ instancePath?: string }>;
    return { kind: "malformed", frame, where: errors.map((e) => e.instancePath || "/").filter((p, i, all) => all.indexOf(p) === i).slice(0, 4).join(", ") || "/" };
  }
  const findings = relayRules("relay-frame", frame) ?? [];
  if (findings.length > 0) return { kind: "malformed", frame, where: findings.map((f) => `${f.code} at ${f.instancePath || "/"}`).slice(0, 4).join(", ") };
  return { kind: "frame", frame };
}
// #endregion relay-frames
