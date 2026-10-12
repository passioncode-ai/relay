// #region relay-admission — docs: docs/protocol/sessions.md#admission
// Who the relay admits: the machines of the estate record it holds, applied only after the contract's own verification
// (relayAdmissionSet, DEC-0047 item 4 over DEC-0055). This module holds that revision between offers and never decides
// anything the contract function does not: a refused offer changes nothing, and a held revision past its window admits
// nobody (fail closed).

import type { JsonObject } from "../contract/findings.ts";
import { relayAdmissionSet, type AdmissionResult } from "../contract/relay.ts";

export interface AdmissionConfig {
  /** The estate's first passkeys, pinned when this relay was set up for the estate (public keys, never secrets). */
  pinned: readonly unknown[];
  /** The bundled estate-record schema validator (src/contract/estate-record.validate.js). */
  schemaValid: (record: unknown) => boolean;
  now: () => Date;
}

export class AdmissionHolder {
  private held: JsonObject | undefined;

  constructor(private readonly config: AdmissionConfig) {}

  /** Applies `candidate` when the contract accepts it against the revision held; otherwise keeps what it held. */
  offer(candidate: unknown): AdmissionResult {
    const result = relayAdmissionSet({ held: this.held, candidate, pinned: this.config.pinned, at: this.config.now(), schemaValid: this.config.schemaValid });
    if (result.ok) this.held = result.held;
    return result;
  }

  /** The set to admit from right now: `expired` once the held revision's window has ended, `no-record` before any. */
  current(): AdmissionResult {
    return relayAdmissionSet({ held: this.held, pinned: this.config.pinned, at: this.config.now(), schemaValid: this.config.schemaValid });
  }

  /** The revision held, for persistence by an adapter; undefined before the first accepted offer. */
  get revision(): JsonObject | undefined {
    return this.held;
  }
}

/** Where an adapter keeps the estate: the pinned passkeys and every revision it was given, in any order. */
export interface EstateSource {
  pinned(): Promise<unknown[]>;
  revisions(): Promise<unknown[]>;
}

/**
 * A holder loaded from `source`: revisions are offered in revision order, each against the one before, and the first
 * refused stops the walk — a gap or a forged revision never lets a later one in. What was refused is reported, not hidden.
 */
export async function loadAdmission(source: EstateSource, schemaValid: (record: unknown) => boolean, now: () => Date): Promise<{ holder: AdmissionHolder; refused: Array<{ revision: unknown; refusal: string; problem?: string }> }> {
  const holder = new AdmissionHolder({ pinned: await source.pinned(), schemaValid, now });
  const revisions = (await source.revisions()).slice().sort((a, b) => Number((a as JsonObject)?.revision) - Number((b as JsonObject)?.revision));
  const refused: Array<{ revision: unknown; refusal: string; problem?: string }> = [];
  for (const revision of revisions) {
    const result = holder.offer(revision);
    if (!result.ok) {
      refused.push({ revision: (revision as JsonObject)?.revision, refusal: result.refusal, ...(result.problem ? { problem: result.problem } : {}) });
      break;
    }
  }
  return { holder, refused };
}
// #endregion relay-admission
