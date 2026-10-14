// #region cloudflare-context — docs: docs/adr/0002-estate-hub.md#consequences
// Every name the hosted relay derives — the estate hub's and each mailbox's Durable Object name, every R2 key — comes
// from this file, through `contextKey()` (relay RLY-08; Fabric CX-REL-01, CX-22). While one relay origin serves one
// context it is a constant, and the names keep their plain forms. In a multi-context relay it becomes the per-context
// pseudonymous id: the enrollment key's thumbprint, or an id derived per (estate, context) that the relay cannot
// invert. It is never the estate id: the relay's operator must not be able to link one person's contexts. Changing
// these forms is a storage migration: mail and blobs stored under the old names are unreachable under new ones.

export function contextKey(): string {
  return "estate";
}

/** The estate hub's Durable Object name (`ESTATE.idFromName`). */
export function hubName(context = contextKey()): string {
  return context;
}

/** A recipient's mailbox Durable Object name (`MAILBOX.idFromName`). */
export function mailboxName(kid: string, context = contextKey()): string {
  return `${context}/${kid}`;
}

/** Where the context's estate record lives in R2: the pinned passkeys and `revisions/<n>.json` under it. */
export function estatePrefix(_context = contextKey()): string {
  return "estate/";
}

/**
 * A blob's R2 key. The bare digest while one context is served (the planned R2 lifecycle rule keeps `sha256:` keys
 * 8 days); a multi-context relay prefixes it with the context and moves the rule with it.
 */
export function blobName(digest: string, _context = contextKey()): string {
  return digest;
}

/** A blob's index entry in R2 (its recipients and fetches). */
export function blobIndexName(digest: string, _context = contextKey()): string {
  return `blobindex/${digest}`;
}
// #endregion cloudflare-context
