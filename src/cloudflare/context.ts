// #region cloudflare-context — docs: docs/adr/0002-estate-hub.md#consequences
// Every Durable Object name the hosted relay derives — the estate hub's, each mailbox's — goes through `contextKey()`
// (relay RLY-08; Fabric CX-REL-01, CX-22). While one relay origin serves one context it is a constant. In a
// multi-context relay it becomes the per-context pseudonymous id: the enrollment key's thumbprint, or an id derived per
// (estate, context) that the relay cannot invert. It is never the estate id: the relay's operator must not be able to
// link one person's contexts.

export function contextKey(): string {
  return "estate";
}

/** The estate hub's Durable Object name (`ESTATE.idFromName`). */
export function hubName(): string {
  return contextKey();
}

/** A recipient's mailbox Durable Object name (`MAILBOX.idFromName`). */
export function mailboxName(kid: string): string {
  return `${contextKey()}/${kid}`;
}
// #endregion cloudflare-context
