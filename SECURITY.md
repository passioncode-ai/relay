# Security

Report a vulnerability privately to contact@passioncode.ai, never in a public issue. Do not attach
credentials, a working exploit or anyone's notes to an issue or a pull request.

What is in scope: the relay's two builds (the Cloudflare Worker and the portable server) and everything they
accept from the network. That covers machine authentication, session isolation between machines and owners,
the integrity of blobs and envelopes stored by digest, refusal while the protocol is not ready, and anything
that would let the relay read a secret, forge or suppress a revocation, or let a caller act at a trust tier it
did not prove. The protocol itself is specified in fabric-agent-contract (DEC-0047); a flaw in the
specification is reported here too. Third-party components are reported to their own projects; tell us too
if this repository ships the affected version.
