# The architect's audit of the relay

The North Star asks every agent tied to a direction for the architect's audit at each release
(fabric-workspace `knowledge/north-star.md` §6, "Merged with the North Star, validated by the architect", gap G30).

## 2026-11-13: scan

- **Command:** `python3.13 tools/audit.py scan <relay checkout>` in fabric-agents-database at `2ea5dd1`, read only
  (that checkout stayed clean). The relay was at `83430f2`. Output: [2026-11-13-scan.json](2026-11-13-scan.json).
- **Result:** no template fits. The top four by score are `content-brand` 9.162, `chat-assistant` 7.2, `web-quality`
  5.633 and `delivery-gateway` 5.523. Every score comes from shared libraries (`typescript`, `ajv`, `wrangler`, `ws`),
  and text similarity is at most 0.163.
- **Verdict:** the judged half (`audit.py start`, `playbooks/audit-agent.md`) does not apply. The relay is transport
  between one estate's machines. It calls no model and has no prompt or tool, so the agent playbook has nothing to
  judge. fabric-agent-contract reached the same conclusion for itself on the board (thread `16093ded`, 2026-11-13).
- **Next:** rescan at each release (the first is RLY-05's hosted deploy, S1 by 2026-11-20). If the relay ever gains an
  agent surface, consult the architect before building it.
