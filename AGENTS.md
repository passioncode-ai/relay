# Working in relay

## Read first

1. The organization's
   [roadmap](https://github.com/passioncode-ai/fabric-workspace/blob/main/knowledge/roadmap.md) —
   every major feature and release across PassionCode.ai as `RM-*` tracks with owner, phase and
   state. It is the entry point: a task here that serves a track names it, and the track's status
   is edited only in the roadmap.
2. The PassionCode.ai knowledge base — `fabric-workspace/knowledge/` in your clone (org-index
   `scripts/clone_all.sh` makes it) or https://wiki.passioncode.ai/knowledge — at least its
   [README](https://github.com/passioncode-ai/fabric-workspace/blob/main/knowledge/README.md),
   vision, principles and how-to-work.
3. This file, then the organization's
   [CONTRIBUTING.md](https://github.com/passioncode-ai/.github/blob/main/CONTRIBUTING.md).

## What this repository is

PassionCode Relay: carries sessions, sealed secret envelopes and package blobs between machines that belong to one person or one organization, with no authority and no plaintext. It is one runtime-neutral core (`src/core/`) with two builds: hosted (`src/cloudflare/`, a Worker with Durable Objects and R2) and portable (`src/portable/`, for self-hosting). Why it is shaped this way: [docs/adr/0001-relay-repository.md](docs/adr/0001-relay-repository.md). Roadmap track: RM-21 (agent network).

## Commands

| What | Command |
|---|---|
| Install | `npm ci` |
| Test (the gate) | `npm run check` — types, then every test; the Worker bundle runs in workerd through Miniflare, no network |
| Build | `npm run build:worker` (hosted bundle into `dist/worker/`); the portable build runs from source (`npm run portable`) until RLY-04 |
| Clean old builds ([LC-15](https://github.com/passioncode-ai/fabric-workspace/blob/main/knowledge/lifecycle.md#lc-15)) | `rm -rf dist .wrangler` — nothing is kept between builds; no cache beyond `node_modules` |
| MCP (register + proving call) | none — the relay is not an MCP server; `GET /healthz` proves a build is up |

## Local rules

- **The protocol lives in fabric-agent-contract DEC-0047, not here.** Do not add a frame, a route that carries
  session data, or an authentication scheme that the accepted DEC does not define. Until it is accepted, every
  session is refused with `protocol-not-ready`, and a test guards each path to that refusal.
- **Both builds route through `handle` in `src/core/relay.ts`.** An adapter converts requests and responses and
  binds storage. It adds no route, so the hosted and the self-hosted relay cannot drift apart.
- **The core uses web-standard APIs only** (`Request`, `Response`, `crypto.subtle`): no `node:*` and no
  `cloudflare:*` import under `src/core/`.
- **Blobs are stored and served only through `putVerified` and `getVerified`.** A blob whose bytes do not hash to
  its name is refused on write and on read.
- No deployment's values in the repository: no account id, no route, no secret. `wrangler.jsonc` declares
  bindings only.
- Logs are structured and never carry a request body, a token or an envelope.
- Several sessions may work here: agent-sync with leases through git, described in [docs/AGENT_SYNC.md](docs/AGENT_SYNC.md). Take a lease before editing a guarded path (`CHANGELOG.md`, the backlog, `docs/adr/`).

## Lifecycle

- The repository installs no resident process, no launchd job and no MCP server.
- `npm run dev` (wrangler) and `npm run portable` run in the foreground of the terminal that started them and
  stop with it (Ctrl-C, SIGINT or SIGTERM). The portable relay stops gracefully: every session is closed 1001, its
  SQLite files are closed, and it exits 0 within 10 s (docs/protocol/sessions.md, "Stopping").
- Tests start workerd through Miniflare and dispose of it when they finish.
- The hosted relay runs on Cloudflare once RLY-05 deploys it. All of an estate's sessions live in one hibernating
  Durable Object (docs/adr/0002-estate-hub.md): idle sockets cost no duration, and each event bills only while it runs.

## Organisation

This repository is one of the `passioncode-ai` repositories. **The org map and onboarding live in
[passioncode-ai/org-index](https://github.com/passioncode-ai/org-index)** (private; readable by
every org member); the shared rules live in the knowledge base:

- [README](https://github.com/passioncode-ai/org-index#repositories): which repository owns what, and how they connect
- [rules](https://github.com/passioncode-ai/fabric-workspace/blob/main/knowledge/rules.md): branches, commits, CI, leases, secrets, handoffs
- [ONBOARDING.md](https://github.com/passioncode-ai/org-index/blob/main/ONBOARDING.md): setting up a new contributor's machine

Where this file is stricter than the rules, this file wins. A change to this repository's
role, dependencies or test command updates its row in `org-index/repositories.json` in the same change.

## Backlog ownership

Read [the common backlog contract](https://github.com/passioncode-ai/fabric-workspace/blob/main/knowledge/backlog.md). Declare canonical task boards and context in `docs/backlog-sources.json`; edit status only in the local owner, keep stable IDs and evidence, and publish after landing. Missing coverage is an error, not an empty queue.

## Report delivery

Follow the [shared report-delivery recommendation](https://github.com/passioncode-ai/fabric-workspace/blob/main/knowledge/how-to-work.md#delivering-reports-to-people): send human-facing reports directly as HTML or Markdown, without requiring ZIP extraction. Keep machine data separate; an explicit recipient format request wins.

## After work

In the same run: update this repository's docs with the change; if a cross-repository fact changed
(a product, a version, a plan row, a principle), update the page in `fabric-workspace/knowledge/`
that owns it; land both; publish (`node scripts/workspace.mjs sync` from a Fabric checkout) or
leave it to the scheduled sync. Leave a handoff with the exact next task.
