# FORK_HARDENING - epicurean-Paradox/obsidian-second-brain

**Upstream:** eugeniughelbur/obsidian-second-brain, pinned at v0.14.0 (commit b8c52f8).
**Governing decision:** claude-code-mastery ADR 0001 (layered knowledge base on a
hardened second-brain fork) - this branch (`gate-hardening`) is its §3.
**Model:** the Graft `gate-hardening` precedent - strip (delete, not disable),
red-first pins as merge gates, source-reviewed manual install.

## Why a fork at all

The upstream capability (vault synthesis, cross-linking, retrieval) is wanted; its
delivery violates standing gates: a `curl|bash` installer class that writes agent
config (`~/.claude/settings.json`, `~/.claude/skills`, `.gemini/`, `.codex/`, ...) -
the L21 injection shape, auto-REJECT; an unattended Telegram poller (Loop Launch
Gate); and direct multi-vendor API egress (no-direct-vendor-API posture; Bedrock-only
per ADR 0001 §2).

## Stripped (deleted, not disabled)

| Class | Paths |
|---|---|
| Installers / agent-config writers | `install.sh`, `update.sh`, `scripts/quick-install.sh`, `scripts/setup.sh`, `scripts/setup_settings_hook.py`, `scripts/install-codex-wrappers.sh` |
| Platform adapters + harness runners (write/drive other harnesses' config: `.gemini/`, `.codex/`, `~/.claude/skills` symlinks, opencode/pi/hermes/grok-bot, the Codex-CLI command runner) | `adapters/` (all), `scripts/build.sh`, `scripts/run-command.sh` |
| Unattended poller | `integrations/telegram-journal/` (launchd daemon) |
| Direct third-party research egress (web search, LLM ladders, media/Whisper) | `scripts/research/` |
| Remote-embed + LLM eval harness (OpenAI-compatible endpoints, OPENAI_API_KEY judge) | `scripts/eval/` |
| Tests of the above | pruned; every kept test exercises kept code |

## Surgically hardened (kept, egress removed)

- `scripts/triage_links.py` - the upstream LLM verdict path POSTed to
  `api.anthropic.com` under a personal key. Now raises `NotImplementedError` until the
  Bedrock provider PR lands. Fail-hard, never silent.
- `integrations/obsidian-mcp-server/vault_ops.py` - the `openai` remote-embed backend
  branch is removed; the local backend additionally refuses any non-localhost
  `OLLAMA_URL`/embed URL (returns lexical fallback instead of egressing). Interim only:
  embeddings move to Bedrock + pgvector in the re-route PR (ADR 0001 §2).

## Kept, scoped (per ADR 0001)

- `hooks/obsidian-bg-agent.sh` - the PostCompact autonomous writer, operator-retained.
  MAY NOT run until the ADR 0001 §5 OWASP LLM Top-10 pipeline gates its writes (build
  prerequisite, later PR) and its write root is confined (§3 enforce layer, later PR).
- Mutation scripts (`merge_notes.py`, `heal_links.py`, `triage_links.py`, ...) - the
  link/vault CRUD; will be fenced to L2 + link-fences by the enforce-layer PR.
- `integrations/obsidian-mcp-server`, `integrations/obsidian-plugin`, `commands/`,
  vault tooling (`vault_scan.py`, `vault_health.py`, `link_graph.py`, ...).

## Install (replaces every stripped installer)

Manual, reviewed, no script:

1. Clone THIS fork at the audited commit; read the diff vs upstream before use.
2. Copy (never symlink-by-script) the specific `commands/*.md` you want into your
   agent config yourself, after reading each one.
3. Set `OBSIDIAN_VAULT_PATH` yourself. Nothing here writes `~/.claude/*` or any other
   agent's config, ever.

## Red-first pins (merge gates - see `tests/test_gate_hardening.py`)

Each pin FAILS on upstream v0.14.0 by construction and must stay green here:

1. No installer/config-writer path exists (the full strip table above).
2. No executable file writes agent-config paths (`settings.json`, `~/.claude`,
   `.gemini/`, `.codex/` ...).
3. No unattended-poller artifacts (telegram-journal, launchd plists).
4. Zero direct-vendor egress hosts in executable code (`api.anthropic.com`,
   `api.openai.com`, `api.x.ai`, `perplexity`, `tavily`, `brave`,
   `generativelanguage.googleapis`); local embed URL pinned to localhost.
5. `triage_links.ask_claude` raises (no silent LLM path).
6. `hooks/obsidian-bg-agent.sh` still present (kept-and-scoped, not lost in the strip).

## Sequence (ADR 0001; each its own reviewed PR)

1. **This branch** - strip + pins.
2. Enforce layer: `DERIVED_VAULT_ROOT` write-root confinement, fence-diff guard,
   OS read-only backstop on SSOT, `layer:` linter, CI egress test.
3. OWASP GenAI LLM Top-10 pipeline (build prerequisite for any autonomous write).
4. Bedrock + pgvector re-route (embeddings, triage LLM, enrichment).

## Re-audit tax

Every upstream pull re-checks for reintroduced installers/pollers/egress **before**
merge - these are near upstream's core and WILL return. The pins make the check
mechanical; the review is still owed.
