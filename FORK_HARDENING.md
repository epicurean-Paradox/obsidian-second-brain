# FORK_HARDENING - epicurean-Paradox/obsidian-second-brain

**Upstream:** eugeniughelbur/obsidian-second-brain, pinned at v0.14.0 (commit b8c52f8).
**Governing decision:** claude-code-mastery ADR 0001 (layered knowledge base on a
hardened second-brain fork) - this branch (`gate-hardening`) is its §3.
**Datamaran binding:** this fork is the first **coppermind** build. Datamaran's
ADR-0032 (`datamaraneers/npm-dashboard` `docs/adr/0032-copperminds-layered-bok.md`,
operator directive 2026-09-07) defines copperminds as specialized agentic clusters over
a layered Body of Knowledge: L0 = the Throughline-governed sources (read-only), L1 =
source-referencing notes with agent writes limited to CRUD on edges (Obsidian links),
L2+ = learned knowledge. The edge-CRUD constraint on L1 is an owed enforce-layer pin
here (see the arming conditions in `docs/council/2026-09-07-bedrock-account-242.md`).
It is not a personal tool; the council addendum of 2026-09-07 records that correction.
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
| Second unattended writer + its harness config template (added 2026-09-09) | `hooks/obsidian-hermes-session-end.sh`, `hooks/hermes-hooks.config.example.yaml` |
| Dead build system left reachable (added 2026-09-09) | `scripts/update-vault-integration.sh`, `scripts/lib.sh` |
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
4. Bedrock (AWS account 242201275909, eu-west-1; council
   `docs/council/2026-09-07-bedrock-account-242.md`): assume the fork's scoped IAM role
   through a named profile (`obsidian-bedrock`; role created by the fork-owned Terraform
   root, never the account-admin profile); source the five non-secret `OBSIDIAN_BEDROCK_*`
   / `AWS_REGION` values from `config/bedrock.eu-west-1.yaml` via a `.envrc` in the vault
   directory; put `OBSIDIAN_VAULT_PATH` and `OBSIDIAN_BG_AGENT_ENABLED` ONLY in the vault
   project's `.claude/settings.json` (project-scoped), never the user-global file; run the
   verification checklist in that council record before arming. Until every blocking
   condition there is read back, `OBSIDIAN_BG_AGENT_ENABLED` stays unset.

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
7. The headless writer's tool surface is pinned: `hooks/obsidian-bg-agent.sh` invokes `claude`
   with `--strict-mcp-config` and exactly `--allowedTools "Read,Write,Edit,Glob,Grep"` (no
   Bash, no network, no MCP). This flag is the boundary between model output as inert data
   and model output that can act (council 2026-09-07, security C4).
8. No committed file arms the bg-agent through the user-global Claude settings file: any
   mention of that file's path within three lines of the enable flag fails (the vault path
   alone arms nothing). PostCompact fires on every session's compaction, so a globally set
   flag feeds unrelated projects' summaries to this writer (council 2026-09-07, C1b).

9. No unattended writer bypasses the OWASP staging gate: any executable that
   invokes a headless agent runner (`hermes -z|run|cron`, `opencode run`,
   `codex exec`, `gemini -p`, `pi run`, `claude -p|--print`) must reference BOTH
   `OBSIDIAN_STAGING_ROOT` and `promote_candidates`. Generalised on purpose, so it
   catches the next harness rather than only Hermes.
10. No non-Claude harness hook artifacts exist (the Hermes session-end writer, its
   config templates, the vault-integration updater).
11. No non-test executable reaches for the stripped build system (`adapters/`,
   `scripts/build.sh`, `scripts/lib.sh`).

### Why 9-11 exist (2026-09-09)

PR #1 stripped `adapters/` and the Codex runner, but two Hermes artifacts survived
in `hooks/`, and nothing pinned them. `hooks/obsidian-hermes-session-end.sh` drove
`hermes -z` against `$OBSIDIAN_VAULT_PATH` **directly** on `on_session_end`: no
staging root, no promoter, no `vault_guard`, and no `--allowedTools` equivalent. Its
only constraint on what the model could write to the vault was a sentence inside its
own prompt -- "Add/update/link only - never delete, archive, or merge" -- which is a
request to a model, not a gate. One flag (`OBSIDIAN_HERMES_HOOK_ENABLED=1`) armed it.

So the step-3 conclusion in this file ("the bg-agent CANNOT reach the vault; the
promoter is the only path in") was true of the Claude writer and false of the repo:
a sibling writer reached the vault with the ten-check pipeline standing beside it,
unused. Pin 7 pinned the Claude writer's tool surface; nothing pinned the existence
of a second writer. Pin 9 is written against the *class* for that reason.

Its companion template also told the reader to install the script into
`~/.hermes/agent-hooks/` -- another agent's config directory, the strip class from
PR #1's first row.

`scripts/update-vault-integration.sh` went with them: it gated on
`adapters/$PLATFORM/adapter.sh` and shelled out to `scripts/build.sh`, both deleted
in PR #1, so it could only ever die at its own guard -- while `llms.txt` still told
people to run it as the way to update an install. `scripts/lib.sh` was sourced by
that same deleted build script and by nothing else.

## Sequence (ADR 0001; each its own reviewed PR)

1. **DONE** (#1) - strip + pins.
2. **DONE** (#2) - enforce layer: `DERIVED_VAULT_ROOT` write-root confinement,
   fence-diff guard, `layer:` linter. (The OS read-only backstop stays a
   deployment step, not code.)
3. **DONE** - OWASP GenAI LLM Top-10 pipeline: `scripts/owasp_pipeline.py` +
   `scripts/promote_candidates.py`, with the writer rewired to staging.
   **Seven checks are live and deterministic** (LLM02/03/04/05/06/09/10, plus a
   deterministic LLM01 prefilter and the LLM08 marker scan). **The three
   LLM-backed checks (LLM01 span classification, LLM07 claim strength, LLM08
   semantic leaks) report UNAVAILABLE, which the gate treats as a FAILURE** --
   so the autonomous write path is still closed, exactly as ADR 0001 intends:
   the pipeline is a prerequisite, and "cannot check" may never read as "pass".
4. **DONE (Bedrock half)** - `scripts/bedrock_provider.py` is the single egress
   path; `check_llm_backed()` now really calls Haiku and parses three verdict
   lines, where a missing, unrecognized or unparseable verdict is a FINDING (a
   check that did not run may never read as a pass). The `triage_links` stub and
   the local-only embed path are replaced. **The write path opens only once the
   operator points `OBSIDIAN_BEDROCK_*` + `AWS_REGION` at an account with
   Bedrock access** - the code no longer blocks it, configuration does.
   Dependency debt from step 1 also cleared here: `pyproject.toml` still
   declared `openai`, `google-genai`, `google-api-python-client`,
   `youtube-transcript-api` and `feedparser` for the deleted research/eval
   stack, so installing a "Bedrock-only" fork still pulled every vendor client
   it exists to avoid.
   **Account decision 2026-09-07 (operator, decision window): AWS 242201275909 / eu-west-1**,
   over 195; four-lens council `docs/council/2026-09-07-bedrock-account-242.md` (4x
   PASS-WITH-CONDITIONS; security and cost lenses dissent that 195 was safer). Model ids:
   generation `eu.anthropic.claude-sonnet-5`, guard `anthropic.claude-haiku-4-5-20251001-v1:0`,
   embeddings `amazon.titan-embed-text-v2:0`. Bedrock invocation logging in 242/eu-west-1
   read OFF the same day; leave it off for this workload. **Blocking before arming** (owed,
   each its own PR): scoped IAM role via a fork-owned Terraform root (local state); boto3
   `Config` timeouts + adaptive retries and a paced guard loop; promoted/quarantined counts in
   the `.claude-runs` JSONL; `dimensions` pinned in `embed()`; per-day iteration cap +
   escalation; AWS Budgets alarm (~$250/mo) and a `second-brain` bucket in the operator's
   242 billing report; a written answer to whether the headless `claude -p` generation is
   Bedrock-routed at all (`CLAUDE_CODE_USE_BEDROCK` is set nowhere here; if not, only the
   guard checks and embeddings land on the 242 bill). Bedrock write-path OPEN iff ALL hold:
   (1) `sts get-caller-identity` under the scoped role shows the role ARN, not the admin;
   (2) every model/profile id resolves via `get-foundation-model` / `get-inference-profile`;
   (3) one fixture Haiku guard call returns a parseable verdict (run twice: marketplace
   auto-subscribe); (4) `available(embeddings=True, guard=True)` is True; (5) a
   `promote_candidates.py --dry-run` over one hand-authored candidate quarantines or
   would-promote for the right reason. Date, role name and config commit go here when done.
5. **REMAINING** - pgvector store for the embedding index (ADR 0001 section 2:
   pgvector on an existing operator-managed RDS). Needs a real database plus a
   migration, so it is deliberately its own change; embeddings currently
   compute via Bedrock and are consumed in-process.

## Re-audit tax

Every upstream pull re-checks for reintroduced installers/pollers/egress **before**
merge - these are near upstream's core and WILL return. The pins make the check
mechanical; the review is still owed.
