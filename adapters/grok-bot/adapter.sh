#!/usr/bin/env bash
# =============================================================================
# adapters/grok-bot/adapter.sh - Grok Bot / Sand platform adapter
# =============================================================================
# Grok Bot (aka Sand) reads the obsidian-second-brain MCP server for vault I/O
# and runs SKILL.md workflow files for playbooks. This adapter compiles the
# platform-neutral commands/ into Grok-runnable SKILL.md files.
#
# Emits, at the dist root:
#   skills/<name>/SKILL.md        - one skill per command (45; calendar is
#                                   excluded). Frontmatter is name + description
#                                   (when to use). Body tells the agent to use
#                                   MCP obsidian_* tools for all vault I/O.
#   skills/obsidian-core/         - the shared engine skill: references/,
#                                   scripts/, and pyproject.toml. The command
#                                   skills' `uv run --directory SKILL_ROOT ...`
#                                   invocations are rewritten to point here.
#   INSTALL.md                    - how to load skills on Grok Bot / Sand.
#
# Design notes:
#   - Each skill body opens with MCP vault I/O instructions and a vault-root
#     resolution preamble so skills are self-sufficient.
#   - references/ai-first-rules.md is embedded in every command skill so the
#     non-negotiable write spec survives even a cherry-picked install.
#   - The trigger policy (proactive vs explicit) is encoded in each description.
#   - Grok Bot has no hook runtime, so no SessionStart or PostToolUse hooks.
# =============================================================================

GROK_PLATFORM="grok-bot"
GROK_SKILLS_DIR="skills"
GROK_CORE="obsidian-core"
# Workspace-relative location of the shared engine skill once installed.
GROK_CORE_PATH=".agents/skills/${GROK_CORE}"

adapter_build() {
  local src="$1" dst="$2"

  _grok_emit_skills "$src/commands" "$dst/$GROK_SKILLS_DIR" "$src/references/ai-first-rules.md"
  _grok_emit_core "$src" "$dst/$GROK_SKILLS_DIR/$GROK_CORE"
  _grok_emit_install_hint "$dst"
}

# Emit one Grok Bot skill per command at skills/<name>/SKILL.md.
_grok_emit_skills() {
  local src="$1" dst="$2" ai_rules="$3"
  [[ -d "$src" ]] || return 0
  local f name desc triggers category trigmode trig_clean out
  for f in "$src"/*.md; do
    [[ -f "$f" ]] || continue
    should_include "$f" "$GROK_PLATFORM" || continue

    name="$(basename "$f" .md)"
    desc="$(parse_frontmatter "$f" description)"
    triggers="$(parse_frontmatter "$f" triggers_en)"
    category="$(parse_frontmatter "$f" category)"
    trigmode="$(parse_frontmatter "$f" trigger-mode)"
    [[ -z "$category" ]] && category="other"
    [[ -z "$desc" ]] && desc="Run the $name command of the obsidian-second-brain skill."
    desc="$(strip_quotes "$desc")"

    # Fold English triggers into the description for implicit selection.
    if [[ -n "$triggers" ]]; then
      trig_clean="$(format_triggers "$triggers")"
      [[ -n "$trig_clean" ]] && desc="$desc Triggers: $trig_clean."
    fi

    # Encode the selection policy - the lever these platforms read.
    desc="$(with_trigger_policy "$desc" "$trigmode")"

    mkdir -p "$dst/$name"
    out="$dst/$name/SKILL.md"
    {
      echo "---"
      echo "name: $name"
      printf 'description: "%s"\n' "${desc//\"/\\\"}"
      echo "---"
      echo
      _grok_preamble
      command_body "$f"
      echo
      echo "---"
      echo
      echo "## AI-first vault rule (embedded)"
      echo
      echo "The write spec below is non-negotiable for every note this skill creates or"
      echo "updates. It is embedded here so it applies even on a partial install."
      echo
      cat "$ai_rules"
    } > "$out"

    rewrite_tool_neutral "$out"
    rewrite_skill_root "$out" "$GROK_CORE_PATH"
    # Bare `references/...` paths in command prose resolve against the installed
    # obsidian-core skill, not the harness CWD.
    rewrite_platform_paths "$out" "${GROK_CORE_PATH#.}"
  done
}

# The self-sufficiency preamble prepended to every command skill body.
_grok_preamble() {
  cat <<EOF
## Setup (read first)

**MCP vault I/O.** This skill works with the \`user-obsidian-second-brain\` MCP
server, which provides \`obsidian_*\` tools for vault operations. Use these MCP
tools for all vault I/O:

- \`obsidian_search\` - search the vault (lexical + semantic if index exists)
- \`obsidian_read_note\` - read a note by path
- \`obsidian_save_note\` - create a new note (writes to Inbox/ by default)
- \`obsidian_update_note\` - append to or update fields in an existing note
- \`obsidian_replace_note_section\` - replace a heading section
- \`obsidian_move_note\` - move or rename a note
- \`obsidian_capture\` - quick-capture an idea (minimal schema)
- \`obsidian_validate_note\` - validate a note against the AI-first spec
- \`obsidian_backlinks\` - find notes linking to a target
- \`obsidian_vault_health\` - run a full vault health check
- \`obsidian_list_skills\` - list available obsidian-second-brain skills
- \`obsidian_get_skill\` - get the instructions for a specific skill

**After writing any note, always call \`obsidian_validate_note\` with the path**
to ensure it meets the AI-first spec. The validator will report any issues.

**Vault root.** Resolve it before reading or writing: use the \`\$OBSIDIAN_VAULT_PATH\`
environment variable if it is set, otherwise use your current working directory.
Read \`_CLAUDE.md\` at the vault root first if it exists - it holds the user's vault
conventions (folder map, daily-note format, naming).

**Shared engine.** Script and reference paths below point at \`${GROK_CORE_PATH}\` -
the \`${GROK_CORE}\` skill installed alongside this one. Run script commands from your
workspace root so that relative path resolves; if you installed skills globally, use
the absolute path to the installed \`${GROK_CORE}\` directory instead.

EOF
}

# Emit the shared obsidian-core skill: a SKILL.md (so it lands in .agents/skills/)
# plus the references/, scripts/, and pyproject.toml the command skills call into.
_grok_emit_core() {
  local src="$1" dst="$2"
  mkdir -p "$dst"

  # references/
  if [[ -d "$src/references" ]]; then
    mkdir -p "$dst/references"
    cp -R "$src/references/." "$dst/references/"
  fi
  # scripts/ + pyproject.toml (self-contained uv project)
  if [[ -d "$src/scripts" ]]; then
    mkdir -p "$dst/scripts"
    cp -R "$src/scripts/." "$dst/scripts/"
  fi
  [[ -f "$src/pyproject.toml" ]] && cp "$src/pyproject.toml" "$dst/pyproject.toml"

  # SKILL.md - carries the discovery frontmatter; instructs not to invoke directly.
  cat > "$dst/SKILL.md" <<EOF
---
name: ${GROK_CORE}
description: "Shared engine for the obsidian-second-brain skills - the AI-first write spec (references/), the Python research + health toolkit (scripts/), and its uv project (pyproject.toml). Support files only; the other skills call into it. Do not invoke directly. Install it alongside the command skills."
---

## What this is

The shared support tree the other obsidian-second-brain skills depend on. It is
not a task skill - do not run it on its own.

- \`references/\` - shared specs. \`references/ai-first-rules.md\` is the canonical,
  non-negotiable vault-write spec; \`vault-schema.md\`, \`folder-map.md\`, and
  \`freshness-policy.md\` back the other skills. These paths are relative to the
  install root, which is load-bearing: if one does not resolve from your working
  directory, search upward for it, and say so before writing if you still cannot
  read it. Every command skill also embeds the AI-first spec inline, so the rule
  survives an unreachable path - but an unreachable path must never pass in
  silence.
- \`scripts/\` - Python helpers for the research toolkit and vault health. The
  command skills invoke them as
  \`uv run --directory ${GROK_CORE_PATH} -m scripts.research.<name> ...\`
  (or \`uv run --directory ${GROK_CORE_PATH} scripts/<name>.py ...\`), run from
  your workspace root.
- \`pyproject.toml\` - makes this directory a self-contained uv project, so both
  modules and dependencies resolve without a separate install step.

If you installed the skills globally rather than into a workspace, replace
\`${GROK_CORE_PATH}\` in those commands with the absolute path to this directory.
EOF
}

_grok_emit_install_hint() {
  local dst="$1"
  # Computed count, not hardcoded - stays correct as commands are added/excluded.
  local GROK_CMD_COUNT=0
  GROK_CMD_COUNT="$(find "$dst/$GROK_SKILLS_DIR" -mindepth 1 -maxdepth 1 -type d \
                    ! -name "$GROK_CORE" 2>/dev/null | wc -l | tr -d ' ')"
  cat > "$dst/INSTALL.md" <<EOF
# Install on Grok Bot / Sand

This build compiles the obsidian-second-brain commands into SKILL.md workflow
files that Grok Bot and Sand agents can run. The MCP server
(\`user-obsidian-second-brain\`) provides the vault I/O layer; the compiled
skills are the playbooks.

The tree contains \`skills/<name>/SKILL.md\` (${GROK_CMD_COUNT} command skills) plus the shared
\`skills/${GROK_CORE}/\` engine skill (references, scripts, pyproject).

## Prerequisites

1. **MCP server connected.** Grok Bot already has the \`user-obsidian-second-brain\`
   MCP server available. Verify it by checking that MCP tools like
   \`obsidian_search\`, \`obsidian_read_note\`, and \`obsidian_save_note\` are
   accessible in your Grok Bot session.

2. **Vault path configured.** The MCP server needs to know your vault location.
   Set the \`OBSIDIAN_VAULT_PATH\` environment variable to point to your vault
   root, either in your shell environment or in the Grok Bot configuration.

## Installation

Grok Bot and Sand load skills from the workspace \`.agents/skills/\` directory.
Copy the compiled skills tree into your workspace:

\`\`\`bash
# From the repo root, after: bash scripts/build.sh --platform grok-bot
mkdir -p /path/to/your/workspace/.agents/skills
cp -R dist/grok-bot/skills/. /path/to/your/workspace/.agents/skills/
\`\`\`

Alternatively, if your Grok Bot or Sand setup supports a global skills directory,
copy the skills there:

\`\`\`bash
mkdir -p ~/.agents/skills
cp -R dist/grok-bot/skills/. ~/.agents/skills/
\`\`\`

## Verification

After installation, verify the skills are loaded:

1. Start your Grok Bot or Sand session in the workspace (or globally if installed
   globally)
2. Ask the agent to list available skills - you should see \`obsidian-save\`,
   \`obsidian-find\`, \`obsidian-daily\`, and others
3. Try a simple command: "Search my vault for project notes" or "Save this
   conversation to my vault"

The agent will use the MCP \`obsidian_*\` tools under the hood to interact with
your vault.

## What is NOT covered

This build provides the command skills only. It does NOT include:

- **Hooks** - Grok Bot has no hook runtime. There are no SessionStart or
  PostToolUse hooks. The skills are self-contained and do not rely on hooks.
- **Scheduled agents** - The morning/nightly/weekly/health routines are not
  included in this build. They remain a Claude Code / Hermes extra.
- **Calendar command** - \`/obsidian-calendar\` requires the Google Calendar MCP
  and is excluded from this build. It ships on Claude Code only.

## How it works

- **MCP is the I/O layer.** Every vault read, write, search, or validation goes
  through the \`user-obsidian-second-brain\` MCP server's \`obsidian_*\` tools.
  The skills tell the agent which tool to call and how to structure the data.
- **Compiled skills are the playbooks.** Each SKILL.md carries the full operating
  instructions for one command (e.g. \`/obsidian-save\`, \`/obsidian-find\`). The
  agent reads the skill, follows the instructions, and uses the MCP tools to
  execute.
- **AI-first rule embedded.** Every skill includes the complete AI-first vault
  write spec inline, so the non-negotiable formatting rules apply even if you
  only install a subset of skills.

## Usage

Once installed, invoke skills by name or let the agent match them implicitly
based on your request:

- "Save this conversation to my vault" → triggers \`obsidian-save\`
- "Find notes about the new project" → triggers \`obsidian-find\`
- "What's on my daily note today?" → triggers \`obsidian-daily\`
- "Create a new project note" → triggers \`obsidian-project\`

The agent will handle the MCP calls, format the notes according to the AI-first
spec, and validate the output automatically.
EOF
}
