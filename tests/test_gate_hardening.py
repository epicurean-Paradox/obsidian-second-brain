"""Gate-hardening pins (FORK_HARDENING.md) - each fails on upstream v0.14.0.

These are the merge gates keeping the strip stripped: an upstream pull that
reintroduces an installer, a poller, an agent-config writer, or direct-vendor
egress goes red here before any human forgets to look.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

STRIPPED_PATHS = [
    "install.sh",
    "update.sh",
    "scripts/quick-install.sh",
    "scripts/setup.sh",
    "scripts/setup_settings_hook.py",
    "scripts/install-codex-wrappers.sh",
    "scripts/research",
    "scripts/eval",
    "scripts/build.sh",
    "scripts/run-command.sh",
    "adapters",
    "integrations/telegram-journal",
]

VENDOR_HOSTS = re.compile(
    r"api\.anthropic\.com|api\.openai\.com|api\.x\.ai|perplexity\.ai"
    r"|tavily|search\.brave\.com|generativelanguage\.googleapis"
)

AGENT_CONFIG_WRITES = re.compile(
    r"(~|\$HOME)/\.claude/(settings\.json|skills|commands)|\.gemini/|\.codex/"
)

# A headless agent invocation is the moment model output stops being data and
# starts being able to write. Every one of these has to sit behind the OWASP
# staging gate, whichever harness it drives.
HEADLESS_AGENT_RUNNER = re.compile(
    # Named harnesses, matched INVOCATION-shaped (binary + subcommand/flag).
    # Deliberately not the bare binary name: `.opencode` and `.hermes` appear in
    # the vault-scanner exclusion lists (vault_ops.py, vault_scan.py), which is a
    # directory to skip, not a command to run. A pin that fires on those gets
    # muted, and a muted pin guards nothing.
    r"\bhermes\s+\S"
    r"|\bopencode\s+run\b"
    r"|\bcodex\s+exec\b"
    r"|\bgemini\s+(-p|--prompt)\b"
    r"|\bpi\s+run\b"
    # Claude's own headless mode.
    r"|\bclaude\s+(-p|--print)\b"
    # Indirection: the stripped Hermes hook ran `$CONSOLIDATE_CMD "$PROMPT"`, so
    # the binary name never appeared on the invoking line. Catch the shape.
    r"|\$\{?[A-Z_]*(CMD|COMMAND|RUNNER)[A-Z_]*\}?\s+\"?\$"
)

# LIMITATION, stated rather than implied: this is a grep over source text, not a
# taint analysis. It catches the harnesses named above and the common
# variable-indirection shape; it does not catch an unnamed future binary, or a
# command assembled from pieces at runtime. It raises the cost of adding a second
# ungated writer and does not make it impossible -- the review is still owed on
# every upstream pull (see "Re-audit tax").

# The build system PR #1 deleted. An executable still reaching for it is dead
# code that reads as live, and it is dead code shaped like the strip class.
STRIPPED_BUILD_SYSTEM = re.compile(r"adapters/|scripts/build\.sh|scripts/lib\.sh")


def _tracked_executable_files():
    out = subprocess.run(
        ["git", "ls-files", "*.py", "*.sh"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [REPO / p for p in out if (REPO / p).exists()]


def test_stripped_paths_stay_stripped():
    present = [p for p in STRIPPED_PATHS if (REPO / p).exists()]
    assert present == [], f"stripped paths reappeared: {present}"


def test_no_executable_writes_agent_config():
    offenders = []
    for f in _tracked_executable_files():
        if f.name == "test_gate_hardening.py":
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            code = line.split("#", 1)[0]  # comments may DESCRIBE the ban
            if AGENT_CONFIG_WRITES.search(code):
                offenders.append(f"{f.relative_to(REPO)}:{i}")
    assert offenders == [], f"agent-config path in executable code: {offenders}"


def test_zero_direct_vendor_hosts_in_executable_code():
    offenders = []
    for f in _tracked_executable_files():
        if f.name == "test_gate_hardening.py":
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            code = line.split("#", 1)[0]
            if VENDOR_HOSTS.search(code):
                offenders.append(f"{f.relative_to(REPO)}:{i}")
    assert offenders == [], f"direct-vendor host in executable code: {offenders}"


def test_no_launchd_poller_artifacts():
    plists = list(REPO.rglob("*.plist*"))
    plists = [p for p in plists if ".git" not in p.parts]
    assert plists == [], f"launchd artifacts present: {plists}"


def test_triage_llm_path_never_silently_defaults():
    """No silent LLM path: with Bedrock unconfigured, ask_claude RAISES.

    Superseded mechanism, same intent as the original step-1 pin. That pin
    asserted a NotImplementedError stub; the Bedrock provider replaced the
    stub, so the durable property is asserted instead -- an unavailable
    classifier must fail loudly, never return a plausible KEEP verdict that
    quietly retains broken links forever.
    """
    import importlib.util
    import os
    import sys

    sys.path.insert(0, str(REPO / "scripts"))
    for var in ("OBSIDIAN_BEDROCK_MODEL_ID", "OBSIDIAN_BEDROCK_GUARD_MODEL_ID"):
        os.environ.pop(var, None)
    spec = importlib.util.spec_from_file_location(
        "triage_links", REPO / "scripts" / "triage_links.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    try:
        mod.ask_claude("note", "line", "link", "key")
    except RuntimeError:
        return
    raise AssertionError("ask_claude did not raise: a silent LLM path exists")


def test_bg_agent_kept():
    # The strip must not silently lose the operator-retained autonomous writer;
    # it is kept-and-scoped (ADR 0001), not deleted.
    assert (REPO / "hooks" / "obsidian-bg-agent.sh").exists()


def test_embed_backend_is_local_only():
    src = (REPO / "integrations" / "obsidian-mcp-server" / "vault_ops.py").read_text(
        encoding="utf-8"
    )
    assert '_EMBED_BACKEND != "ollama"' in src, "remote embed backend guard missing"
    assert "127.0.0.1" in src and "localhost" in src, "localhost pin missing"


def _tracked_text_files():
    """Every git-tracked file that decodes as UTF-8 text (docs, scripts, configs)."""
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.split()
    files = []
    for rel in out:
        path = REPO / rel
        if not path.is_file() or path.suffix in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".woff", ".woff2"}:
            continue
        files.append(path)
    return files


# --- Pins 7 and 8: council 2026-09-07 (docs/council/2026-09-07-bedrock-account-242.md) ---

_HOOK = REPO / "hooks" / "obsidian-bg-agent.sh"
_ALLOWED_TOOLS = '--allowedTools "Read,Write,Edit,Glob,Grep"'
_ARMING_VARS = ("OBSIDIAN_BG_AGENT_ENABLED",)
_GLOBAL_SETTINGS = "~/.claude/settings.json"


def test_headless_writer_tool_surface_is_pinned():
    """Pin 7. The headless `claude -p` call must keep `--strict-mcp-config` and exactly the
    filesystem-only tool list. Fails if Bash (or anything else) is added to --allowedTools,
    if the list is dropped, or if MCP loading is re-enabled: that flag is the boundary between
    model output as inert data and model output that can act."""
    src = _HOOK.read_text(encoding="utf-8")
    invocation = [l for l in src.splitlines() if "claude " in l and "-p" in l or "--allowedTools" in l]
    assert any("--strict-mcp-config" in l for l in src.splitlines() if l.lstrip().startswith("claude ")), (
        "headless claude invocation lost --strict-mcp-config"
    )
    assert _ALLOWED_TOOLS in src, f"headless claude invocation lost {_ALLOWED_TOOLS}"
    for line in invocation:
        if "--allowedTools" in line:
            assert "Bash" not in line and "WebFetch" not in line and "mcp__" not in line, line


def test_no_committed_file_arms_bg_agent_via_global_settings():
    """Pin 8. The arming flag belongs in the vault project's own .claude/settings.json.
    Any committed text (outside this test) that names the user-global settings file within
    three lines of OBSIDIAN_BG_AGENT_ENABLED fails: PostCompact fires on every session's
    compaction, so a globally set flag feeds unrelated projects' summaries to the writer.
    The vault PATH alone arms nothing, so per-project vault-path docs are not in scope;
    docs/council/ records are excluded because they quote the anti-pattern as evidence."""
    offenders: list[str] = []
    for f in _tracked_text_files():
        if f.resolve() == Path(__file__).resolve():
            continue
        # Council records quote the anti-pattern verbatim as evidence; they are the
        # reason this pin exists, not an install instruction.
        if "docs/council/" in f.relative_to(REPO).as_posix():
            continue
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for i, line in enumerate(lines):
            if _GLOBAL_SETTINGS not in line:
                continue
            window = " ".join(lines[max(0, i - 3): i + 4])
            if any(v in window for v in _ARMING_VARS):
                offenders.append(f"{f.relative_to(REPO)}:{i + 1}")
    assert not offenders, "global settings named next to an arming variable: " + ", ".join(offenders)


# --- Pins 9-11: no second unattended writer, whatever harness it drives ------


def test_no_unattended_writer_bypasses_the_owasp_gate():
    """Pin 9. The bg-agent is the ONLY unattended vault writer, and it writes to
    staging where `promote_candidates.py` is the single path in.

    Failure this closes: `hooks/obsidian-hermes-session-end.sh` drove `hermes -z`
    against the vault directly on `on_session_end` -- no staging root, no
    promoter, no `vault_guard`, and no tool-surface restriction. Its only
    constraint on what the model could write was a sentence in its own prompt
    ("add/update/link only - never delete"), which is a request, not a gate. One
    flag (`OBSIDIAN_HERMES_HOOK_ENABLED=1`) armed it, and no pin watched that
    flag -- exactly the single-misconfiguration shape the 2026-09-07 council
    named as C1b for the Claude side.

    Generalised deliberately: this catches the NEXT harness someone adds, not
    just Hermes.
    """
    offenders = []
    for path in _tracked_executable_files():
        src = path.read_text(encoding="utf-8", errors="ignore")
        if not HEADLESS_AGENT_RUNNER.search(src):
            continue
        gated = "OBSIDIAN_STAGING_ROOT" in src and "promote_candidates" in src
        if not gated:
            offenders.append(path.relative_to(REPO).as_posix())

    assert not offenders, (
        "these invoke a headless agent without routing through the OWASP staging "
        f"gate (OBSIDIAN_STAGING_ROOT + promote_candidates): {offenders}. An "
        "unattended writer that reaches the vault directly makes the ten-check "
        "pipeline decorative."
    )


def test_no_non_claude_harness_hook_artifacts():
    """Pin 10. The harness-runner class stays stripped on the hooks surface too.

    PR #1 deleted `adapters/` (every platform adapter) and the Codex runner, but
    left two Hermes artifacts behind in `hooks/` -- a session-end writer and a
    paste-in config template that told the reader to install it into
    `~/.hermes/agent-hooks/`, i.e. another agent's config directory.
    """
    forbidden = [
        "hooks/obsidian-hermes-session-end.sh",
        "hooks/hermes-hooks.config.example.yaml",
        "hooks/hermes-hooks.cli-config.example.yaml",
        "scripts/update-vault-integration.sh",
    ]
    present = [p for p in forbidden if (REPO / p).exists()]
    assert not present, f"harness-runner artifacts are back: {present}"


def test_no_executable_reaches_for_the_stripped_build_system():
    """Pin 11. Dead-strip integrity.

    `scripts/update-vault-integration.sh` shelled out to `scripts/build.sh` and
    gated on `adapters/$PLATFORM/adapter.sh`, both deleted in PR #1 -- so it
    could only ever die at its own guard, while reading like a live install path
    (and `llms.txt` told people to run it). `scripts/lib.sh` was sourced by that
    same deleted build script and by nothing else.
    """
    offenders = []
    for path in _tracked_executable_files():
        rel = path.relative_to(REPO).as_posix()
        # The pins themselves name the stripped paths -- that is their job.
        if rel.startswith("tests/"):
            continue
        src = path.read_text(encoding="utf-8", errors="ignore")
        if STRIPPED_BUILD_SYSTEM.search(src):
            offenders.append(rel)

    assert not offenders, (
        f"these reference the stripped build system: {offenders}. Dead code that "
        "reads as a live install path is worse than no code."
    )
