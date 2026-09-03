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


def test_triage_llm_path_raises_until_bedrock():
    import importlib.util
    import sys

    sys.path.insert(0, str(REPO / "scripts"))  # triage_links imports note_io
    spec = importlib.util.spec_from_file_location(
        "triage_links", REPO / "scripts" / "triage_links.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    try:
        mod.ask_claude("note", "line", "link", "key")
    except NotImplementedError:
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
