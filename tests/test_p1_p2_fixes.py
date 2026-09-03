"""Fences for defects that reach a real user.

  B30 heal_links --apply counted a fix that changed nothing, then tripped its
      own no-progress guard and abandoned every remaining safe fix
  B18 SKILL.md called the ASCII hyphen an em dash, so an agent following it
      literally produced filenames that no wikilink can resolve
  B33 the documented set_fields example was a silent soft-delete

(The B31 SSRF fences for the research podcast fetcher, the B22 build.sh
bytecode fences, and the B34 retrieval-eval fence were removed with their
subjects: scripts/research/, scripts/build.sh, and scripts/eval/ are deleted
in this hardened fork.)
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "integrations" / "obsidian-mcp-server"))


# --- B18 -------------------------------------------------------------------


def test_skill_md_does_not_call_the_hyphen_an_em_dash():
    src = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "(em dash)" not in src, (
        "SKILL.md labels the ASCII hyphen an em dash. An agent following it "
        "literally writes a filename no wikilink can resolve, and the write-time "
        "validator only checks content, not filenames"
    )
    assert "Never an em dash" in src


# --- B33 -------------------------------------------------------------------


def test_update_note_reports_a_retrieval_affecting_status(tmp_path, monkeypatch):
    v = tmp_path / "vault"
    v.mkdir()
    (v / "n.md").write_text("---\ntype: note\n---\n\nbody\n", encoding="utf-8")
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(v))
    import importlib

    import vault_ops

    importlib.reload(vault_ops)

    quiet = vault_ops.update_note("n.md", set_fields={"owner": "alex"})
    assert "faded" not in quiet, "an ordinary field should not warn"

    faded = vault_ops.update_note("n.md", set_fields={"status": "done"})
    assert "faded" in faded, (
        "setting a stale status de-ranks the note in every future search and said "
        "nothing about it, which is closer to archiving than to labelling"
    )


def test_the_documented_example_is_not_a_soft_delete():
    src = (REPO_ROOT / "integrations" / "obsidian-mcp-server" / "server.py").read_text(
        encoding="utf-8"
    )
    assert '{"status": "done"}' not in src, (
        "the tool's own example told the agent to set a status that fades the note"
    )


# --- B30 -------------------------------------------------------------------


def test_heal_links_does_not_count_a_rewrite_that_changed_nothing():
    src = (REPO_ROOT / "scripts" / "heal_links.py").read_text(encoding="utf-8")
    assert "text, _ = _rewrite(" not in src, (
        "apply_loop discards the replacement count, so an anchored or aliased "
        "link reports a fix, writes identical bytes, then trips the no-progress "
        "guard and abandons the remaining safe fixes"
    )
    assert "if n == 0:" in src
