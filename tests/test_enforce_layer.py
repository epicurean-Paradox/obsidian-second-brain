"""Enforce-layer tests (fork ADR 0001 section 3): write-root confinement,
fence-diff guard, and the layer linter. Red-first: every rule has a fixture
that MUST be blocked and a clean one that MUST pass. Wrong behaviour these
catch: a machine write eating hand-authored SSOT prose, a write with no
declared derived root sailing through, a linter that lints nothing and
reports success.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from layer_lint import lint_layers  # noqa: E402
from vault_guard import (  # noqa: E402
    FENCE_END,
    FENCE_START,
    VaultWriteError,
    guard_write,
    split_fence,
)

FENCED = f"# Note\n\nHand prose.\n\n{FENCE_START}\n[[a]]\n{FENCE_END}\n"


@pytest.fixture
def roots(tmp_path, monkeypatch):
    ssot = tmp_path / "raw"
    derived = tmp_path / "wiki"
    ssot.mkdir()
    derived.mkdir()
    monkeypatch.setenv("SSOT_VAULT_ROOTS", str(ssot))
    monkeypatch.setenv("DERIVED_VAULT_ROOT", str(derived))
    return ssot, derived


def test_l2_write_allowed(roots):
    _, derived = roots
    guard_write(derived / "new.md", "machine tier")  # must not raise


def test_ssot_prose_write_blocked(roots):
    ssot, _ = roots
    note = ssot / "precedent.md"
    note.write_text(FENCED, encoding="utf-8")
    with pytest.raises(VaultWriteError, match="OUTSIDE the L2 link fence"):
        guard_write(note, FENCED.replace("Hand prose.", "machine prose."))


def test_ssot_fence_only_change_allowed(roots):
    ssot, _ = roots
    note = ssot / "precedent.md"
    note.write_text(FENCED, encoding="utf-8")
    guard_write(note, FENCED.replace("[[a]]", "[[a]]\n[[b]]"))  # must not raise


def test_ssot_new_file_blocked(roots):
    ssot, _ = roots
    with pytest.raises(VaultWriteError, match="new note inside SSOT"):
        guard_write(ssot / "brand-new.md", "anything")


def test_unset_derived_root_fails_closed(roots, monkeypatch):
    ssot, _ = roots
    note = ssot / "precedent.md"
    note.write_text(FENCED, encoding="utf-8")
    monkeypatch.delenv("DERIVED_VAULT_ROOT")
    with pytest.raises(VaultWriteError, match="DERIVED_VAULT_ROOT"):
        guard_write(note, FENCED.replace("[[a]]", "[[b]]"))


def test_malformed_fence_fails_closed(roots):
    ssot, _ = roots
    note = ssot / "precedent.md"
    note.write_text(FENCED + FENCE_START + "\n", encoding="utf-8")  # 2 starts
    with pytest.raises(VaultWriteError, match="malformed link fence"):
        guard_write(note, FENCED)


def test_nested_derived_root_wins(tmp_path, monkeypatch):
    # vault/raw + vault/wiki layout with SSOT declared at VAULT grain: a write
    # inside wiki/ must still be treated as L2, not fenced.
    vault = tmp_path / "vault"
    (vault / "wiki").mkdir(parents=True)
    monkeypatch.setenv("SSOT_VAULT_ROOTS", str(vault))
    monkeypatch.setenv("DERIVED_VAULT_ROOT", str(vault / "wiki"))
    guard_write(vault / "wiki" / "syn.md", "machine tier")  # must not raise


def test_non_vault_path_out_of_scope(tmp_path, monkeypatch):
    monkeypatch.delenv("SSOT_VAULT_ROOTS", raising=False)
    monkeypatch.delenv("DERIVED_VAULT_ROOT", raising=False)
    guard_write(tmp_path / "export.md", "not a vault")  # must not raise


def test_write_exact_routes_through_guard(roots):
    ssot, _ = roots
    note = ssot / "precedent.md"
    note.write_text(FENCED, encoding="utf-8")
    from note_io import write_exact

    with pytest.raises(VaultWriteError):
        write_exact(note, FENCED.replace("Hand prose.", "eaten"))
    assert note.read_text(encoding="utf-8") == FENCED  # original untouched


def test_split_fence_none_when_absent():
    assert split_fence("no fence here") is None


# -- layer linter ---------------------------------------------------------------


def _note(root, name, layer=None, body="text"):
    fm = f"---\nlayer: {layer}\n---\n" if layer else "---\ntitle: x\n---\n"
    (root / name).write_text(fm + body, encoding="utf-8")


def test_linter_passes_on_labeled_vault(tmp_path):
    _note(tmp_path, "a.md", "L0")
    _note(tmp_path, "b.md", "L2")
    assert lint_layers(tmp_path) == []


def test_linter_fails_on_missing_layer(tmp_path):
    _note(tmp_path, "a.md", "L0")
    _note(tmp_path, "bad.md", None)
    errors = lint_layers(tmp_path)
    assert any("bad.md" in e and e.startswith("E1") for e in errors)


def test_linter_fails_closed_on_zero_notes(tmp_path):
    errors = lint_layers(tmp_path)
    assert any(e.startswith("E2") for e in errors)
