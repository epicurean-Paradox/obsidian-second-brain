"""vault_guard.py - fail-closed write-root confinement + fence-diff guard.

Enforce layer of the fork hardening (FORK_HARDENING.md step 2; fork ADR 0001
section 3). Every machine write to a vault note routes through guard_write()
via note_io.write_exact and the MCP server's atomic writer. The rules:

  1. DERIVED_VAULT_ROOT is REQUIRED for any guarded write. Unset -> hard error.
     No cwd or home fallback: an undefined derived root means the L2 boundary
     is undefined, and an undefined boundary fails closed.
  2. A write whose real path is inside DERIVED_VAULT_ROOT (the L2 tree) is
     allowed unconditionally: L2 is the machine's tier.
  3. A write whose real path is inside any SSOT_VAULT_ROOTS entry (colon-
     separated; the L0/L1 trees) is allowed ONLY when the change is confined
     to the machine-owned link fence: every byte outside the fence markers
     must be identical before and after. Creating a NEW file in SSOT is never
     allowed.
  4. A write outside every declared root is not a vault write; the guard does
     not apply (exports, site builds, temp files).

The fence:

    <!-- L2:links start -->
    ...machine-owned wikilink block...
    <!-- L2:links end -->

Exactly zero or one fence per note. A malformed fence (unpaired or repeated
markers) fails closed - before AND after states must both be well-formed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Tuple

FENCE_START = "<!-- L2:links start -->"
FENCE_END = "<!-- L2:links end -->"


class VaultWriteError(RuntimeError):
    """A guarded write violated the confinement rules. Never catch-and-continue."""


def _required_derived_root() -> Path:
    raw = os.environ.get("DERIVED_VAULT_ROOT", "").strip()
    if not raw:
        raise VaultWriteError(
            "DERIVED_VAULT_ROOT is not set. The derived (L2) write root is "
            "required for any vault write; there is no cwd or home fallback "
            "(fork ADR 0001 section 3, fail-closed)."
        )
    root = Path(raw).expanduser()
    try:
        return root.resolve(strict=True)
    except FileNotFoundError:
        raise VaultWriteError(
            f"DERIVED_VAULT_ROOT does not exist: {root}. Refusing to invent it."
        ) from None


def _ssot_roots() -> List[Path]:
    raw = os.environ.get("SSOT_VAULT_ROOTS", "")
    roots = []
    for part in raw.split(":"):
        part = part.strip()
        if part:
            p = Path(part).expanduser()
            if p.exists():
                roots.append(p.resolve())
    return roots


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def split_fence(text: str) -> Optional[Tuple[str, str, str]]:
    """Split text into (before, fence-body, after); None if no fence.

    Raises VaultWriteError on a malformed fence (repeated or unpaired markers).
    """
    starts = text.count(FENCE_START)
    ends = text.count(FENCE_END)
    if starts == 0 and ends == 0:
        return None
    if starts != 1 or ends != 1:
        raise VaultWriteError(f"malformed link fence: {starts} start / {ends} end marker(s)")
    before, rest = text.split(FENCE_START, 1)
    body, after = rest.split(FENCE_END, 1)
    if "\n" not in body and body.strip():
        # tolerated: single-line fence body
        pass
    return (before, body, after)


def _prose_of(text: str) -> Tuple[str, str]:
    """The bytes OUTSIDE the fence, as a (before, after) pair. No-fence -> whole text."""
    parts = split_fence(text)
    if parts is None:
        return (text, "")
    return (parts[0], parts[2])


def guard_write(path: Path, new_text: str, old_text: Optional[str] = None) -> None:
    """Raise VaultWriteError unless writing new_text to path is permitted.

    old_text: current content of the note; pass what the caller already read.
    If None and the file exists, it is read here (strict UTF-8 via bytes).
    """
    real = path.expanduser()
    real = (real.parent.resolve() / real.name) if not real.exists() else real.resolve()

    ssot_roots = [r for r in _ssot_roots() if _is_inside(real, r)]
    derived_hit = False
    derived_root = None
    # Only consult DERIVED_VAULT_ROOT when the target is plausibly a vault
    # write: inside an SSOT root, or the derived root itself resolves and
    # contains the target. A completely unrelated path (exports, site build,
    # tempfiles) is out of scope for the guard.
    if ssot_roots:
        derived_root = _required_derived_root()  # required whenever vault writes happen
        derived_hit = _is_inside(real, derived_root)
    else:
        raw = os.environ.get("DERIVED_VAULT_ROOT", "").strip()
        if raw:
            candidate = Path(raw).expanduser()
            if candidate.exists() and _is_inside(real, candidate.resolve()):
                derived_hit = True

    if derived_hit:
        # L2 wins even when the derived root is nested inside a declared SSOT
        # umbrella (the vault/raw + vault/wiki layout): the derived root is by
        # definition the machine's tier. Declare SSOT roots at tier grain
        # (vault/raw), not vault grain, to avoid relying on this precedence.
        return

    if not ssot_roots:
        return  # not a vault path at all.

    # SSOT target: only a fence-confined change to an EXISTING note may pass.
    if not real.exists():
        raise VaultWriteError(
            f"refusing to create a new note inside SSOT root: {real} "
            "(prose flows down: humans author L0, sync authors L1)"
        )
    if old_text is None:
        try:
            old_text = real.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            raise VaultWriteError(
                f"SSOT note is not valid UTF-8, refusing to touch it: {real}"
            ) from None

    old_prose = _prose_of(old_text)
    new_prose = _prose_of(new_text)
    if old_prose != new_prose:
        raise VaultWriteError(
            f"write to SSOT note {real} changes bytes OUTSIDE the L2 link fence; "
            "machine writes may only touch the fenced block "
            f"({FENCE_START} ... {FENCE_END})"
        )
