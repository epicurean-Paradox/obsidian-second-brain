#!/usr/bin/env python3
"""layer_lint.py - every vault note declares its tier; fail-closed.

Enforce layer of the fork hardening (fork ADR 0001 section 3, item 4). Run
against a VAULT root (pre-commit or CI on the vault repo):

    python layer_lint.py <vault-root>

Rules:
  E1  every .md note carries frontmatter `layer: L0|L1|L2`
  E2  a linter run that parses ZERO notes fails (a linter that lints nothing
      is the SOFT trap it exists to prevent)
  E3  with --changed <file>... (the pre-commit form): a changed L0/L1 note is
      an error unless the change is confined to the L2 link fence, verified
      byte-wise against --base-ref (default HEAD) via git show.

Exit codes: 0 pass, 1 violations, 2 usage/unreadable.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vault_guard import VaultWriteError, _prose_of  # noqa: E402

LAYER_RE = re.compile(r"^layer:\s*(L0|L1|L2)\s*$", re.MULTILINE)
EXCLUDED_DIRS = {".git", ".obsidian", "node_modules"}


def note_layer(text: str) -> str | None:
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    m = LAYER_RE.search(text[: end + 4])
    return m.group(1) if m else None


def iter_notes(root: Path):
    for p in sorted(root.rglob("*.md")):
        if any(part in EXCLUDED_DIRS for part in p.parts):
            continue
        yield p


def lint_layers(root: Path) -> list[str]:
    errors, seen = [], 0
    for p in iter_notes(root):
        seen += 1
        try:
            text = p.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"E1 {p}: not valid UTF-8")
            continue
        if note_layer(text) is None:
            errors.append(f"E1 {p}: missing frontmatter 'layer: L0|L1|L2'")
    if seen == 0:
        errors.append(f"E2 {root}: zero notes parsed (fail-closed)")
    return errors


def lint_changed(root: Path, files: list[str], base_ref: str) -> list[str]:
    errors = []
    for rel in files:
        p = (root / rel).resolve()
        if p.suffix != ".md" or not p.exists():
            continue
        text = p.read_bytes().decode("utf-8", errors="replace")
        layer = note_layer(text)
        if layer in (None, "L2"):
            continue  # L2 is the machine tier; missing layer is caught by E1
        try:
            base = subprocess.run(
                ["git", "show", f"{base_ref}:{rel}"],
                cwd=root,
                capture_output=True,
                check=True,
            ).stdout.decode("utf-8")
        except subprocess.CalledProcessError:
            errors.append(f"E3 {rel}: new {layer} note in a tool commit (humans author L0/L1)")
            continue
        try:
            if _prose_of(base) != _prose_of(text):
                errors.append(f"E3 {rel}: {layer} prose changed outside the L2 link fence")
        except VaultWriteError as exc:
            errors.append(f"E3 {rel}: {exc}")
    return errors


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", type=Path)
    ap.add_argument(
        "--changed", nargs="*", default=None, help="repo-relative changed files (pre-commit form)"
    )
    ap.add_argument("--base-ref", default="HEAD")
    args = ap.parse_args(argv)
    if not args.root.is_dir():
        print(f"layer_lint: not a directory: {args.root}", file=sys.stderr)
        return 2
    errors = lint_layers(args.root)
    if args.changed is not None:
        errors += lint_changed(args.root, args.changed, args.base_ref)
    for e in errors:
        print(f"ERROR {e}")
    print(f"layer_lint: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
