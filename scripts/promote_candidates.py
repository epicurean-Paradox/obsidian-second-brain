#!/usr/bin/env python3
"""promote_candidates.py - the only path from the autonomous writer to the vault.

The writer (hooks/obsidian-bg-agent.sh) writes CANDIDATES into a staging root
and never touches the vault. This script walks the staging root, runs every
candidate through the OWASP ten-check gate (scripts/owasp_pipeline.py), and:

  * clean pass  -> committed to the vault via note_io.write_exact, which routes
                   through vault_guard (write-root confinement + fence-diff);
  * any finding -> moved to ``<derived>/_review/`` next to a ``.findings.json``
                   sidecar, for a human. It never reaches L0/L1.

Usage:
    promote_candidates.py --staging <dir> [--dry-run]

Environment (all required; unset = hard error, per ADR 0001 section 3):
    DERIVED_VAULT_ROOT   the L2 tree candidates may be committed into
    SSOT_VAULT_ROOTS     colon-separated L0/L1 roots (link-fence writes only)

A candidate declares its target and provenance in a sidecar
``<name>.candidate.json``: {"target": "<path relative to a vault root>",
"provenance": {...}}. A staged file with no sidecar is quarantined -- an
untargeted write is not a write we can reason about.

Exit codes: 0 = every candidate resolved (promoted or quarantined),
1 = a promotion was refused by the guard (a real defect, not a policy denial),
2 = usage / environment error.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from note_io import write_exact  # noqa: E402
from owasp_pipeline import Candidate, findings_to_json, gate_candidate  # noqa: E402
from vault_guard import VaultWriteError, _required_derived_root, _ssot_roots  # noqa: E402


def _load_candidate(staged: Path, vault_roots: list[Path]) -> tuple[Candidate | None, str]:
    sidecar = staged.with_suffix(staged.suffix + ".candidate.json")
    if not sidecar.exists():
        return None, "no .candidate.json sidecar (untargeted write)"
    try:
        meta = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"unreadable sidecar: {exc}"
    target_rel = str(meta.get("target") or "").strip()
    if not target_rel or Path(target_rel).is_absolute() or ".." in Path(target_rel).parts:
        return None, f"unsafe or missing target: {target_rel!r}"
    try:
        text = staged.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"candidate not valid UTF-8: {exc}"
    # Resolve the target against the FIRST vault root that already contains it,
    # else the derived root (a new note is always L2).
    target = None
    for root in vault_roots:
        if (root / target_rel).exists():
            target = root / target_rel
            break
    if target is None:
        target = vault_roots[0] / target_rel
    return Candidate(
        staged_path=staged,
        target_path=target,
        text=text,
        provenance=meta.get("provenance") or {},
    ), ""


def _quarantine(derived_root: Path, staged: Path, reason_json: str) -> Path:
    review = derived_root / "_review"
    review.mkdir(parents=True, exist_ok=True)
    dest = review / staged.name
    shutil.move(str(staged), dest)
    dest.with_suffix(dest.suffix + ".findings.json").write_text(reason_json, encoding="utf-8")
    sidecar = staged.with_suffix(staged.suffix + ".candidate.json")
    if sidecar.exists():
        shutil.move(str(sidecar), review / sidecar.name)
    return dest


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--staging", required=True, type=Path)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    if not args.staging.is_dir():
        print(f"promote: staging root is not a directory: {args.staging}", file=sys.stderr)
        return 2
    try:
        derived_root = _required_derived_root()
    except VaultWriteError as exc:
        print(f"promote: {exc}", file=sys.stderr)
        return 2
    ssot_roots = _ssot_roots()
    vault_roots = [derived_root, *ssot_roots]

    promoted = quarantined = 0
    run_bytes = 0
    refused = False
    staged_files = sorted(p for p in args.staging.rglob("*.md") if ".candidate.json" not in p.name)
    for index, staged in enumerate(staged_files):
        cand, err = _load_candidate(staged, vault_roots)
        if cand is None:
            _quarantine(
                derived_root,
                staged,
                json.dumps([{"check": "PIPELINE", "detail": err, "fatal": True}], indent=2),
            )
            quarantined += 1
            print(f"QUARANTINE {staged.name}: {err}")
            continue

        findings = gate_candidate(
            cand,
            derived_root=derived_root,
            ssot_roots=ssot_roots,
            vault_roots=vault_roots,
            run_bytes_so_far=run_bytes,
            candidate_index=index,
        )
        if findings:
            checks = ",".join(sorted({f.check for f in findings}))
            if not args.dry_run:
                _quarantine(derived_root, staged, findings_to_json(findings))
            quarantined += 1
            print(f"QUARANTINE {staged.name}: {checks}")
            continue

        run_bytes += len(cand.text.encode("utf-8"))
        if args.dry_run:
            print(f"WOULD PROMOTE {staged.name} -> {cand.target_path}")
            promoted += 1
            continue
        try:
            cand.target_path.parent.mkdir(parents=True, exist_ok=True)
            write_exact(cand.target_path, cand.text)
        except VaultWriteError as exc:
            # The gate passed but the guard refused: the two disagree, which is
            # a defect in one of them, not a policy outcome. Do not paper over it.
            print(f"REFUSED {staged.name}: guard rejected a gated write: {exc}", file=sys.stderr)
            _quarantine(
                derived_root,
                staged,
                json.dumps([{"check": "GUARD", "detail": str(exc), "fatal": True}], indent=2),
            )
            refused = True
            quarantined += 1
            continue
        staged.unlink(missing_ok=True)
        staged.with_suffix(staged.suffix + ".candidate.json").unlink(missing_ok=True)
        promoted += 1
        print(f"PROMOTED {staged.name} -> {cand.target_path}")

    print(f"promote: {promoted} promoted, {quarantined} quarantined")
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
