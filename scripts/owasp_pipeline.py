"""owasp_pipeline.py - fail-closed pre-write gate over the OWASP GenAI LLM Top 10 (2026).

Step 3 of FORK_HARDENING.md; the ADR 0001 section 5 gate. The autonomous writer
never touches the vault directly: it writes CANDIDATES into a staging root, and
every candidate must pass all ten checks before `promote_candidates.py` commits
it. A candidate that fails any check is quarantined under the derived tree's
``_review/`` for a human and never reaches L0/L1.

Why a staging root rather than an in-process filter: the writer is a headless
agent using its own Write/Edit tools, so there is no call site to wrap. Making
the vault physically unreachable (it writes elsewhere) is a boundary; asking a
model not to write is an instruction.

The ten checks, mapped from ADR 0001 section 5:

  LLM01 Prompt Injection ............ instruction-shaped spans in ingested text
  LLM02 Sensitive Info Disclosure ... secret/PII patterns in the candidate
  LLM03 Excessive Agency ............ write target confined; no fence-escape
  LLM04 Supply Chain ................ provenance stamp present + generator pinned
  LLM05 Data & Model Poisoning ...... source refs resolve; hashes recorded
  LLM06 Unbounded Consumption ....... per-run candidate + byte budget
  LLM07 Misinformation .............. claim strength vs cited source (LLM)
  LLM08 Hidden Context Exposure ..... leaked system/hidden-prompt markers
  LLM09 Vector & Embedding .......... retrieval hits resolve to real notes
  LLM10 Improper Output Handling .... markdown/frontmatter/fence integrity

Three checks (LLM01 span classification, LLM07 claim strength, LLM08 semantic
leak detection) are LLM-based per the ADR and must run on Haiku via Bedrock.
Bedrock is not wired in this fork until step 4, so those checks currently
report UNAVAILABLE -- which this gate treats as a FAILURE, not a pass. That is
deliberate: the ADR calls the pipeline a build prerequisite for the autonomous
L0 write path, so the path stays closed until the checks can actually run.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from vault_guard import FENCE_END, FENCE_START, split_fence

# --- budgets (LLM06) ---------------------------------------------------------
MAX_CANDIDATES_PER_RUN = int(os.getenv("OWASP_MAX_CANDIDATES", "50"))
MAX_CANDIDATE_BYTES = int(os.getenv("OWASP_MAX_CANDIDATE_BYTES", str(256 * 1024)))
MAX_RUN_BYTES = int(os.getenv("OWASP_MAX_RUN_BYTES", str(2 * 1024 * 1024)))

# --- LLM01: instruction-shaped spans ----------------------------------------
# Deterministic prefilter only. The ADR assigns the real classification to a
# Haiku call; this catches the unambiguous cases so they never even reach it.
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
    re.compile(r"disregard\s+(your|the)\s+(instructions|rules|system\s+prompt)", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+\w+", re.I),
    re.compile(r"</?(system|instructions?)>", re.I),
    re.compile(r"\bnew\s+system\s+prompt\b", re.I),
    re.compile(r"reveal\s+(your|the)\s+(system\s+)?prompt", re.I),
    re.compile(r"\bexfiltrat\w+\b", re.I),
    re.compile(r"run\s+this\s+(command|script)|curl\s+[^\s]+\s*\|\s*(ba)?sh", re.I),
]

# --- LLM02: secrets / PII ----------------------------------------------------
_SECRET_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws-access-key-id"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "aws-temp-key-id"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private-key-block"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"), "github-token"),
    (re.compile(r"\bxox[abpsr]-[A-Za-z0-9-]{10,}\b"), "slack-token"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "vendor-api-key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."), "jwt"),
    (
        re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*\S{8,}"),
        "credential-assignment",
    ),
]
_PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "us-ssn-shaped"),
    (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "card-number-shaped"),
]

# --- LLM08: hidden-context markers ------------------------------------------
_HIDDEN_CONTEXT_MARKERS = [
    re.compile(r"<\s*/?\s*(system-reminder|antml:|thinking)\b", re.I),
    re.compile(r"\bYou are Claude\b"),
    re.compile(r"\bsystem prompt\b.*\bfollows\b", re.I),
    re.compile(r"\bCLAUDE\.md\b.*\bcontents?\b.*:", re.I),
]

# --- LLM10: output handling --------------------------------------------------
_DANGEROUS_MARKUP = [
    re.compile(r"<script\b", re.I),
    re.compile(r"<iframe\b", re.I),
    re.compile(r"\bjavascript:", re.I),
    re.compile(r"<\s*img[^>]*\bonerror\b", re.I),
]

REQUIRED_FRONTMATTER = ("layer", "generated-by", "generated-at", "source-refs")


@dataclass
class Finding:
    check: str  # "LLM01" ... "LLM10"
    detail: str
    fatal: bool = True


@dataclass
class Candidate:
    """One staged note awaiting promotion."""

    staged_path: Path
    target_path: Path
    text: str
    provenance: Dict[str, object] = field(default_factory=dict)


class LlmCheckUnavailable(RuntimeError):
    """An LLM-backed check could not run (no Bedrock provider yet)."""


# =============================================================================
# deterministic checks (7)
# =============================================================================


def check_llm01_injection(c: Candidate) -> List[Finding]:
    out = []
    for pat in _INJECTION_PATTERNS:
        m = pat.search(c.text)
        if m:
            out.append(Finding("LLM01", f"instruction-shaped span: {pat.pattern[:48]!r}"))
    return out


def check_llm02_sensitive(c: Candidate) -> List[Finding]:
    out = []
    for pat, label in _SECRET_PATTERNS + _PII_PATTERNS:
        if pat.search(c.text):
            # The matched value is never echoed: a finding that quotes the
            # secret moves it into the findings sidecar (LESSONS L13 shape).
            out.append(Finding("LLM02", f"{label} pattern present"))
    return out


def check_llm03_agency(
    c: Candidate, derived_root: Path, ssot_roots: Sequence[Path]
) -> List[Finding]:
    """The candidate's target must be inside the derived tree, or be a pure
    link-fence edit of an SSOT note. Anything else is the writer exceeding its
    authority regardless of what the guard would later say."""
    target = c.target_path
    try:
        resolved = target.resolve() if target.exists() else (target.parent.resolve() / target.name)
    except OSError as exc:
        return [Finding("LLM03", f"target path unresolvable: {exc}")]

    def inside(root: Path) -> bool:
        try:
            resolved.relative_to(root.resolve())
            return True
        except (ValueError, OSError):
            return False

    if inside(derived_root):
        return []
    for root in ssot_roots:
        if inside(root):
            if not resolved.exists():
                return [Finding("LLM03", "new note inside an SSOT root")]
            try:
                current = resolved.read_bytes().decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                return [Finding("LLM03", f"SSOT note unreadable: {exc}")]
            try:
                before = split_fence(current)
                after = split_fence(c.text)
            except Exception as exc:  # malformed fence -> fail closed
                return [Finding("LLM03", f"fence malformed: {exc}")]
            outside_before = current if before is None else before[0] + before[2]
            outside_after = c.text if after is None else after[0] + after[2]
            if outside_before != outside_after:
                return [Finding("LLM03", "SSOT prose changed outside the link fence")]
            return []
    return [Finding("LLM03", "target is outside every declared vault root")]


def check_llm04_supply_chain(c: Candidate) -> List[Finding]:
    """Provenance must name the generator AND pin it. An unpinned generator
    means a later upstream pull silently changes what produced the note."""
    gen = str(c.provenance.get("generated-by") or "")
    if not gen:
        return [Finding("LLM04", "no generated-by provenance")]
    if "@" not in gen:
        return [Finding("LLM04", f"generator not pinned to a commit: {gen!r}")]
    return []


def check_llm05_poisoning(c: Candidate, vault_roots: Sequence[Path]) -> List[Finding]:
    """Every cited source ref must resolve to a real note. A derivation of a
    source that does not exist is unfalsifiable by construction."""
    refs = c.provenance.get("source-refs") or []
    if not isinstance(refs, (list, tuple)) or not refs:
        return [Finding("LLM05", "source-refs missing or empty")]
    out = []
    for ref in refs:
        rel = str(ref).split("#", 1)[0].strip()
        if not rel:
            out.append(Finding("LLM05", f"unparseable source ref {ref!r}"))
            continue
        if not any((root / rel).exists() for root in vault_roots):
            out.append(Finding("LLM05", f"source ref does not resolve: {rel}"))
    return out


def check_llm06_consumption(
    c: Candidate, run_bytes_so_far: int, candidate_index: int
) -> List[Finding]:
    out = []
    size = len(c.text.encode("utf-8"))
    if size > MAX_CANDIDATE_BYTES:
        out.append(Finding("LLM06", f"candidate {size}B exceeds {MAX_CANDIDATE_BYTES}B"))
    if candidate_index >= MAX_CANDIDATES_PER_RUN:
        out.append(Finding("LLM06", f"run exceeds {MAX_CANDIDATES_PER_RUN} candidates"))
    if run_bytes_so_far + size > MAX_RUN_BYTES:
        out.append(Finding("LLM06", f"run exceeds {MAX_RUN_BYTES}B total"))
    return out


def check_llm09_vector(c: Candidate, vault_roots: Sequence[Path]) -> List[Finding]:
    """Retrieval hits recorded on the candidate must resolve to real notes --
    the fail-closed rule from ADR 0001 section 2."""
    hits = c.provenance.get("retrieval-hits") or []
    if not isinstance(hits, (list, tuple)):
        return [Finding("LLM09", "retrieval-hits is not a list")]
    out = []
    for hit in hits:
        rel = str(hit).split("#", 1)[0].strip()
        if not rel or not any((root / rel).exists() for root in vault_roots):
            out.append(Finding("LLM09", f"retrieval hit does not resolve: {hit!r}"))
    return out


def check_llm10_output(c: Candidate) -> List[Finding]:
    out = []
    for pat in _DANGEROUS_MARKUP:
        if pat.search(c.text):
            out.append(Finding("LLM10", f"dangerous markup: {pat.pattern[:32]!r}"))
    if not c.text.startswith("---"):
        out.append(Finding("LLM10", "no frontmatter block"))
    else:
        end = c.text.find("\n---", 3)
        if end == -1:
            out.append(Finding("LLM10", "unterminated frontmatter block"))
        else:
            head = c.text[: end + 4]
            for key in REQUIRED_FRONTMATTER:
                if not re.search(rf"(?m)^{re.escape(key)}\s*:", head):
                    out.append(Finding("LLM10", f"frontmatter missing {key!r}"))
    starts, ends = c.text.count(FENCE_START), c.text.count(FENCE_END)
    if starts != ends or starts > 1:
        out.append(Finding("LLM10", f"fence markers unbalanced ({starts}/{ends})"))
    for marker in _HIDDEN_CONTEXT_MARKERS:
        if marker.search(c.text):
            out.append(Finding("LLM08", f"hidden-context marker: {marker.pattern[:32]!r}"))
    return out


# =============================================================================
# LLM-backed checks (3) -- Bedrock only, fail closed until step 4
# =============================================================================


def _bedrock_available() -> bool:
    """True only when a Bedrock provider is configured for this fork.

    Deliberately narrow: the fork's egress policy is Bedrock-only, so any other
    provider must NOT make these checks look runnable.
    """
    return bool(os.getenv("OBSIDIAN_BEDROCK_MODEL_ID")) and bool(os.getenv("AWS_REGION"))


def check_llm_backed(c: Candidate) -> List[Finding]:
    """LLM01 span classification, LLM07 claim strength, LLM08 semantic leaks.

    Returns a FATAL finding while Bedrock is unwired: the ADR makes the
    pipeline a prerequisite for the autonomous write path, so "cannot check"
    must block, never pass. Step 4 replaces the body with real Haiku calls.
    """
    if not _bedrock_available():
        return [
            Finding(
                "LLM01/07/08",
                "LLM-backed checks unavailable: no Bedrock provider configured "
                "(fork ADR 0001 step 4). The autonomous write path stays closed "
                "until these can run -- this is the prerequisite, not a warning.",
            )
        ]
    raise LlmCheckUnavailable(
        "Bedrock env is set but the provider is not implemented yet (step 4). "
        "Refusing to report a pass for checks that did not run."
    )


# =============================================================================
# the gate
# =============================================================================


def gate_candidate(
    c: Candidate,
    *,
    derived_root: Path,
    ssot_roots: Sequence[Path],
    vault_roots: Sequence[Path],
    run_bytes_so_far: int = 0,
    candidate_index: int = 0,
    llm_check: Optional[Callable[[Candidate], List[Finding]]] = None,
) -> List[Finding]:
    """Run all ten checks. Empty list == promote. Any finding == quarantine.

    Fail-closed in every direction: an exception inside a check is itself a
    finding, because a check that crashed did not pass.
    """
    findings: List[Finding] = []
    runners: List[Callable[[], List[Finding]]] = [
        lambda: check_llm01_injection(c),
        lambda: check_llm02_sensitive(c),
        lambda: check_llm03_agency(c, derived_root, ssot_roots),
        lambda: check_llm04_supply_chain(c),
        lambda: check_llm05_poisoning(c, vault_roots),
        lambda: check_llm06_consumption(c, run_bytes_so_far, candidate_index),
        lambda: check_llm09_vector(c, vault_roots),
        lambda: check_llm10_output(c),
        lambda: (llm_check or check_llm_backed)(c),
    ]
    for run in runners:
        try:
            findings.extend(run())
        except Exception as exc:  # noqa: BLE001 -- a crashed check is a failure
            findings.append(Finding("PIPELINE", f"check raised {type(exc).__name__}: {exc}"))
    return findings


def findings_to_json(findings: Sequence[Finding]) -> str:
    return json.dumps(
        [{"check": f.check, "detail": f.detail, "fatal": f.fatal} for f in findings],
        indent=2,
    )
