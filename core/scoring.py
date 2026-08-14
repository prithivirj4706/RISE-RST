"""
core/scoring.py
===============
Deterministic security scoring for SENTINELAUDIT.

Design principles
-----------------
- Pure function: same inputs always produce the same output.
- No ML, no LLM, no randomness.
- Transparent algorithm: every factor is explicit in this file.
- The score is a simple weighted penalty model on 0–100 scale.

Score interpretation
--------------------
  90–100  Excellent
  75–89   Good
  50–74   Fair
  25–49   Poor
   0–24   Critical

Penalty table (per FAIL finding)
---------------------------------
  CRITICAL  →  −25 points
  HIGH      →  −15 points
  MEDIUM    →  −8  points
  LOW       →  −3  points

UNKNOWN findings receive half the FAIL penalty (evidence missing;
could be a real issue or an unsupported tool).

PASS findings contribute no penalty.

The score is clamped to [0, 100].
"""

from __future__ import annotations

from dataclasses import dataclass

from core.models import Finding

# ---------------------------------------------------------------------------
# Penalty weights
# ---------------------------------------------------------------------------

FAIL_PENALTY: dict[str, int] = {
    "CRITICAL": 25,
    "HIGH":     15,
    "MEDIUM":    8,
    "LOW":       3,
}

# UNKNOWN penalty = half the FAIL penalty for the same severity.
# Integer division is used: 25//2=12, 15//2=7, 8//2=4, 3//2=1
UNKNOWN_DIVISOR: int = 2

# Starting score before any penalties are applied.
BASE_SCORE: int = 100


# ---------------------------------------------------------------------------
# Score result
# ---------------------------------------------------------------------------

@dataclass
class ScoreResult:
    """
    Holds the computed score and a transparent breakdown.

    Attributes
    ----------
    score           : Final score (0–100).
    total_penalty   : Sum of all penalties applied.
    pass_count      : Number of PASS findings.
    fail_count      : Number of FAIL findings.
    unknown_count   : Number of UNKNOWN findings.
    breakdown       : Per-finding penalty detail list.
    grade           : Letter-grade label.
    """

    score: int
    total_penalty: int
    pass_count: int
    fail_count: int
    unknown_count: int
    breakdown: list[dict]
    grade: str

    def __str__(self) -> str:
        return (
            f"Score: {self.score}/100  Grade: {self.grade}  "
            f"(PASS={self.pass_count}, FAIL={self.fail_count}, "
            f"UNKNOWN={self.unknown_count})"
        )


# ---------------------------------------------------------------------------
# Audit summary — deterministic counts per severity/status
# ---------------------------------------------------------------------------

@dataclass
class AuditSummary:
    """
    Deterministic counts derived from a list of findings.

    Produced by ``build_summary()``.  All values are non-negative integers.

    Attributes
    ----------
    total_checks : Total number of findings evaluated.
    passed       : Findings with status PASS.
    failed       : Findings with status FAIL.
    unknown      : Findings with status UNKNOWN.
    critical     : Findings with severity CRITICAL (any status).
    high         : Findings with severity HIGH (any status).
    medium       : Findings with severity MEDIUM (any status).
    low          : Findings with severity LOW (any status).
    score        : Final security score (0–100).
    grade        : Letter-grade label.

    Note: severity counts span all statuses (PASS + FAIL + UNKNOWN).
    They represent the *gravity distribution* of all checks, not only failures.
    """

    total_checks: int
    passed: int
    failed: int
    unknown: int
    critical: int
    high: int
    medium: int
    low: int
    score: int
    grade: str

    def __str__(self) -> str:
        return (
            f"Checks: {self.total_checks}  "
            f"PASS={self.passed}  FAIL={self.failed}  UNKNOWN={self.unknown}  "
            f"| CRITICAL={self.critical}  HIGH={self.high}  "
            f"MEDIUM={self.medium}  LOW={self.low}  "
            f"| Score: {self.score}/100  Grade: {self.grade}"
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def calculate_score(findings: list[Finding]) -> ScoreResult:
    """
    Calculate a deterministic security score from a list of findings.

    Parameters
    ----------
    findings : list[Finding]
        All Finding objects returned by the audit engine.

    Returns
    -------
    ScoreResult
        Final score, grade, counts, and per-finding breakdown.
    """
    total_penalty = 0
    pass_count = 0
    fail_count = 0
    unknown_count = 0
    breakdown: list[dict] = []

    for finding in findings:
        penalty = 0

        if finding.status == "FAIL":
            penalty = FAIL_PENALTY.get(finding.severity, 0)
            fail_count += 1
        elif finding.status == "UNKNOWN":
            penalty = FAIL_PENALTY.get(finding.severity, 0) // UNKNOWN_DIVISOR
            unknown_count += 1
        else:  # PASS
            pass_count += 1

        total_penalty += penalty
        breakdown.append(
            {
                "rule_id":  finding.rule_id,
                "title":    finding.title,
                "status":   finding.status,
                "severity": finding.severity,
                "penalty":  penalty,
            }
        )

    raw_score = BASE_SCORE - total_penalty
    final_score = max(0, min(100, raw_score))

    return ScoreResult(
        score=final_score,
        total_penalty=total_penalty,
        pass_count=pass_count,
        fail_count=fail_count,
        unknown_count=unknown_count,
        breakdown=breakdown,
        grade=_letter_grade(final_score),
    )


def calculate_score_int(findings: list[Finding]) -> int:
    """
    Convenience wrapper: return only the integer score (0–100).

    Identical algorithm to ``calculate_score``; useful when callers
    only need the numeric result without the full breakdown.

    Penalty rules (FAIL):
        CRITICAL → 100 - 25 = 75
        HIGH     → 100 - 15 = 85
        MEDIUM   → 100 - 8  = 92
        LOW      → 100 - 3  = 97

    Penalty rules (UNKNOWN, integer floor division by 2):
        CRITICAL → 100 - 12 = 88
        HIGH     → 100 - 7  = 93
        MEDIUM   → 100 - 4  = 96
        LOW      → 100 - 1  = 99
    """
    return calculate_score(findings).score


def build_summary(findings: list[Finding], score: int) -> AuditSummary:
    """
    Build a structured count summary from a list of findings.

    Parameters
    ----------
    findings : list[Finding]
        All findings from the audit run.
    score : int
        Pre-computed security score (0–100).

    Returns
    -------
    AuditSummary
        Deterministic counts and the score.
    """
    passed  = sum(1 for f in findings if f.status == "PASS")
    failed  = sum(1 for f in findings if f.status == "FAIL")
    unknown = sum(1 for f in findings if f.status == "UNKNOWN")

    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    high     = sum(1 for f in findings if f.severity == "HIGH")
    medium   = sum(1 for f in findings if f.severity == "MEDIUM")
    low      = sum(1 for f in findings if f.severity == "LOW")

    return AuditSummary(
        total_checks=len(findings),
        passed=passed,
        failed=failed,
        unknown=unknown,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        score=score,
        grade=_letter_grade(score),
    )


def _letter_grade(score: int) -> str:
    """Return a human-readable grade for the given score."""
    if score >= 90:
        return "A (Excellent)"
    if score >= 75:
        return "B (Good)"
    if score >= 50:
        return "C (Fair)"
    if score >= 25:
        return "D (Poor)"
    return "F (Critical)"
