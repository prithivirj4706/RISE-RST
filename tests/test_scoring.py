"""
tests/test_scoring.py
=====================
Unit tests for core/scoring.py (deterministic scoring).
"""

import pytest

from core.models import Finding
from core.scoring import (
    calculate_score,
    ScoreResult,
    BASE_SCORE,
    FAIL_PENALTY,
    UNKNOWN_DIVISOR,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _f(status: str, severity: str) -> Finding:
    return Finding(
        rule_id="T-001",
        platform="linux",
        title="Test",
        status=status,
        severity=severity,
        command="echo test",
        evidence="test",
        remediation="none",
    )


# ---------------------------------------------------------------------------
# Empty finding list
# ---------------------------------------------------------------------------

class TestEmptyFindings:

    def test_empty_list_returns_100(self):
        result = calculate_score([])
        assert result.score == 100

    def test_empty_list_all_counts_zero(self):
        result = calculate_score([])
        assert result.pass_count == 0
        assert result.fail_count == 0
        assert result.unknown_count == 0


# ---------------------------------------------------------------------------
# PASS findings — no penalty
# ---------------------------------------------------------------------------

class TestPassFindings:

    def test_all_pass_returns_100(self):
        findings = [_f("PASS", s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
        result = calculate_score(findings)
        assert result.score == 100

    def test_pass_count_correct(self):
        findings = [_f("PASS", "LOW")] * 3
        result = calculate_score(findings)
        assert result.pass_count == 3


# ---------------------------------------------------------------------------
# FAIL findings — full penalty
# ---------------------------------------------------------------------------

class TestFailFindings:

    def test_critical_fail_penalty(self):
        result = calculate_score([_f("FAIL", "CRITICAL")])
        expected = BASE_SCORE - FAIL_PENALTY["CRITICAL"]
        assert result.score == expected

    def test_high_fail_penalty(self):
        result = calculate_score([_f("FAIL", "HIGH")])
        expected = BASE_SCORE - FAIL_PENALTY["HIGH"]
        assert result.score == expected

    def test_medium_fail_penalty(self):
        result = calculate_score([_f("FAIL", "MEDIUM")])
        expected = BASE_SCORE - FAIL_PENALTY["MEDIUM"]
        assert result.score == expected

    def test_low_fail_penalty(self):
        result = calculate_score([_f("FAIL", "LOW")])
        expected = BASE_SCORE - FAIL_PENALTY["LOW"]
        assert result.score == expected

    def test_multiple_fails_accumulate(self):
        findings = [_f("FAIL", "HIGH")] * 4
        result = calculate_score(findings)
        expected = max(0, BASE_SCORE - 4 * FAIL_PENALTY["HIGH"])
        assert result.score == expected

    def test_score_never_goes_below_zero(self):
        findings = [_f("FAIL", "CRITICAL")] * 20
        result = calculate_score(findings)
        assert result.score >= 0


# ---------------------------------------------------------------------------
# UNKNOWN findings — half penalty
# ---------------------------------------------------------------------------

class TestUnknownFindings:

    def test_unknown_half_penalty_of_fail(self):
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            fail_result    = calculate_score([_f("FAIL",    severity)])
            unknown_result = calculate_score([_f("UNKNOWN", severity)])
            expected_penalty = FAIL_PENALTY[severity] // UNKNOWN_DIVISOR
            assert unknown_result.score == BASE_SCORE - expected_penalty

    def test_unknown_count_tracked(self):
        result = calculate_score([_f("UNKNOWN", "HIGH")] * 2)
        assert result.unknown_count == 2


# ---------------------------------------------------------------------------
# Score is clamped to [0, 100]
# ---------------------------------------------------------------------------

class TestScoreClamping:

    def test_score_clamped_to_100_max(self):
        # Even with no findings, score should not exceed 100.
        result = calculate_score([])
        assert result.score <= 100

    def test_score_clamped_to_0_min(self):
        findings = [_f("FAIL", "CRITICAL")] * 20
        result = calculate_score(findings)
        assert result.score == 0


# ---------------------------------------------------------------------------
# Grades
# ---------------------------------------------------------------------------

class TestLetterGrades:

    def test_perfect_score_is_A(self):
        result = calculate_score([])
        assert result.grade.startswith("A")

    def test_grade_present_in_str(self):
        result = calculate_score([])
        s = str(result)
        assert "Grade:" in s or "Score:" in s


# ---------------------------------------------------------------------------
# Breakdown
# ---------------------------------------------------------------------------

class TestBreakdown:

    def test_breakdown_length_matches_findings(self):
        findings = [_f("PASS", "LOW"), _f("FAIL", "HIGH"), _f("UNKNOWN", "MEDIUM")]
        result = calculate_score(findings)
        assert len(result.breakdown) == 3

    def test_breakdown_contains_rule_id(self):
        findings = [_f("FAIL", "HIGH")]
        result = calculate_score(findings)
        assert "rule_id" in result.breakdown[0]

    def test_pass_breakdown_has_zero_penalty(self):
        result = calculate_score([_f("PASS", "CRITICAL")])
        assert result.breakdown[0]["penalty"] == 0
