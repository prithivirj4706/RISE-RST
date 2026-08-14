"""
tests/test_phase2_scoring.py
============================
Focused tests for Phase 2 improvements to scoring and AuditResult.

Covers all 12 required test cases plus edge-case validation.

Scoring algorithm recap (documented in core/scoring.py)
--------------------------------------------------------
FAIL penalties   : CRITICAL=25  HIGH=15  MEDIUM=8  LOW=3
UNKNOWN penalties: CRITICAL=12  HIGH=7   MEDIUM=4  LOW=1   (floor(FAIL//2))
PASS penalty     : 0
Base score       : 100
Clamping         : max(0, min(100, base - total_penalty))

Single-finding score lookup table
----------------------------------
Status    Severity   Penalty   Score
FAIL      CRITICAL   25        75
FAIL      HIGH       15        85
FAIL      MEDIUM     8         92
FAIL      LOW        3         97
UNKNOWN   CRITICAL   12        88
UNKNOWN   HIGH       7         93
UNKNOWN   MEDIUM     4         96
UNKNOWN   LOW        1         99
PASS      *          0         100
"""

from __future__ import annotations

import pytest

from core.engine import AuditEngine, AuditResult, PlatformAdapter, _validate_findings
from core.models import Finding
from core.scoring import (
    AuditSummary,
    ScoreResult,
    build_summary,
    calculate_score,
    calculate_score_int,
    FAIL_PENALTY,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _f(
    status: str,
    severity: str,
    rule_id: str = "T-001",
    platform: str = "linux",
) -> Finding:
    """Create a minimal valid Finding."""
    return Finding(
        rule_id=rule_id,
        platform=platform,
        title=f"Test Check {rule_id}",
        status=status,
        severity=severity,
        command="echo test",
        evidence="test evidence",
        remediation="no remediation",
    )


# ---------------------------------------------------------------------------
# Test case 1 — Empty findings → score 100
# ---------------------------------------------------------------------------

class TestEmptyFindings:

    def test_empty_score_is_100(self):
        assert calculate_score_int([]) == 100

    def test_empty_score_result_score_is_100(self):
        sr = calculate_score([])
        assert sr.score == 100

    def test_empty_all_counts_zero(self):
        sr = calculate_score([])
        assert sr.pass_count == 0
        assert sr.fail_count == 0
        assert sr.unknown_count == 0

    def test_empty_breakdown_is_empty_list(self):
        sr = calculate_score([])
        assert sr.breakdown == []

    def test_empty_summary_all_zeros(self):
        s = build_summary([], 100)
        assert s.total_checks == 0
        assert s.passed == 0
        assert s.failed == 0
        assert s.unknown == 0
        assert s.critical == 0
        assert s.high == 0
        assert s.medium == 0
        assert s.low == 0
        assert s.score == 100


# ---------------------------------------------------------------------------
# Test case 2 — One CRITICAL FAIL → score 75
# ---------------------------------------------------------------------------

class TestCriticalFail:

    def test_critical_fail_score_is_75(self):
        assert calculate_score_int([_f("FAIL", "CRITICAL")]) == 75

    def test_critical_fail_penalty_is_25(self):
        sr = calculate_score([_f("FAIL", "CRITICAL")])
        assert sr.total_penalty == 25

    def test_critical_fail_grade_is_B(self):
        sr = calculate_score([_f("FAIL", "CRITICAL")])
        assert sr.grade.startswith("B")   # 75 → "B (Good)"


# ---------------------------------------------------------------------------
# Test case 3 — One HIGH FAIL → score 85
# ---------------------------------------------------------------------------

class TestHighFail:

    def test_high_fail_score_is_85(self):
        assert calculate_score_int([_f("FAIL", "HIGH")]) == 85

    def test_high_fail_penalty_is_15(self):
        sr = calculate_score([_f("FAIL", "HIGH")])
        assert sr.total_penalty == 15


# ---------------------------------------------------------------------------
# Test case 4 — One MEDIUM FAIL → score 92
# ---------------------------------------------------------------------------

class TestMediumFail:

    def test_medium_fail_score_is_92(self):
        assert calculate_score_int([_f("FAIL", "MEDIUM")]) == 92

    def test_medium_fail_penalty_is_8(self):
        sr = calculate_score([_f("FAIL", "MEDIUM")])
        assert sr.total_penalty == 8


# ---------------------------------------------------------------------------
# Test case 5 — One LOW FAIL → score 97
# ---------------------------------------------------------------------------

class TestLowFail:

    def test_low_fail_score_is_97(self):
        assert calculate_score_int([_f("FAIL", "LOW")]) == 97

    def test_low_fail_penalty_is_3(self):
        sr = calculate_score([_f("FAIL", "LOW")])
        assert sr.total_penalty == 3


# ---------------------------------------------------------------------------
# Test case 6 — One CRITICAL UNKNOWN → score 88
#
# Rule: UNKNOWN penalty = FAIL_PENALTY // 2  (floor integer division)
#        CRITICAL FAIL penalty = 25 → UNKNOWN = 25 // 2 = 12
#        Score = 100 - 12 = 88
# ---------------------------------------------------------------------------

class TestCriticalUnknown:

    def test_critical_unknown_score_is_88(self):
        """
        DETERMINISTIC RULE:
          UNKNOWN CRITICAL penalty = 25 // 2 = 12  (floor division)
          Score = 100 - 12 = 88
        """
        assert calculate_score_int([_f("UNKNOWN", "CRITICAL")]) == 88

    def test_critical_unknown_penalty_is_12(self):
        sr = calculate_score([_f("UNKNOWN", "CRITICAL")])
        assert sr.total_penalty == 12

    def test_critical_unknown_count_incremented(self):
        sr = calculate_score([_f("UNKNOWN", "CRITICAL")])
        assert sr.unknown_count == 1
        assert sr.fail_count == 0
        assert sr.pass_count == 0


# ---------------------------------------------------------------------------
# Test case 7 — Mixed findings
# ---------------------------------------------------------------------------

class TestMixedFindings:

    def _mixed(self):
        return [
            _f("PASS",    "CRITICAL", "A"),  # penalty 0
            _f("FAIL",    "HIGH",     "B"),  # penalty 15
            _f("UNKNOWN", "MEDIUM",   "C"),  # penalty 4
            _f("PASS",    "LOW",      "D"),  # penalty 0
            _f("FAIL",    "LOW",      "E"),  # penalty 3
        ]

    def test_mixed_total_penalty(self):
        # 0 + 15 + 4 + 0 + 3 = 22
        sr = calculate_score(self._mixed())
        assert sr.total_penalty == 22

    def test_mixed_score(self):
        assert calculate_score_int(self._mixed()) == 78

    def test_mixed_pass_count(self):
        sr = calculate_score(self._mixed())
        assert sr.pass_count == 2

    def test_mixed_fail_count(self):
        sr = calculate_score(self._mixed())
        assert sr.fail_count == 2

    def test_mixed_unknown_count(self):
        sr = calculate_score(self._mixed())
        assert sr.unknown_count == 1


# ---------------------------------------------------------------------------
# Test case 8 — Score never goes below 0
# ---------------------------------------------------------------------------

class TestScoreFloor:

    def test_massive_fails_clamp_to_zero(self):
        findings = [_f("FAIL", "CRITICAL")] * 20  # 20 × 25 = 500 penalty
        assert calculate_score_int(findings) == 0

    def test_zero_is_minimum(self):
        findings = [_f("FAIL", "CRITICAL")] * 100
        sr = calculate_score(findings)
        assert sr.score >= 0


# ---------------------------------------------------------------------------
# Test case 9 — Score never goes above 100
# ---------------------------------------------------------------------------

class TestScoreCeiling:

    def test_all_pass_stays_at_100(self):
        findings = [_f("PASS", s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
        assert calculate_score_int(findings) == 100

    def test_score_maximum_is_100(self):
        sr = calculate_score([])
        assert sr.score <= 100


# ---------------------------------------------------------------------------
# Test case 10 — Summary counts are correct
# ---------------------------------------------------------------------------

class TestSummaryCounts:

    def _findings(self):
        return [
            _f("PASS",    "CRITICAL", "R1"),
            _f("FAIL",    "CRITICAL", "R2"),
            _f("FAIL",    "HIGH",     "R3"),
            _f("UNKNOWN", "MEDIUM",   "R4"),
            _f("PASS",    "LOW",      "R5"),
        ]

    def test_total_checks(self):
        s = build_summary(self._findings(), 50)
        assert s.total_checks == 5

    def test_passed_count(self):
        s = build_summary(self._findings(), 50)
        assert s.passed == 2

    def test_failed_count(self):
        s = build_summary(self._findings(), 50)
        assert s.failed == 2

    def test_unknown_count(self):
        s = build_summary(self._findings(), 50)
        assert s.unknown == 1

    def test_critical_count_spans_all_statuses(self):
        # R1=PASS/CRIT, R2=FAIL/CRIT → 2 critical
        s = build_summary(self._findings(), 50)
        assert s.critical == 2

    def test_high_count(self):
        s = build_summary(self._findings(), 50)
        assert s.high == 1

    def test_medium_count(self):
        s = build_summary(self._findings(), 50)
        assert s.medium == 1

    def test_low_count(self):
        s = build_summary(self._findings(), 50)
        assert s.low == 1

    def test_score_stored_in_summary(self):
        s = build_summary(self._findings(), 42)
        assert s.score == 42

    def test_grade_stored_in_summary(self):
        s = build_summary([], 100)
        assert s.grade.startswith("A")

    def test_summary_str_contains_key_info(self):
        s = build_summary(self._findings(), 50)
        text = str(s)
        assert "PASS" in text
        assert "FAIL" in text
        assert "Score" in text


# ---------------------------------------------------------------------------
# Test case 11 — Engine returns the expected AuditResult structure
# ---------------------------------------------------------------------------

class _StubAdapter(PlatformAdapter):
    platform_name = "linux"

    def run_checks(self):
        return [
            _f("PASS",    "LOW",      "S1"),
            _f("FAIL",    "HIGH",     "S2"),
            _f("UNKNOWN", "CRITICAL", "S3"),
        ]


class TestEngineAuditResult:

    def test_engine_result_has_summary(self, monkeypatch):
        import platforms.linux as linux_mod
        monkeypatch.setattr(linux_mod, "LinuxAdapter", _StubAdapter)
        result = AuditEngine(force_platform="linux").run()
        assert result.summary is not None
        assert isinstance(result.summary, AuditSummary)

    def test_engine_result_has_score_result(self, monkeypatch):
        import platforms.linux as linux_mod
        monkeypatch.setattr(linux_mod, "LinuxAdapter", _StubAdapter)
        result = AuditEngine(force_platform="linux").run()
        assert result.score_result is not None
        assert isinstance(result.score_result, ScoreResult)

    def test_engine_result_score_matches_manual(self, monkeypatch):
        import platforms.linux as linux_mod
        monkeypatch.setattr(linux_mod, "LinuxAdapter", _StubAdapter)
        result = AuditEngine(force_platform="linux").run()
        expected = calculate_score_int(_StubAdapter().run_checks())
        assert result.score == expected

    def test_engine_result_summary_counts_match(self, monkeypatch):
        import platforms.linux as linux_mod
        monkeypatch.setattr(linux_mod, "LinuxAdapter", _StubAdapter)
        result = AuditEngine(force_platform="linux").run()
        s = result.summary
        assert s.total_checks == 3
        assert s.passed == 1
        assert s.failed == 1
        assert s.unknown == 1

    def test_engine_error_result_score_is_zero(self):
        result = AuditEngine(force_platform="dos").run()
        assert result.has_error is True
        assert result.score == 0

    def test_engine_error_result_summary_is_not_none(self):
        result = AuditEngine(force_platform="dos").run()
        assert result.summary is not None
        assert result.summary.total_checks == 0


# ---------------------------------------------------------------------------
# Test case 12 — Platform adapter integration compatibility
# ---------------------------------------------------------------------------

class _LinuxStyleAdapter(PlatformAdapter):
    """Simulates the adapter interface that Linux/Windows/macOS contributors use."""
    platform_name = "linux"

    def run_checks(self):
        return [
            _f("PASS",    "HIGH",     "FW-001"),
            _f("FAIL",    "CRITICAL", "SSH-001"),
            _f("UNKNOWN", "MEDIUM",   "PKG-001"),
            _f("PASS",    "LOW",      "USR-001"),
        ]


class TestAdapterCompatibility:

    def test_adapter_findings_flow_through_unchanged(self, monkeypatch):
        """Findings from an adapter must reach AuditResult unmodified."""
        import platforms.linux as linux_mod
        monkeypatch.setattr(linux_mod, "LinuxAdapter", _LinuxStyleAdapter)
        result = AuditEngine(force_platform="linux").run()
        ids = {f.rule_id for f in result.findings}
        assert ids == {"FW-001", "SSH-001", "PKG-001", "USR-001"}

    def test_adapter_score_correct_for_known_findings(self, monkeypatch):
        """
        FW-001  PASS HIGH    → 0
        SSH-001 FAIL CRITICAL → 25
        PKG-001 UNKNOWN MEDIUM → 4
        USR-001 PASS LOW    → 0
        Total penalty = 29  → score = 71
        """
        import platforms.linux as linux_mod
        monkeypatch.setattr(linux_mod, "LinuxAdapter", _LinuxStyleAdapter)
        result = AuditEngine(force_platform="linux").run()
        assert result.score == 71

    def test_adapter_summary_matches_findings(self, monkeypatch):
        import platforms.linux as linux_mod
        monkeypatch.setattr(linux_mod, "LinuxAdapter", _LinuxStyleAdapter)
        result = AuditEngine(force_platform="linux").run()
        s = result.summary
        assert s.total_checks == 4
        assert s.passed == 2
        assert s.failed == 1
        assert s.unknown == 1
        assert s.critical == 1
        assert s.high == 1
        assert s.medium == 1
        assert s.low == 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_all_pass_score_100(self):
        findings = [_f("PASS", s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
        assert calculate_score_int(findings) == 100

    def test_all_fail_critical_clamped(self):
        findings = [_f("FAIL", "CRITICAL")] * 10  # 250 penalty → clamped to 0
        assert calculate_score_int(findings) == 0

    def test_all_unknown_medium(self):
        # 3 × UNKNOWN MEDIUM = 3 × 4 = 12 penalty → 88
        findings = [_f("UNKNOWN", "MEDIUM", f"R{i}") for i in range(3)]
        assert calculate_score_int(findings) == 88

    def test_duplicate_rule_ids_both_scored(self):
        """Duplicate rule_ids are allowed and both incur their penalty."""
        findings = [
            _f("FAIL", "HIGH", "DUPE-001"),
            _f("FAIL", "HIGH", "DUPE-001"),
        ]
        # 2 × 15 = 30 penalty → score 70
        assert calculate_score_int(findings) == 70

    def test_validate_findings_rejects_non_finding(self):
        """Non-Finding objects are rejected and logged as warnings."""
        raw = [
            _f("PASS", "LOW", "OK"),
            "this is not a finding",
            42,
        ]
        valid, warnings = _validate_findings(raw, "TestAdapter")
        assert len(valid) == 1
        assert len(warnings) == 2
        assert valid[0].rule_id == "OK"

    def test_validate_findings_all_valid_no_warnings(self):
        raw = [_f("PASS", "LOW", f"R{i}") for i in range(5)]
        valid, warnings = _validate_findings(raw, "TestAdapter")
        assert len(valid) == 5
        assert warnings == []

    def test_validate_findings_empty_input(self):
        valid, warnings = _validate_findings([], "TestAdapter")
        assert valid == []
        assert warnings == []

    def test_calculate_score_int_is_pure(self):
        """Same input always produces the same output."""
        findings = [_f("FAIL", "HIGH"), _f("UNKNOWN", "MEDIUM")]
        assert calculate_score_int(findings) == calculate_score_int(findings)

    def test_unknown_all_severities_half_penalty(self):
        """Verify all UNKNOWN penalties are exactly floor(FAIL//2)."""
        for severity, fail_p in FAIL_PENALTY.items():
            expected_unknown_p = fail_p // 2
            sr = calculate_score([_f("UNKNOWN", severity)])
            assert sr.total_penalty == expected_unknown_p, (
                f"UNKNOWN {severity}: expected penalty {expected_unknown_p}, "
                f"got {sr.total_penalty}"
            )
