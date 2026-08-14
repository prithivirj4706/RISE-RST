"""
tests/test_engine.py
====================
Unit tests for core/engine.py (AuditEngine).

These tests verify that:
- The engine detects the platform and loads the correct adapter.
- The engine returns a list of Finding objects.
- Engine errors are captured in AuditResult rather than raised.
"""

import pytest

from core.engine import AuditEngine, AuditResult, PlatformAdapter
from core.models import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(rule_id="T-001", status="PASS", severity="LOW") -> Finding:
    return Finding(
        rule_id=rule_id,
        platform="linux",
        title="Test Finding",
        status=status,
        severity=severity,
        command="echo test",
        evidence="test evidence",
        remediation="none",
    )


class _MockAdapter(PlatformAdapter):
    """Minimal adapter that returns two predetermined findings."""

    platform_name = "linux"

    def run_checks(self) -> list[Finding]:
        return [
            _make_finding("T-001", "PASS",    "LOW"),
            _make_finding("T-002", "FAIL",    "HIGH"),
            _make_finding("T-003", "UNKNOWN", "MEDIUM"),
        ]


class _ErrorAdapter(PlatformAdapter):
    """Adapter that always raises (to test engine error handling)."""

    platform_name = "linux"

    def run_checks(self) -> list[Finding]:
        raise RuntimeError("Simulated adapter failure")


# ---------------------------------------------------------------------------
# AuditResult properties
# ---------------------------------------------------------------------------

class TestAuditResult:

    def _result_with_findings(self) -> AuditResult:
        findings = [
            _make_finding("A", "PASS",    "LOW"),
            _make_finding("B", "FAIL",    "HIGH"),
            _make_finding("C", "UNKNOWN", "MEDIUM"),
        ]
        return AuditResult(
            platform="linux",
            platform_detail={},
            findings=findings,
        )

    def test_total_count(self):
        r = self._result_with_findings()
        assert r.total == 3

    def test_passed_filter(self):
        r = self._result_with_findings()
        assert len(r.passed) == 1

    def test_failed_filter(self):
        r = self._result_with_findings()
        assert len(r.failed) == 1

    def test_unknown_filter(self):
        r = self._result_with_findings()
        assert len(r.unknown) == 1

    def test_has_error_false_by_default(self):
        r = AuditResult(platform="linux", platform_detail={}, findings=[])
        assert r.has_error is False

    def test_has_error_true_when_error_set(self):
        r = AuditResult(
            platform="linux", platform_detail={}, findings=[], error="oops"
        )
        assert r.has_error is True


# ---------------------------------------------------------------------------
# AuditEngine — forced platform
# ---------------------------------------------------------------------------

class TestAuditEngine:

    def test_engine_returns_audit_result(self, monkeypatch):
        """Engine should return AuditResult containing Finding objects."""
        import platforms.linux as linux_mod

        # Swap the real adapter for our mock
        monkeypatch.setattr(linux_mod, "LinuxAdapter", _MockAdapter)

        engine = AuditEngine(force_platform="linux")
        result = engine.run()

        assert isinstance(result, AuditResult)
        assert result.has_error is False
        assert len(result.findings) == 3

    def test_all_findings_are_finding_instances(self, monkeypatch):
        import platforms.linux as linux_mod
        monkeypatch.setattr(linux_mod, "LinuxAdapter", _MockAdapter)

        engine = AuditEngine(force_platform="linux")
        result = engine.run()

        for f in result.findings:
            assert isinstance(f, Finding)

    def test_unknown_platform_returns_error(self):
        engine = AuditEngine(force_platform="dos")
        result = engine.run()
        assert result.has_error is True
        assert len(result.findings) == 0

    def test_engine_captures_adapter_exception(self, monkeypatch):
        import platforms.linux as linux_mod
        monkeypatch.setattr(linux_mod, "LinuxAdapter", _ErrorAdapter)

        engine = AuditEngine(force_platform="linux")
        result = engine.run()

        assert result.has_error is True
        assert "Simulated adapter failure" in result.error
