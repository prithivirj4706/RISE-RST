"""
tests/test_models.py
====================
Unit tests for core/models.py (Finding dataclass).
"""

import pytest
from core.models import Finding, SEVERITY_ORDER, VALID_STATUSES, VALID_SEVERITIES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_finding(**overrides) -> Finding:
    """Return a valid Finding, optionally with field overrides."""
    defaults = dict(
        rule_id="TST-001",
        platform="linux",
        title="Test Check",
        status="PASS",
        severity="LOW",
        command="echo test",
        evidence="test output",
        remediation="none required",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

class TestFindingConstruction:

    def test_valid_finding_creates_successfully(self):
        f = make_finding()
        assert f.rule_id == "TST-001"
        assert f.platform == "linux"
        assert f.status == "PASS"
        assert f.severity == "LOW"

    def test_all_valid_statuses(self):
        for status in VALID_STATUSES:
            f = make_finding(status=status)
            assert f.status == status

    def test_all_valid_severities(self):
        for severity in VALID_SEVERITIES:
            f = make_finding(severity=severity)
            assert f.severity == severity

    def test_invalid_status_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid status"):
            make_finding(status="MAYBE")

    def test_invalid_severity_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid severity"):
            make_finding(severity="EXTREME")

    def test_empty_rule_id_raises_value_error(self):
        with pytest.raises(ValueError, match="rule_id"):
            make_finding(rule_id="")

    def test_empty_title_raises_value_error(self):
        with pytest.raises(ValueError, match="title"):
            make_finding(title="")

    def test_whitespace_rule_id_raises_value_error(self):
        with pytest.raises(ValueError):
            make_finding(rule_id="   ")


# ---------------------------------------------------------------------------
# Convenience properties
# ---------------------------------------------------------------------------

class TestFindingProperties:

    def test_passed_true_for_pass(self):
        assert make_finding(status="PASS").passed is True

    def test_passed_false_for_fail(self):
        assert make_finding(status="FAIL").passed is False

    def test_failed_true_for_fail(self):
        assert make_finding(status="FAIL").failed is True

    def test_unknown_true_for_unknown(self):
        assert make_finding(status="UNKNOWN").unknown is True

    def test_severity_weight_order(self):
        critical = make_finding(severity="CRITICAL").severity_weight
        high     = make_finding(severity="HIGH").severity_weight
        medium   = make_finding(severity="MEDIUM").severity_weight
        low      = make_finding(severity="LOW").severity_weight
        assert critical > high > medium > low

    def test_to_dict_contains_all_fields(self):
        f = make_finding()
        d = f.to_dict()
        for key in ["rule_id", "platform", "title", "status", "severity",
                    "command", "evidence", "remediation"]:
            assert key in d

    def test_str_representation_contains_key_info(self):
        f = make_finding(rule_id="X-001", status="FAIL", title="Foo Check")
        s = str(f)
        assert "X-001" in s
        assert "FAIL" in s
        assert "Foo Check" in s


# ---------------------------------------------------------------------------
# Extra field (metadata)
# ---------------------------------------------------------------------------

class TestFindingExtra:

    def test_extra_defaults_to_empty_dict(self):
        f = make_finding()
        assert f.extra == {}

    def test_extra_can_hold_arbitrary_data(self):
        f = make_finding(extra={"cve": "CVE-2024-1234", "ref": "CIS 1.1"})
        assert f.extra["cve"] == "CVE-2024-1234"
