"""
tests/test_collector.py
=======================
Unit tests for core/collector.py (safe command execution).

These tests focus on the safety contract and error handling.
They use short-lived real system commands where appropriate,
and monkeypatching for error simulation.
"""

import subprocess
import pytest

from core.collector import CommandCollector, CollectorResult, make_collector


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAFE_COMMANDS = {
    "echo_hello":    ["echo", "hello"],
    "true_cmd":      ["true"],           # always exits 0
    "false_cmd":     ["false"],          # always exits 1
}


@pytest.fixture
def collector():
    return make_collector(SAFE_COMMANDS)


# ---------------------------------------------------------------------------
# CommandCollector construction
# ---------------------------------------------------------------------------

class TestCommandCollectorConstruction:

    def test_accepts_valid_dict(self):
        c = CommandCollector(allowed={"k": ["echo", "x"]})
        assert "k" in c.available_commands

    def test_raises_on_non_dict_allowed(self):
        with pytest.raises(TypeError):
            CommandCollector(allowed=["echo", "x"])

    def test_available_commands_lists_keys(self):
        c = make_collector({"a": ["echo"], "b": ["true"]})
        assert set(c.available_commands) == {"a", "b"}


# ---------------------------------------------------------------------------
# Key validation
# ---------------------------------------------------------------------------

class TestKeyValidation:

    def test_unknown_key_raises_key_error(self, collector):
        with pytest.raises(KeyError, match="not in the allowed commands"):
            collector.run("rm_everything")

    def test_known_key_does_not_raise(self, collector):
        result = collector.run("echo_hello")
        assert isinstance(result, CollectorResult)


# ---------------------------------------------------------------------------
# Successful execution
# ---------------------------------------------------------------------------

class TestSuccessfulExecution:

    def test_echo_stdout_captured(self, collector):
        result = collector.run("echo_hello")
        assert result.stdout == "hello"

    def test_echo_returncode_zero(self, collector):
        result = collector.run("echo_hello")
        assert result.returncode == 0

    def test_ok_property_true_on_success(self, collector):
        result = collector.run("echo_hello")
        assert result.ok is True

    def test_ok_property_false_on_nonzero(self, collector):
        result = collector.run("false_cmd")
        assert result.ok is False

    def test_evidence_text_returns_stdout_when_present(self, collector):
        result = collector.run("echo_hello")
        assert result.evidence_text == "hello"


# ---------------------------------------------------------------------------
# Error conditions
# ---------------------------------------------------------------------------

class TestErrorConditions:

    def test_command_not_found(self):
        c = make_collector({"ghost": ["__nonexistent_binary_xyz__"]})
        result = c.run("ghost")
        assert result.not_found is True
        assert result.ok is False
        assert "__nonexistent_binary_xyz__" in result.error

    def test_timeout_handled(self, monkeypatch):
        """Simulate a timeout by patching subprocess.run."""
        def fake_run(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=["sleep", "999"], timeout=1)

        monkeypatch.setattr(subprocess, "run", fake_run)
        c = make_collector({"slow": ["sleep", "999"]}, timeout=1)
        result = c.run("slow")
        assert result.timed_out is True
        assert result.ok is False

    def test_permission_error_handled(self, monkeypatch):
        """Simulate a permission error."""
        def fake_run(*args, **kwargs):
            raise PermissionError("Permission denied")

        monkeypatch.setattr(subprocess, "run", fake_run)
        c = make_collector({"restricted": ["cat", "/root/secret"]})
        result = c.run("restricted")
        assert result.permission_denied is True
        assert result.ok is False

    def test_os_error_handled(self, monkeypatch):
        """Simulate a generic OS error."""
        def fake_run(*args, **kwargs):
            raise OSError("generic OS failure")

        monkeypatch.setattr(subprocess, "run", fake_run)
        c = make_collector({"bad_cmd": ["bogus"]})
        result = c.run("bad_cmd")
        assert result.ok is False
        assert "OS error" in result.error


# ---------------------------------------------------------------------------
# Result __str__
# ---------------------------------------------------------------------------

class TestCollectorResultStr:

    def test_str_ok_result(self, collector):
        result = collector.run("echo_hello")
        assert "echo_hello" in str(result)
        assert "OK" in str(result)

    def test_str_error_result(self):
        c = make_collector({"ghost": ["__ghost__"]})
        result = c.run("ghost")
        assert "ghost" in str(result)
        assert "ERROR" in str(result)
