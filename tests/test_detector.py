"""
tests/test_detector.py
======================
Unit tests for core/detector.py (OS detection).
"""

import sys
import platform

import pytest

from core.detector import (
    detect_platform,
    get_platform_detail,
    PLATFORM_LINUX,
    PLATFORM_WINDOWS,
    PLATFORM_MACOS,
    PLATFORM_UNKNOWN,
)


class TestDetectPlatform:

    def test_returns_string(self):
        result = detect_platform()
        assert isinstance(result, str)

    def test_returns_known_value(self):
        valid = {PLATFORM_LINUX, PLATFORM_WINDOWS, PLATFORM_MACOS, PLATFORM_UNKNOWN}
        assert detect_platform() in valid

    def test_linux_detected_on_linux(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        assert detect_platform() == PLATFORM_LINUX

    def test_linux2_detected_on_linux(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux2")
        assert detect_platform() == PLATFORM_LINUX

    def test_darwin_detected_as_macos(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        assert detect_platform() == PLATFORM_MACOS

    def test_win32_detected_as_windows(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        assert detect_platform() == PLATFORM_WINDOWS

    def test_cygwin_detected_as_windows(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "cygwin")
        assert detect_platform() == PLATFORM_WINDOWS

    def test_unknown_platform_falls_back(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "haiku")
        monkeypatch.setattr(platform, "system", lambda: "Haiku")
        result = detect_platform()
        assert result == PLATFORM_UNKNOWN


class TestGetPlatformDetail:

    def test_returns_dict(self):
        detail = get_platform_detail()
        assert isinstance(detail, dict)

    def test_contains_required_keys(self):
        detail = get_platform_detail()
        for key in ["platform", "system", "release", "version", "machine", "python"]:
            assert key in detail, f"Missing key: {key}"

    def test_platform_value_is_normalised(self):
        detail = get_platform_detail()
        valid = {PLATFORM_LINUX, PLATFORM_WINDOWS, PLATFORM_MACOS, PLATFORM_UNKNOWN}
        assert detail["platform"] in valid
