"""
core/detector.py
================
Operating-system detection for SENTINELAUDIT.

Returns a normalised platform name: "linux" | "windows" | "macos" | "unknown".

Rules
-----
- Uses Python's standard library only (sys / platform / os).
- Does NOT execute any shell commands.
- Is intentionally simple and side-effect free.
"""

from __future__ import annotations

import platform
import sys

# Normalised names used throughout the codebase.
PLATFORM_LINUX   = "linux"
PLATFORM_WINDOWS = "windows"
PLATFORM_MACOS   = "macos"
PLATFORM_UNKNOWN = "unknown"


def detect_platform() -> str:
    """
    Detect the current operating system and return a normalised name.

    Returns
    -------
    str
        One of: "linux", "windows", "macos", "unknown".
    """
    system = sys.platform  # "linux", "win32", "darwin", etc.

    if system.startswith("linux"):
        return PLATFORM_LINUX
    if system in ("win32", "cygwin", "msys"):
        return PLATFORM_WINDOWS
    if system == "darwin":
        return PLATFORM_MACOS

    # Fallback: try platform.system() for edge cases
    system_alt = platform.system().lower()
    if "linux" in system_alt:
        return PLATFORM_LINUX
    if "windows" in system_alt or "win" in system_alt:
        return PLATFORM_WINDOWS
    if "darwin" in system_alt or "macos" in system_alt:
        return PLATFORM_MACOS

    return PLATFORM_UNKNOWN


def get_platform_detail() -> dict[str, str]:
    """
    Return a richer dictionary of OS metadata for display / reporting.

    This is purely informational and does NOT affect rule evaluation.
    """
    return {
        "platform": detect_platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": sys.version,
    }
