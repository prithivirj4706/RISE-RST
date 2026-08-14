"""Target operating-system detection.

Detection runs *over the connector*, not on the machine the agent happens to be
installed on -- otherwise auditing a Linux container from a Mac would load the
wrong rule set. Two allowlisted probes are enough: ``uname -s`` covers every
POSIX target, and a PowerShell environment read covers Windows.
"""

from __future__ import annotations

from .. import allowlist
from ..connectors.base import Connector

SUPPORTED = ("linux", "macos", "windows")

_UNAME_MAP = {
    "linux": "linux",
    "darwin": "macos",
}


class DetectionError(RuntimeError):
    """The target's operating system could not be identified."""


def detect(connector: Connector) -> tuple[str, str]:
    """Return ``(platform, evidence)`` for the target behind ``connector``."""
    uname = connector.run(allowlist.get("probe.uname"), timeout=15)
    if uname.ok and uname.stdout:
        kernel = uname.stdout.strip().splitlines()[0].strip().lower()
        platform = _UNAME_MAP.get(kernel)
        if platform:
            return platform, f"uname -s -> {uname.stdout.strip()}"
        raise DetectionError(
            f"unsupported kernel {uname.stdout.strip()!r}; supported targets are "
            + ", ".join(SUPPORTED)
        )

    win = connector.run(allowlist.get("probe.windows"), timeout=30)
    if win.ok and "windows" in win.stdout.lower():
        return "windows", f"$env:OS -> {win.stdout.strip()}"

    raise DetectionError(
        "neither `uname -s` nor a PowerShell probe identified the target "
        f"(uname: {uname.error or uname.stderr or 'no output'}; "
        f"powershell: {win.error or win.stderr or 'no output'})"
    )
