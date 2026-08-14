"""
platforms/windows.py
====================
Windows platform adapter for SENTINELAUDIT.

Current state: Phase 1 foundation — placeholder only.
Windows security rule coverage will be added in a future phase by
the designated Windows contributor.

When adding real Windows security rules:
1. Add the command to ALLOWED_COMMANDS (prefer PowerShell with -NonInteractive).
2. Implement a _check_<name>() method that uses self._collector.
3. Call it from run_checks() and append the Finding to results.
4. Import the matching rule from rules/windows_rules.py.

Note: All PowerShell commands must be read-only.
      Never use Invoke-Expression or similar dynamic-eval primitives.
"""

from __future__ import annotations

import logging

from core.collector import make_collector
from core.engine import PlatformAdapter
from core.models import Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowed read-only commands for Windows
# (expand this list as real rules are added)
# ---------------------------------------------------------------------------

ALLOWED_COMMANDS: dict[str, list[str]] = {
    # DEMO — used only to verify the pipeline works end-to-end.
    # PowerShell: get Windows version info without any modifications.
    "demo_winver": [
        "powershell",
        "-NonInteractive",
        "-Command",
        "[System.Environment]::OSVersion.VersionString",
    ],
    # Real commands will be added here by the Windows rules contributor.
}


class WindowsAdapter(PlatformAdapter):
    """
    Runs security checks on a Windows host.

    Placeholder — no production checks are implemented yet.
    """

    platform_name = "windows"

    def __init__(self) -> None:
        self._collector = make_collector(ALLOWED_COMMANDS)

    # ------------------------------------------------------------------
    # PlatformAdapter interface
    # ------------------------------------------------------------------

    def run_checks(self) -> list[Finding]:
        """
        Run all currently implemented Windows security checks.

        Returns
        -------
        list[Finding]
            One Finding per check executed.
        """
        results: list[Finding] = []

        # ── DEMO CHECK ────────────────────────────────────────────────
        results.append(self._demo_winver_check())
        # ─────────────────────────────────────────────────────────────

        # Real checks will be added here, e.g.:
        # results.append(self._check_windows_firewall())
        # results.append(self._check_windows_defender())

        logger.info("WindowsAdapter: completed %d check(s).", len(results))
        return results

    # ------------------------------------------------------------------
    # Demo check (REMOVE when real rules are in place)
    # ------------------------------------------------------------------

    def _demo_winver_check(self) -> Finding:
        """
        [DEMO] Verifies that PowerShell is accessible and readable.

        This is NOT a real security check. Pipeline smoke-test only.
        """
        result = self._collector.run("demo_winver")

        if result.ok:
            status = "PASS"
            evidence = f"[DEMO] Windows OS version: {result.stdout}"
        else:
            status = "UNKNOWN"
            evidence = f"[DEMO] PowerShell query failed: {result.error or result.stderr}"

        return Finding(
            rule_id="DEMO-WIN-001",
            platform="windows",
            title="[DEMO] Pipeline Smoke Test — PowerShell accessible",
            status=status,
            severity="LOW",
            command=" ".join(ALLOWED_COMMANDS["demo_winver"]),
            evidence=evidence,
            remediation=(
                "This is a demo check only. "
                "No remediation required. "
                "Replace with real Windows security rules."
            ),
        )
