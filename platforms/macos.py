"""
platforms/macos.py
==================
macOS platform adapter for SENTINELAUDIT.

Current state: Phase 1 foundation.
One DEMO check is implemented to exercise the full pipeline.
Full macOS rule coverage will be added in a future phase by
the designated macOS / reporting contributor.

When adding real macOS security rules:
1. Add the command to ALLOWED_COMMANDS.
2. Implement a _check_<name>() method that uses self._collector.
3. Call it from run_checks() and append the Finding to results.
4. Import the matching rule from rules/macos_rules.py.
"""

from __future__ import annotations

import logging

from core.collector import make_collector
from core.engine import PlatformAdapter
from core.models import Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowed read-only commands for macOS
# (expand this list as real rules are added)
# ---------------------------------------------------------------------------

ALLOWED_COMMANDS: dict[str, list[str]] = {
    # DEMO — pipeline smoke-test.
    "demo_sw_vers": ["sw_vers"],
    # Real commands will be added here by the macOS rules contributor.
    # Example (do NOT uncomment until the rule is implemented):
    # "firewall_status": [
    #     "/usr/libexec/ApplicationFirewall/socketfilterfw",
    #     "--getglobalstate",
    # ],
    # "sip_status":      ["csrutil", "status"],
    # "filevault_status":["fdesetup",  "status"],
}


class MacOSAdapter(PlatformAdapter):
    """
    Runs security checks on a macOS host.

    All checks are read-only. The host is never modified.
    """

    platform_name = "macos"

    def __init__(self) -> None:
        self._collector = make_collector(ALLOWED_COMMANDS)

    # ------------------------------------------------------------------
    # PlatformAdapter interface
    # ------------------------------------------------------------------

    def run_checks(self) -> list[Finding]:
        """
        Run all currently implemented macOS security checks.

        Returns
        -------
        list[Finding]
            One Finding per check executed.
        """
        results: list[Finding] = []

        # ── DEMO CHECK ────────────────────────────────────────────────
        results.append(self._demo_sw_vers_check())
        # ─────────────────────────────────────────────────────────────

        # Real checks will be added here, e.g.:
        # results.append(self._check_firewall())
        # results.append(self._check_sip())
        # results.append(self._check_filevault())

        logger.info("MacOSAdapter: completed %d check(s).", len(results))
        return results

    # ------------------------------------------------------------------
    # Demo check (REMOVE when real rules are in place)
    # ------------------------------------------------------------------

    def _demo_sw_vers_check(self) -> Finding:
        """
        [DEMO] Verifies that sw_vers is accessible and readable.

        This is NOT a real security check. Pipeline smoke-test only.
        Status is PASS when sw_vers runs successfully; UNKNOWN otherwise.
        """
        result = self._collector.run("demo_sw_vers")

        if result.ok:
            status = "PASS"
            evidence = f"[DEMO] macOS version info:\n{result.stdout}"
        else:
            status = "UNKNOWN"
            evidence = (
                f"[DEMO] sw_vers failed: {result.error or result.stderr}"
            )

        return Finding(
            rule_id="DEMO-MAC-001",
            platform="macos",
            title="[DEMO] Pipeline Smoke Test — sw_vers accessible",
            status=status,
            severity="LOW",
            command=" ".join(ALLOWED_COMMANDS["demo_sw_vers"]),
            evidence=evidence,
            remediation=(
                "This is a demo check only. "
                "No remediation required. "
                "Replace with real macOS security rules."
            ),
        )
