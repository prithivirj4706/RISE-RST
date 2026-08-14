"""
platforms/linux.py
==================
Linux platform adapter for SENTINELAUDIT.

Primary platform — Linux will have the most complete rule coverage.

Current state: Phase 1 foundation.
Only a single DEMO check is implemented so the full pipeline can be
exercised end-to-end. The demo check is clearly labelled.

When adding real Linux security rules:
1. Add the command to ALLOWED_COMMANDS.
2. Implement a _check_<name>() method that uses self._collector.
3. Call it from run_checks() and append the Finding to results.
4. Import the matching rule from rules/linux_rules.py.
"""

from __future__ import annotations

import logging

from core.collector import make_collector
from core.engine import PlatformAdapter
from core.models import Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowed read-only commands for Linux
# (expand this list as real rules are added)
# ---------------------------------------------------------------------------

ALLOWED_COMMANDS: dict[str, list[str]] = {
    # DEMO — used only to verify the pipeline works end-to-end.
    "demo_uname": ["uname", "-a"],
    # Real commands will be added here by the Linux rules contributor.
    # Example (do NOT uncomment until the rule is implemented):
    # "firewall_ufw_status": ["ufw", "status"],
    # "sshd_config":         ["cat", "/etc/ssh/sshd_config"],
    # "passwd_file":         ["cat", "/etc/passwd"],
}


class LinuxAdapter(PlatformAdapter):
    """
    Runs security checks on a Linux host.

    All checks are read-only. No files are modified. No services are
    restarted. The host is never altered in any way.
    """

    platform_name = "linux"

    def __init__(self) -> None:
        self._collector = make_collector(ALLOWED_COMMANDS)

    # ------------------------------------------------------------------
    # PlatformAdapter interface
    # ------------------------------------------------------------------

    def run_checks(self) -> list[Finding]:
        """
        Run all currently implemented Linux security checks.

        Returns
        -------
        list[Finding]
            One Finding per check executed.
        """
        results: list[Finding] = []

        # ── DEMO CHECK ────────────────────────────────────────────────
        # This check exists ONLY to prove the pipeline works.
        # Replace/remove it once real Linux rules are contributed.
        results.append(self._demo_uname_check())
        # ─────────────────────────────────────────────────────────────

        # Real checks will be added here, e.g.:
        # results.append(self._check_firewall())
        # results.append(self._check_ssh_root_login())

        logger.info("LinuxAdapter: completed %d check(s).", len(results))
        return results

    # ------------------------------------------------------------------
    # Demo check (REMOVE when real rules are in place)
    # ------------------------------------------------------------------

    def _demo_uname_check(self) -> Finding:
        """
        [DEMO] Verifies that uname is accessible and readable.

        This is NOT a real security check. It is a pipeline smoke-test.
        Status is always PASS when uname runs; UNKNOWN otherwise.
        """
        result = self._collector.run("demo_uname")

        if result.ok:
            status = "PASS"
            evidence = f"[DEMO] uname output: {result.stdout}"
        else:
            status = "UNKNOWN"
            evidence = f"[DEMO] uname failed: {result.error or result.stderr}"

        return Finding(
            rule_id="DEMO-LNX-001",
            platform="linux",
            title="[DEMO] Pipeline Smoke Test — uname accessible",
            status=status,
            severity="LOW",
            command=" ".join(ALLOWED_COMMANDS["demo_uname"]),
            evidence=evidence,
            remediation=(
                "This is a demo check only. "
                "No remediation required. "
                "Replace with real Linux security rules."
            ),
        )
