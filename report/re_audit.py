"""
report/re_audit.py
==================
Re-audit / delta comparison for SENTINELAUDIT.

Status: PHASE 1 STUB — interface defined, implementation in Phase 2.
Implementation: assigned to the macOS + reporting contributor.

Purpose
-------
Compare the findings from two consecutive audits and surface:
  - Regressions  : checks that were PASS and are now FAIL
  - Improvements : checks that were FAIL and are now PASS
  - New issues   : checks that are FAIL in the new run but didn't exist before
  - Resolved     : checks that were FAIL and no longer appear

Interface contract
------------------
accept two AuditResult objects (baseline, current) and return a
ReAuditDelta object describing the differences.
"""

from __future__ import annotations

# from core.engine import AuditResult  # uncomment when implementing
# from core.models import Finding      # uncomment when implementing


class ReAuditDelta:
    """
    Represents the difference between two consecutive audits.

    Attributes (to be populated in Phase 2)
    -----------------------------------------
    regressions  : list[Finding]  — previously PASS, now FAIL
    improvements : list[Finding]  — previously FAIL, now PASS
    new_issues   : list[Finding]  — new FAIL findings
    resolved     : list[Finding]  — FAIL findings no longer present
    unchanged    : list[Finding]  — same status in both audits
    """

    def __init__(self) -> None:
        self.regressions: list  = []
        self.improvements: list = []
        self.new_issues: list   = []
        self.resolved: list     = []
        self.unchanged: list    = []


def compare_audits(baseline, current) -> ReAuditDelta:
    """
    Compare two AuditResult objects and return a ReAuditDelta.

    Phase 1 stub — not yet implemented.
    """
    raise NotImplementedError(
        "Re-audit comparison is a Phase 2 feature. "
        "Implement in report/re_audit.py."
    )
