"""
main.py
=======
SENTINELAUDIT — Cross-Platform Security Auditor
Command-line entry point.

Usage
-----
    python main.py

Behaviour
---------
- Detects current OS.
- Runs the available checks for the detected platform.
- Prints findings (sorted by severity), summary counts, and security score.
- Exits 0 on success; non-zero on engine error.
"""

from __future__ import annotations

import sys

from core.detector import get_platform_detail
from core.engine import AuditEngine
from core.models import SEVERITY_ORDER

# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

_SEPARATOR = "=" * 44
_THIN_SEP  = "-" * 44

STATUS_SYMBOL = {
    "PASS":    "✅ PASS",
    "FAIL":    "❌ FAIL",
    "UNKNOWN": "⚠️  UNKNOWN",
}

SEVERITY_COLOUR_LABEL = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH",
    "MEDIUM":   "🟡 MEDIUM",
    "LOW":      "🔵 LOW",
}


def print_banner() -> None:
    print(_SEPARATOR)
    print("        SENTINELAUDIT")
    print("  Cross-Platform Security Auditor")
    print("  Evidence First — Deterministic Rules")
    print(_SEPARATOR)


def print_platform_info(detail: dict) -> None:
    print(f"\nPlatform : {detail['platform'].upper()}")
    print(f"System   : {detail['system']} {detail['release']}")
    print(f"Machine  : {detail['machine']}")


def print_finding(finding) -> None:
    symbol   = STATUS_SYMBOL.get(finding.status, finding.status)
    severity = SEVERITY_COLOUR_LABEL.get(finding.severity, finding.severity)

    print(f"\n{_THIN_SEP}")
    print(f"  {symbol}  [{finding.rule_id}]")
    print(f"  {finding.title}")
    print(f"  Severity  : {severity}")
    print(f"  Command   : {finding.command}")
    print(f"  Evidence  :")
    for line in finding.evidence.splitlines():
        print(f"    {line}")
    if finding.status != "PASS":
        print(f"  Remediation: {finding.remediation}")


def print_summary_and_score(result) -> None:
    """Print the summary block using AuditResult.summary and .score_result."""
    s = result.summary          # AuditSummary
    sr = result.score_result    # ScoreResult (may be None on error path)

    print(f"\n{_SEPARATOR}")

    # Status counts
    print(f"  Checks  : {s.total_checks}")
    print(f"  PASS    : {s.passed}")
    print(f"  FAIL    : {s.failed}")
    print(f"  UNKNOWN : {s.unknown}")

    # Severity distribution
    print()
    print(f"  Critical: {s.critical}")
    print(f"  High    : {s.high}")
    print(f"  Medium  : {s.medium}")
    print(f"  Low     : {s.low}")

    # Score bar
    print()
    bar_filled = round(s.score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    print(f"  Security Score : {s.score:>3}/100  [{bar}]")
    print(f"  Grade          : {s.grade}")

    print(_SEPARATOR)

    # Non-fatal warnings from the engine (e.g. malformed adapter findings)
    if result.has_warnings:
        print("\n  ⚠️  Engine warnings:")
        for w in result.warnings:
            print(f"     {w}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print_banner()

    # 1. Platform info (no shell commands)
    detail = get_platform_detail()
    print_platform_info(detail)

    # 2. Run the audit (engine handles detection, adapter, scoring, summary)
    print("\nRunning audit...")
    engine = AuditEngine()
    result = engine.run()

    if result.has_error:
        print(f"\n[ERROR] Audit engine failed: {result.error}", file=sys.stderr)
        return 1

    if not result.findings:
        print("\n[WARNING] No findings returned by the adapter.", file=sys.stderr)
        return 1

    # 3. Display findings sorted by severity (most severe first)
    sorted_findings = sorted(
        result.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
        reverse=True,
    )
    for finding in sorted_findings:
        print_finding(finding)

    # 4. Summary + score
    print_summary_and_score(result)

    print("\nAudit complete. No changes were made to this system.\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
