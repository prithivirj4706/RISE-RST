"""
main.py
=======
SENTINELAUDIT — Cross-Platform Security Auditor
Command-line entry point.

Usage
-----
    python main.py

Phase 1 behaviour
-----------------
- Detects current OS.
- Runs the demo check for the detected platform.
- Prints findings and security score to stdout.
- Exits 0 on success; non-zero on engine error.
"""

from __future__ import annotations

import sys

from core.detector import get_platform_detail
from core.engine import AuditEngine
from core.models import SEVERITY_ORDER
from core.scoring import calculate_score

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
    print("  Phase 1 Foundation — Evidence First")
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
    # Indent evidence lines for readability
    for line in finding.evidence.splitlines():
        print(f"    {line}")
    if finding.status != "PASS":
        print(f"  Remediation: {finding.remediation}")


def print_score(score_result) -> None:
    print(f"\n{_SEPARATOR}")
    bar_filled = round(score_result.score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    print(f"  Security Score : {score_result.score:>3}/100  [{bar}]")
    print(f"  Grade          : {score_result.grade}")
    print(f"  PASS={score_result.pass_count}  "
          f"FAIL={score_result.fail_count}  "
          f"UNKNOWN={score_result.unknown_count}")
    print(_SEPARATOR)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print_banner()

    # 1. Gather platform detail (does not execute any shell commands)
    detail = get_platform_detail()
    print_platform_info(detail)

    # 2. Run the audit
    print("\nRunning audit...")
    engine = AuditEngine()
    result = engine.run()

    if result.has_error:
        print(f"\n[ERROR] Audit engine failed: {result.error}", file=sys.stderr)
        return 1

    if not result.findings:
        print("\n[WARNING] No findings returned by the adapter.", file=sys.stderr)
        return 1

    # 3. Display findings (sorted by severity weight descending)
    sorted_findings = sorted(
        result.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
        reverse=True,
    )
    for finding in sorted_findings:
        print_finding(finding)

    # 4. Score
    score_result = calculate_score(result.findings)
    print_score(score_result)

    print("\nAudit complete. No changes were made to this system.")
    print("(Phase 1 — demo checks only. Real rules coming in Phase 2.)\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
