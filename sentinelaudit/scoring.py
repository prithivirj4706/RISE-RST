"""Deterministic security score and severity-weighted summary.

The score is a communication device, not a verdict: it is derived entirely from
the findings, so two runs with the same findings always produce the same number.
UNKNOWN never costs points -- an audit that could not read something has not
found a problem, and inventing a deduction would be exactly the kind of
unevidenced claim this tool exists to avoid. UNKNOWNs are surfaced as coverage
instead, so a reader can see how much of the rule set actually ran.
"""

from __future__ import annotations

from .models import (
    FAIL,
    PASS,
    SEVERITY_ORDER,
    SEVERITY_WEIGHT,
    UNKNOWN,
    Finding,
)


def summarize(findings: list[Finding]) -> dict[str, object]:
    by_status = {PASS: 0, FAIL: 0, UNKNOWN: 0}
    by_severity = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        by_status[finding.status] += 1
        if finding.status == FAIL:
            by_severity[finding.severity] += 1

    return {
        "rules_evaluated": len(findings),
        "passed": by_status[PASS],
        "failed": by_status[FAIL],
        "unknown": by_status[UNKNOWN],
        "failed_by_severity": by_severity,
    }


def score(findings: list[Finding]) -> dict[str, object]:
    deductions = [
        {"rule_id": f.rule_id, "severity": f.severity,
         "points": SEVERITY_WEIGHT[f.severity]}
        for f in findings
        if f.status == FAIL
    ]
    deductions.sort(key=lambda d: (SEVERITY_ORDER[str(d["severity"])], str(d["rule_id"])))
    total_deducted = sum(int(d["points"]) for d in deductions)
    value = max(0, 100 - total_deducted)

    conclusive = sum(1 for f in findings if f.status != UNKNOWN)
    coverage = round(100.0 * conclusive / len(findings), 1) if findings else 0.0
    sufficient = coverage >= MIN_COVERAGE_FOR_GRADE

    note = (
        f"{conclusive} of {len(findings)} rules reached a PASS/FAIL verdict; "
        f"{len(findings) - conclusive} returned UNKNOWN and are excluded from "
        "the score."
    )
    if not sufficient:
        note += (
            f" Coverage is below {MIN_COVERAGE_FOR_GRADE:.0f}%, so no grade is "
            "issued: too little of the rule set was observable for the score to "
            "mean anything."
        )

    return {
        "value": value,
        "max": 100,
        "grade": _grade(value) if sufficient else "INSUFFICIENT-DATA",
        "sufficient_coverage": sufficient,
        "points_deducted": total_deducted,
        "coverage_percent": coverage,
        "coverage_note": note,
        "weights": dict(SEVERITY_WEIGHT),
        "deductions": deductions,
    }


# Below this share of conclusive verdicts, a high score says more about what the
# audit could not read than about the host, so we refuse to grade it. A tool
# that reports "100/100, grade A" after failing to run 9 of 11 checks is exactly
# the confidently-wrong output this project exists to avoid.
MIN_COVERAGE_FOR_GRADE = 60.0


def _grade(value: int) -> str:
    if value >= 90:
        return "A"
    if value >= 75:
        return "B"
    if value >= 60:
        return "C"
    if value >= 40:
        return "D"
    return "F"
