"""Prioritizer: rank the failures and write the copy-paste-ready fix list.

Hard boundary, and the reason this tool can be trusted: **the prioritizer never
decides PASS/FAIL.** It only ever sees findings the rule engine already
adjudicated, and it only ever ranks, explains and attaches a remediation command.

Ordering is deterministic by construction -- severity first, ``rule_id`` to break
ties -- so it does not depend on the LLM at all. If the optional LLM layer is
enabled it may replace ``why_it_matters`` prose and nothing else; the ordering
and the ``fix_command`` still come from the static tables, and any LLM-suggested
command that disagrees with the known-good table is recorded as a mismatch note
rather than shipped to the user.
"""

from __future__ import annotations

from .models import FAIL, Finding, FixItem


def _headline(finding: Finding) -> str:
    """One sentence stating what was observed, quoting the evidence."""
    first_line = finding.evidence.splitlines()[0].strip() if finding.evidence else ""
    if not first_line:
        return finding.title
    if len(first_line) > 160:
        first_line = first_line[:157] + "..."
    return f"{finding.title} failed. Observed: {first_line}"


def build_fix_list(
    findings: list[Finding],
    explanations: dict[str, str] | None = None,
) -> list[FixItem]:
    """Rank FAIL findings and attach evidence plus a remediation command.

    ``explanations`` optionally maps ``rule_id`` -> prose for ``why_it_matters``.
    A rule_id the engine never produced is ignored, so the LLM cannot introduce
    an item for a check that was not run.
    """
    explanations = explanations or {}
    failures = sorted(
        (f for f in findings if f.status == FAIL), key=lambda f: f.sort_key
    )

    items: list[FixItem] = []
    for priority, finding in enumerate(failures, start=1):
        prose = explanations.get(finding.rule_id)
        items.append(
            FixItem(
                priority=priority,
                rule_id=finding.rule_id,
                category=finding.category,
                finding=_headline(finding),
                why_it_matters=prose or finding.rationale,
                # Always the deterministic known-good command, never the LLM's.
                fix_command=finding.remediation,
                evidence_ref=finding.rule_id,
                severity=finding.severity,
                evidence=finding.evidence,
                command=finding.command,
                explanation_source="llm" if prose else "static",
            )
        )
    return items


def unknown_items(findings: list[Finding]) -> list[dict[str, str]]:
    """Rules that could not be adjudicated, with the reason -- never hidden."""
    rows = [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "command": f.command,
            "reason": f.reason or "no reason recorded",
        }
        for f in findings
        if f.status == "UNKNOWN"
    ]
    rows.sort(key=lambda r: r["rule_id"])
    return rows
