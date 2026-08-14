"""Re-audit: diff the current run against a previous report.

Answers the question an audit tool exists to answer -- *did the fix actually
work?* -- by comparing rule verdicts across two reports of the same target.

Both sides are read from the stored JSON, so a diff can be produced between any
two historical reports, not just against the run that just finished.
"""

from __future__ import annotations

import json
from typing import Any

from .models import FAIL, PASS, SEVERITY_ORDER, UNKNOWN, AuditReport

FIXED = "FIXED"
STILL_FAILING = "STILL_FAILING"
NEW = "NEW"
REGRESSED = "REGRESSED"
UNCHANGED_PASS = "UNCHANGED_PASS"
NOW_UNKNOWN = "NOW_UNKNOWN"
RESOLVED_UNKNOWN = "RESOLVED_UNKNOWN"
ADDED_RULE = "ADDED_RULE"
REMOVED_RULE = "REMOVED_RULE"

# Order the changes that matter to a human first.
_ORDER = [
    FIXED, STILL_FAILING, NEW, REGRESSED, NOW_UNKNOWN, RESOLVED_UNKNOWN,
    ADDED_RULE, REMOVED_RULE, UNCHANGED_PASS,
]


def load(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _classify(before: str | None, after: str | None) -> str:
    if before is None:
        return ADDED_RULE
    if after is None:
        return REMOVED_RULE
    if before == FAIL and after == PASS:
        return FIXED
    if before == FAIL and after == FAIL:
        return STILL_FAILING
    if before == FAIL and after == UNKNOWN:
        return NOW_UNKNOWN
    if before == PASS and after == FAIL:
        return REGRESSED
    if before == UNKNOWN and after == FAIL:
        return NEW
    if before == UNKNOWN and after in (PASS,):
        return RESOLVED_UNKNOWN
    if before == PASS and after == UNKNOWN:
        return NOW_UNKNOWN
    return UNCHANGED_PASS


def compare(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    before = {f["rule_id"]: f for f in previous.get("findings", [])}
    after = {f["rule_id"]: f for f in current.get("findings", [])}

    rows: list[dict[str, Any]] = []
    for rule_id in sorted(set(before) | set(after)):
        b, a = before.get(rule_id), after.get(rule_id)
        change = _classify(
            b["status"] if b else None,
            a["status"] if a else None,
        )
        source = a or b
        rows.append({
            "rule_id": rule_id,
            "title": source["title"],
            "severity": source["severity"],
            "change": change,
            "before": b["status"] if b else None,
            "after": a["status"] if a else None,
            "evidence": (a or b).get("evidence", ""),
        })

    rows.sort(key=lambda r: (
        _ORDER.index(r["change"]),
        SEVERITY_ORDER[r["severity"]],
        r["rule_id"],
    ))

    counts = {name: 0 for name in _ORDER}
    for row in rows:
        counts[row["change"]] += 1

    prev_score = int(previous.get("score", {}).get("value", 0))
    curr_score = int(current.get("score", {}).get("value", 0))

    return {
        "previous_generated_at": previous.get("generated_at"),
        "current_generated_at": current.get("generated_at"),
        "previous_fingerprint": previous.get("fingerprint"),
        "current_fingerprint": current.get("fingerprint"),
        "no_drift": previous.get("fingerprint") == current.get("fingerprint"),
        "score_before": prev_score,
        "score_after": curr_score,
        "score_delta": curr_score - prev_score,
        "counts": counts,
        "changes": rows,
    }


def render(diff: dict[str, Any]) -> str:
    out: list[str] = []
    w = out.append

    w("# Re-audit diff\n")
    w(f"**Previous run:** {diff['previous_generated_at']}  ")
    w(f"**Current run:** {diff['current_generated_at']}\n")
    w(f"**Security score:** {diff['score_before']} -> {diff['score_after']} "
      f"({diff['score_delta']:+d})\n")

    if diff["no_drift"]:
        w("> Both reports share the fingerprint "
          f"`{diff['current_fingerprint']}`. The target is unchanged and the "
          "tool produced a byte-identical result.\n")

    interesting = [
        r for r in diff["changes"]
        if r["change"] not in (UNCHANGED_PASS,)
    ]
    if not interesting:
        w("No verdict changed between the two runs.\n")
        return "\n".join(out) + "\n"

    w("| Rule | Change | Before | After | Severity | Title |")
    w("| --- | --- | --- | --- | --- | --- |")
    for row in interesting:
        w(f"| `{row['rule_id']}` | **{row['change']}** | {row['before'] or '-'} "
          f"| {row['after'] or '-'} | {row['severity']} | {row['title']} |")
    w("")
    return "\n".join(out) + "\n"


def render_terminal(diff: dict[str, Any]) -> str:
    marks = {
        FIXED: "[+] FIXED         ",
        STILL_FAILING: "[!] STILL FAILING ",
        NEW: "[N] NEW           ",
        REGRESSED: "[R] REGRESSED     ",
        NOW_UNKNOWN: "[?] NOW UNKNOWN   ",
        RESOLVED_UNKNOWN: "[+] NOW READABLE  ",
        ADDED_RULE: "[A] NEW RULE      ",
        REMOVED_RULE: "[D] RULE REMOVED  ",
    }
    lines = [
        "",
        "RE-AUDIT",
        f"  BEFORE: {diff['score_before']}/100",
        f"  AFTER:  {diff['score_after']}/100  ({diff['score_delta']:+d})",
        "",
    ]
    shown = [r for r in diff["changes"] if r["change"] in marks]
    if not shown:
        lines.append("  No verdict changed between the two runs.")
    for row in shown:
        lines.append(f"  {marks[row['change']]} {row['rule_id']:<20} {row['title']}")
    lines.append("")
    return "\n".join(lines)


def diff_reports(previous_path: str, current: AuditReport) -> dict[str, Any]:
    return compare(load(previous_path), current.to_dict())
