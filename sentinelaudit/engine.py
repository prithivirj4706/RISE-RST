"""The rule engine: collect once, evaluate deterministically.

This is the only component that decides PASS / FAIL / UNKNOWN. Nothing
downstream -- not the prioritizer, not the LLM, not the reporter -- may change a
verdict. Verdicts come from parsers reading captured output, full stop.
"""

from __future__ import annotations

from typing import Callable, Iterable

from . import allowlist
from .connectors.base import Connector, ConnectorError
from .models import UNKNOWN, CommandResult, Finding
from .rules import load_rules
from .rules.base import Context, Rule

ProgressFn = Callable[[int, int, str], None]


def collect(
    connector: Connector,
    rules: Iterable[Rule],
    progress: ProgressFn | None = None,
) -> tuple[dict[str, CommandResult], dict[str, list[str]], list[str]]:
    """Run every allowlisted command the loaded rules need, exactly once.

    Returns ``(results_by_id, rules_fed_by_command, notes)``. Each command is
    tagged with the rules it feeds so a reader can trace evidence in either
    direction.
    """
    needed: set[str] = set()
    feeds: dict[str, list[str]] = {}
    for rule in rules:
        for cid in rule.commands:
            needed.add(cid)
            feeds.setdefault(cid, []).append(rule.rule_id)
    for cid in feeds:
        feeds[cid].sort()

    # Sorted so the collection order -- and therefore any partial run -- is
    # identical between two invocations.
    ordered = sorted(needed)
    results: dict[str, CommandResult] = {}
    notes: list[str] = []

    for index, cid in enumerate(ordered, start=1):
        spec = allowlist.get(cid)
        if progress:
            progress(index, len(ordered), spec.description)
        try:
            result = connector.run(spec)
        except ConnectorError:
            raise
        except Exception as exc:  # noqa: BLE001 - one bad command must not kill the run
            result = CommandResult(
                command_id=cid,
                argv=list(spec.argv),
                display=spec.display,
                available=False,
                error=f"collector error: {exc}",
            )
        results[cid] = result

        if not result.available:
            notes.append(f"{cid}: skipped -- {result.error or 'unavailable on target'}")
        elif result.error:
            notes.append(f"{cid}: {result.error}")
        elif result.permission_denied:
            notes.append(f"{cid}: permission denied for the audit user")

    return results, feeds, notes


def evaluate(
    rules: Iterable[Rule],
    results: dict[str, CommandResult],
    platform: str,
) -> list[Finding]:
    """Turn captured output into evidenced findings, sorted deterministically."""
    findings: list[Finding] = []

    for rule in rules:
        ctx = Context(results, rule)
        try:
            verdict = rule.parser(ctx)
        except Exception as exc:  # noqa: BLE001 - a broken parser is UNKNOWN, not a crash
            from .rules.base import verdict_unknown

            verdict = verdict_unknown(
                f"parser raised {type(exc).__name__}: {exc}", rule.primary_command
            )

        cited = verdict.command_id or rule.primary_command
        cited_result = results.get(cited)
        command_display = (
            cited_result.display if cited_result else allowlist.get(cited).display
        )

        findings.append(
            Finding(
                rule_id=rule.rule_id,
                control_id=rule.control_id,
                platform=platform,
                title=rule.title,
                category=rule.category,
                status=verdict.status,
                severity=rule.severity,
                command=command_display,
                command_id=cited,
                evidence=verdict.evidence.strip(),
                remediation=rule.remediation,
                rationale=rule.rationale,
                reason=verdict.reason if verdict.status == UNKNOWN else None,
            )
        )

    findings.sort(key=lambda f: f.sort_key)
    return findings


def audit(
    connector: Connector,
    platform: str,
    progress: ProgressFn | None = None,
) -> tuple[list[Finding], dict[str, CommandResult], dict[str, list[str]], list[str]]:
    rules = load_rules(platform)
    results, feeds, notes = collect(connector, rules, progress)
    findings = evaluate(rules, results, platform)
    return findings, results, feeds, notes
