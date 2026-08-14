"""Rule definitions and the evaluation context handed to every parser.

A rule is data plus one small pure function. The function receives already
captured command output -- it can never run anything itself -- and returns a
verdict with the exact evidence excerpt that justifies it.

Parsers are deliberately boring: regex and exact matching against known-good
patterns, per the handout. Anything a parser cannot confidently read becomes
UNKNOWN with a logged reason, never a guessed PASS or FAIL.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from ..models import FAIL, PASS, UNKNOWN, CommandResult


@dataclass(frozen=True)
class Verdict:
    status: str
    evidence: str
    command_id: str | None = None
    reason: str | None = None


def verdict_pass(evidence: str, command_id: str | None = None) -> Verdict:
    return Verdict(PASS, evidence, command_id)


def verdict_fail(evidence: str, command_id: str | None = None) -> Verdict:
    return Verdict(FAIL, evidence, command_id)


def verdict_unknown(reason: str, command_id: str | None = None,
                    evidence: str = "") -> Verdict:
    return Verdict(UNKNOWN, evidence or f"(no usable output: {reason})",
                   command_id, reason)


@dataclass(frozen=True)
class Rule:
    rule_id: str          # CIS-style identifier, cited in the report
    control_id: str       # portable cross-platform control, e.g. "FW-001"
    platform: str
    title: str
    category: str
    severity: str
    commands: tuple[str, ...]   # allowlist command_ids this rule may read
    primary_command: str        # cited when the parser does not pick one
    rationale: str              # why this matters, static and always available
    remediation: str            # known-good remediation command
    parser: Callable[["Context"], Verdict]


class Context:
    """Read-only view over the commands captured for one audit run."""

    def __init__(self, results: dict[str, CommandResult], rule: Rule) -> None:
        self._results = results
        self._rule = rule

    def result(self, command_id: str) -> CommandResult | None:
        if command_id not in self._rule.commands:
            raise KeyError(
                f"{self._rule.rule_id} tried to read {command_id!r}, which is not "
                f"in its declared command list"
            )
        return self._results.get(command_id)

    def usable(self, command_id: str) -> CommandResult | None:
        """The result only if it actually produced readable output."""
        res = self.result(command_id)
        if res is None or not res.available or res.error:
            return None
        if res.exit_code != 0 and not res.stdout:
            return None
        return res

    def stdout(self, command_id: str) -> str:
        res = self.usable(command_id)
        return res.stdout if res else ""

    def first_usable(self, *command_ids: str) -> CommandResult | None:
        for cid in command_ids:
            res = self.usable(cid)
            if res and res.stdout:
                return res
        return None

    def why_unavailable(self, *command_ids: str) -> str:
        """A single honest sentence explaining why nothing could be read."""
        parts: list[str] = []
        for cid in command_ids:
            res = self.result(cid)
            if res is None:
                parts.append(f"{cid}: not collected")
            elif not res.available:
                parts.append(f"{cid}: {res.error or 'binary unavailable'}")
            elif res.permission_denied:
                parts.append(f"{cid}: permission denied")
            elif res.error:
                parts.append(f"{cid}: {res.error}")
            elif not res.stdout:
                parts.append(f"{cid}: empty output (exit {res.exit_code})")
            else:
                parts.append(f"{cid}: unparseable output")
        return "; ".join(parts)


# ---------------------------------------------------------------------------
# Parser helpers
# ---------------------------------------------------------------------------


def excerpt(text: str, limit: int = 12) -> str:
    """Trim long output to a stable, quotable excerpt."""
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    if len(lines) <= limit:
        return "\n".join(lines)
    hidden = len(lines) - limit
    return "\n".join(lines[:limit] + [f"... ({hidden} more lines)"])


def matching_lines(text: str, pattern: str, limit: int = 12) -> list[str]:
    """Lines matching a regex, sorted so evidence never reorders between runs."""
    rx = re.compile(pattern, re.IGNORECASE)
    hits = sorted({ln.strip() for ln in text.splitlines() if ln.strip() and rx.search(ln)})
    return hits[:limit]


def keyword_value(text: str, keyword: str) -> str | None:
    """First value for ``keyword`` in ``key value`` or ``key=value`` output."""
    rx = re.compile(rf"^\s*{re.escape(keyword)}\s*[=:]?\s+(.+?)\s*$", re.IGNORECASE)
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = rx.match(line)
        if m:
            return m.group(1).strip().strip('"').strip(";")
    return None


def uncommented_lines(text: str) -> list[str]:
    return [
        ln.strip() for ln in text.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
