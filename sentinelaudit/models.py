"""Core data shapes shared by every stage of the pipeline.

The schemas here are the interface contract between collector -> rule engine ->
prioritizer -> reporter. Nothing downstream is allowed to invent its own shape.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Verdicts and severities
# ---------------------------------------------------------------------------

PASS = "PASS"
FAIL = "FAIL"
UNKNOWN = "UNKNOWN"
VALID_STATUS = (PASS, FAIL, UNKNOWN)

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

# Lower number == more urgent. Used as the primary deterministic sort key.
SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

# Points deducted from a 100-point baseline for each FAIL at this severity.
SEVERITY_WEIGHT = {CRITICAL: 25, HIGH: 12, MEDIUM: 6, LOW: 2}

# The handout's findings contract uses a lowercase `severity_hint`.
SEVERITY_HINT = {CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low"}


# ---------------------------------------------------------------------------
# Collector output
# ---------------------------------------------------------------------------


@dataclass
class CommandResult:
    """Captured output of one allowlisted command run against the target.

    Every field here is raw observation. No interpretation happens at this
    layer -- that is the rule engine's job.
    """

    command_id: str
    argv: list[str]
    display: str  # human-readable rendering of argv, for the report
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    available: bool = True  # False when the binary is missing on the target
    error: str | None = None  # transport-level failure reason, if any

    @property
    def ok(self) -> bool:
        return self.available and self.error is None and self.exit_code == 0

    @property
    def permission_denied(self) -> bool:
        blob = f"{self.stderr}\n{self.stdout}".lower()
        return any(
            marker in blob
            for marker in (
                "permission denied",
                "operation not permitted",
                "must be run as root",
                "you need to be root",
                "requires root",
                "access is denied",
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "command": self.display,
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "available": self.available,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Rule engine output
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """One rule's verdict plus the evidence that backs it.

    Key set is a superset of the handout's findings contract
    (rule_id / title / command / status / evidence / severity_hint) and of the
    team's agreed platform contract (rule_id / platform / title / status /
    severity / command / evidence / remediation), so both consumers are happy.
    """

    rule_id: str
    control_id: str  # portable cross-platform control, e.g. "FW-001"
    platform: str
    title: str
    category: str
    status: str
    severity: str
    command: str  # the command whose output produced the evidence
    command_id: str
    evidence: str
    remediation: str
    rationale: str
    reason: str | None = None  # why UNKNOWN, when status is UNKNOWN

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUS:
            raise ValueError(f"{self.rule_id}: bad status {self.status!r}")
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"{self.rule_id}: bad severity {self.severity!r}")

    @property
    def severity_hint(self) -> str:
        return SEVERITY_HINT[self.severity]

    @property
    def sort_key(self) -> tuple[int, str]:
        """Deterministic ordering: severity first, then rule_id to break ties."""
        return (SEVERITY_ORDER[self.severity], self.rule_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "control_id": self.control_id,
            "platform": self.platform,
            "title": self.title,
            "category": self.category,
            "status": self.status,
            "severity": self.severity,
            "severity_hint": self.severity_hint,
            "command": self.command,
            "command_id": self.command_id,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "rationale": self.rationale,
            "reason": self.reason,
        }


# ---------------------------------------------------------------------------
# Prioritizer output
# ---------------------------------------------------------------------------


@dataclass
class FixItem:
    """One entry in the prioritized, copy-paste-ready remediation plan.

    Mirrors the handout's fix-list contract exactly, plus severity/evidence so a
    reader never has to cross-reference the findings array by hand.
    """

    priority: int
    rule_id: str
    category: str
    finding: str
    why_it_matters: str
    fix_command: str
    evidence_ref: str
    severity: str
    evidence: str
    command: str
    explanation_source: str = "static"  # "static" or "llm"

    def to_dict(self) -> dict[str, Any]:
        return {
            "priority": self.priority,
            "rule_id": self.rule_id,
            "category": self.category,
            "finding": self.finding,
            "why_it_matters": self.why_it_matters,
            "fix_command": self.fix_command,
            "evidence_ref": self.evidence_ref,
            "severity": self.severity,
            "evidence": self.evidence,
            "command": self.command,
            "explanation_source": self.explanation_source,
        }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


@dataclass
class AuditReport:
    schema_version: str
    tool_version: str
    generated_at: str  # the ONLY field allowed to differ between two runs
    target: dict[str, Any]
    platform: str
    summary: dict[str, Any]
    score: dict[str, Any]
    findings: list[Finding]
    fix_list: list[FixItem]
    commands: list[CommandResult]
    notes: list[str] = field(default_factory=list)
    fingerprint: str = ""

    def stable_payload(self) -> dict[str, Any]:
        """Everything except the timestamp -- this is what must not drift."""
        return {
            "schema_version": self.schema_version,
            "platform": self.platform,
            "target": {k: v for k, v in self.target.items() if k != "resolved_at"},
            "summary": self.summary,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
            "fix_list": [f.to_dict() for f in self.fix_list],
        }

    def compute_fingerprint(self) -> str:
        blob = json.dumps(self.stable_payload(), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "generated_at": self.generated_at,
            "fingerprint": self.fingerprint,
            "platform": self.platform,
            "target": self.target,
            "summary": self.summary,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
            "fix_list": [f.to_dict() for f in self.fix_list],
            "commands": [c.to_dict() for c in self.commands],
            "notes": list(self.notes),
        }
