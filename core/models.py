"""
core/models.py
==============
Central data model for SENTINELAUDIT.

Every security rule on every platform MUST return a Finding object.
The schema is intentionally stable — do NOT change field names without
coordinating with all platform and rules contributors.

Status values  : PASS | FAIL | UNKNOWN
Severity values: CRITICAL | HIGH | MEDIUM | LOW
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# ---------------------------------------------------------------------------
# Type aliases (used for IDE auto-complete and static analysis)
# ---------------------------------------------------------------------------

StatusType = Literal["PASS", "FAIL", "UNKNOWN"]
SeverityType = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
PlatformType = Literal["linux", "windows", "macos", "unknown"]

# Ordered severity levels — used by scoring and sorting helpers.
SEVERITY_ORDER: dict[SeverityType, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

VALID_STATUSES: frozenset[str] = frozenset({"PASS", "FAIL", "UNKNOWN"})
VALID_SEVERITIES: frozenset[str] = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})


# ---------------------------------------------------------------------------
# Finding — the canonical result of one security rule evaluation
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    Represents the outcome of a single security rule evaluation.

    Fields
    ------
    rule_id     : Unique rule identifier, e.g. "FW-001".
    platform    : Normalized OS name: "linux", "windows", "macos", or "unknown".
    title       : Short human-readable description of the check.
    status      : "PASS", "FAIL", or "UNKNOWN".
    severity    : "CRITICAL", "HIGH", "MEDIUM", or "LOW".
    command     : The exact read-only command that was executed (for audit trail).
    evidence    : Raw stdout/stderr captured from the command.
    remediation : Human-readable recommendation if status is FAIL or UNKNOWN.

    Constraints
    -----------
    - status    must be one of VALID_STATUSES.
    - severity  must be one of VALID_SEVERITIES.
    - command   must be the real command string; never an LLM-generated string.
    - evidence  must be actual captured output; never fabricated.
    """

    rule_id: str
    platform: str
    title: str
    status: StatusType
    severity: SeverityType
    command: str
    evidence: str
    remediation: str

    # Optional metadata — contributors may add structured context here.
    # Keep it simple; a plain dict is intentional.
    extra: dict = field(default_factory=dict, compare=False, repr=False)

    # ------------------------------------------------------------------
    def __post_init__(self) -> None:
        """Validate field values immediately after construction."""
        if self.status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status '{self.status}'. "
                f"Must be one of: {sorted(VALID_STATUSES)}"
            )
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{self.severity}'. "
                f"Must be one of: {sorted(VALID_SEVERITIES)}"
            )
        if not self.rule_id.strip():
            raise ValueError("rule_id must not be empty.")
        if not self.title.strip():
            raise ValueError("title must not be empty.")

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    @property
    def failed(self) -> bool:
        return self.status == "FAIL"

    @property
    def unknown(self) -> bool:
        return self.status == "UNKNOWN"

    @property
    def severity_weight(self) -> int:
        """Numeric weight for the severity (higher = more severe)."""
        return SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict:
        """Return a plain dictionary representation (useful for serialisation)."""
        return {
            "rule_id": self.rule_id,
            "platform": self.platform,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "command": self.command,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }

    def __str__(self) -> str:
        return (
            f"[{self.status}] {self.rule_id} | {self.title} "
            f"| Severity: {self.severity} | Platform: {self.platform}"
        )
