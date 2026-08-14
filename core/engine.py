"""
core/engine.py
==============
Central audit engine for SENTINELAUDIT.

Pipeline
--------
1. Detect the current platform.
2. Load the correct platform adapter (Linux / Windows / macOS).
3. Invoke the adapter's security checks.
4. Validate that every returned object is a Finding instance.
5. Run deterministic scoring.
6. Build AuditSummary.
7. Return a fully populated AuditResult.

Design rules
------------
- The engine NEVER decides PASS / FAIL — that is the adapter's job.
- The engine NEVER executes raw shell strings.
- Every adapter MUST implement the PlatformAdapter interface.
- Adding a new platform requires only: (a) a new adapter module and
  (b) registering it in _load_adapters() below — no other engine changes.
- Teammates returning real findings from their adapters require zero engine
  changes; the interface is: run_checks() -> list[Finding].
"""

from __future__ import annotations

import logging
from typing import Optional

from core.detector import detect_platform, get_platform_detail
from core.models import Finding
from core.scoring import AuditSummary, ScoreResult, build_summary, calculate_score

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Platform adapter interface
# ---------------------------------------------------------------------------

class PlatformAdapter:
    """
    Abstract base class for all platform adapters.

    Every adapter must implement ``run_checks`` and return a list of Finding
    objects.  The engine calls nothing else on the adapter.

    Concrete adapters live in:
        platforms/linux.py   → LinuxAdapter
        platforms/windows.py → WindowsAdapter
        platforms/macos.py   → MacOSAdapter
    """

    platform_name: str = "unknown"

    def run_checks(self) -> list[Finding]:
        """
        Run all security checks for this platform.

        Returns
        -------
        list[Finding]
            One Finding per security rule evaluated.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement run_checks()."
        )


# ---------------------------------------------------------------------------
# Adapter registry — add new platforms here
# ---------------------------------------------------------------------------

def _load_adapters() -> dict[str, type[PlatformAdapter]]:
    """
    Import platform adapters lazily so the engine does not break on
    platforms where some adapter's optional dependencies are absent.
    """
    registry: dict[str, type[PlatformAdapter]] = {}

    try:
        from platforms.linux import LinuxAdapter
        registry["linux"] = LinuxAdapter
    except ImportError as exc:
        logger.warning("Could not load Linux adapter: %s", exc)

    try:
        from platforms.windows import WindowsAdapter
        registry["windows"] = WindowsAdapter
    except ImportError as exc:
        logger.warning("Could not load Windows adapter: %s", exc)

    try:
        from platforms.macos import MacOSAdapter
        registry["macos"] = MacOSAdapter
    except ImportError as exc:
        logger.warning("Could not load macOS adapter: %s", exc)

    return registry


# ---------------------------------------------------------------------------
# Finding validation
# ---------------------------------------------------------------------------

class FindingValidationError(ValueError):
    """Raised when an adapter returns a malformed finding."""


def _validate_findings(
    raw: list,
    adapter_name: str,
) -> tuple[list[Finding], list[str]]:
    """
    Validate that every item in *raw* is a proper Finding instance.

    Returns
    -------
    (valid_findings, warnings)
        valid_findings : list[Finding]   — items that passed validation.
        warnings       : list[str]       — human-readable messages for each
                         item that was rejected.

    Rules
    -----
    - Non-Finding objects are rejected with a warning (never silently kept).
    - Duplicate rule_ids are allowed (e.g. a rule may run per-user or per-file);
      they are logged as informational messages, not errors.
    - Finding objects that failed __post_init__ validation are already invalid
      at construction time, so they never reach this function.
    """
    valid: list[Finding] = []
    warnings: list[str] = []
    seen_ids: dict[str, int] = {}

    for idx, item in enumerate(raw):
        if not isinstance(item, Finding):
            warnings.append(
                f"{adapter_name} returned a non-Finding object at index {idx}: "
                f"{type(item).__name__!r} — skipped."
            )
            continue

        # Track duplicate rule_ids (informational only).
        seen_ids[item.rule_id] = seen_ids.get(item.rule_id, 0) + 1
        if seen_ids[item.rule_id] > 1:
            logger.info(
                "Duplicate rule_id '%s' from %s (occurrence %d). "
                "This is allowed but may indicate a configuration issue.",
                item.rule_id,
                adapter_name,
                seen_ids[item.rule_id],
            )

        valid.append(item)

    return valid, warnings


# ---------------------------------------------------------------------------
# Audit result
# ---------------------------------------------------------------------------

class AuditResult:
    """
    The fully populated result returned by AuditEngine.run().

    Attributes
    ----------
    platform        : Detected platform name.
    platform_detail : Full OS metadata dictionary (from get_platform_detail).
    findings        : All validated Finding objects from the adapter.
    score_result    : Full ScoreResult (score, grade, breakdown, counts).
    summary         : AuditSummary with deterministic status/severity counts.
    error           : Non-empty string if the engine could not run.
    warnings        : List of non-fatal validation warnings from the adapter.

    Backwards-compatible properties
    --------------------------------
    .total   → int          (len of findings)
    .passed  → list[Finding]
    .failed  → list[Finding]
    .unknown → list[Finding]
    .score   → int          (final security score 0–100)

    The ``score`` and ``summary`` attributes are set to sentinel values when
    ``has_error`` is True (score=0, summary with all-zero counts).
    """

    def __init__(
        self,
        platform: str,
        platform_detail: dict,
        findings: list[Finding],
        score_result: Optional[ScoreResult] = None,
        summary: Optional[AuditSummary] = None,
        error: str = "",
        warnings: Optional[list[str]] = None,
    ) -> None:
        self.platform = platform
        self.platform_detail = platform_detail
        self.findings = findings
        self.score_result = score_result
        self.summary = summary
        self.error = error
        self.warnings: list[str] = warnings or []

    # ------------------------------------------------------------------
    # Error / warning state
    # ------------------------------------------------------------------

    @property
    def has_error(self) -> bool:
        return bool(self.error)

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)

    # ------------------------------------------------------------------
    # Backwards-compatible convenience properties
    # ------------------------------------------------------------------

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def passed(self) -> list[Finding]:
        return [f for f in self.findings if f.passed]

    @property
    def failed(self) -> list[Finding]:
        return [f for f in self.findings if f.failed]

    @property
    def unknown(self) -> list[Finding]:
        return [f for f in self.findings if f.unknown]

    @property
    def score(self) -> int:
        """Final security score (0–100). 0 when has_error is True."""
        if self.score_result is None:
            return 0
        return self.score_result.score


# ---------------------------------------------------------------------------
# Audit engine
# ---------------------------------------------------------------------------

class AuditEngine:
    """
    Orchestrates the full audit lifecycle.

    Pipeline
    --------
    detect platform → load adapter → run_checks() → validate findings
    → score → build summary → return AuditResult

    Usage
    -----
        engine = AuditEngine()
        result = engine.run()

        print(result.score)           # int 0–100
        print(result.summary)         # AuditSummary counts
        for finding in result.findings:
            print(finding)
    """

    def __init__(self, force_platform: Optional[str] = None) -> None:
        """
        Parameters
        ----------
        force_platform : str, optional
            Override platform detection. Useful for testing.
            Accepted values: "linux", "windows", "macos".
        """
        self._force_platform = force_platform

    # ------------------------------------------------------------------

    def run(self) -> AuditResult:
        """
        Execute the full audit pipeline and return an AuditResult.

        Never raises — all errors are captured in AuditResult.error.
        """
        platform_detail = get_platform_detail()
        current_platform = self._force_platform or detect_platform()

        logger.info("AuditEngine: detected platform = %s", current_platform)

        adapters = _load_adapters()

        if current_platform not in adapters:
            error_msg = (
                f"No adapter registered for platform '{current_platform}'. "
                f"Registered: {sorted(adapters.keys())}"
            )
            logger.error(error_msg)
            return self._error_result(current_platform, platform_detail, error_msg)

        adapter_class = adapters[current_platform]
        adapter: PlatformAdapter = adapter_class()

        # Step 3 — run checks
        try:
            raw_findings = adapter.run_checks()
        except Exception as exc:  # pragma: no cover
            error_msg = f"Adapter '{adapter_class.__name__}' raised: {exc}"
            logger.exception(error_msg)
            return self._error_result(current_platform, platform_detail, error_msg)

        # Step 4 — validate
        findings, warnings = _validate_findings(raw_findings, adapter_class.__name__)
        for w in warnings:
            logger.warning(w)

        # Step 5 — score
        score_result: ScoreResult = calculate_score(findings)

        # Step 6 — summary
        summary: AuditSummary = build_summary(findings, score_result.score)

        logger.info(
            "AuditEngine: %d finding(s) | score=%d | %d warning(s)",
            len(findings),
            score_result.score,
            len(warnings),
        )

        return AuditResult(
            platform=current_platform,
            platform_detail=platform_detail,
            findings=findings,
            score_result=score_result,
            summary=summary,
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _error_result(
        platform: str,
        platform_detail: dict,
        error_msg: str,
    ) -> AuditResult:
        """Return an AuditResult that signals a fatal engine error."""
        empty_summary = build_summary([], 0)
        return AuditResult(
            platform=platform,
            platform_detail=platform_detail,
            findings=[],
            score_result=None,
            summary=empty_summary,
            error=error_msg,
        )
