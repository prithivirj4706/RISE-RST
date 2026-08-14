"""
core/engine.py
==============
Central audit engine for SENTINELAUDIT.

Responsibilities
----------------
1. Detect the current platform.
2. Load the correct platform adapter (Linux / Windows / macOS).
3. Invoke the adapter's security checks.
4. Collect and return a list of Finding objects.

Design rules
------------
- The engine NEVER decides PASS / FAIL — that is the adapter's job.
- The engine NEVER executes raw shell strings.
- Every adapter MUST implement the PlatformAdapter interface.
- Adding a new platform requires only: (a) a new adapter module and
  (b) registering it in _ADAPTER_REGISTRY below.
"""

from __future__ import annotations

import logging
from typing import Optional

from core.detector import detect_platform, get_platform_detail
from core.models import Finding

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
# Audit result
# ---------------------------------------------------------------------------

class AuditResult:
    """
    Container returned by AuditEngine.run().

    Attributes
    ----------
    platform    : Detected platform name.
    platform_detail : Full OS metadata dictionary.
    findings    : All Finding objects returned by the adapter.
    error       : Non-empty if the engine could not run (adapter missing, etc.)
    """

    def __init__(
        self,
        platform: str,
        platform_detail: dict,
        findings: list[Finding],
        error: str = "",
    ) -> None:
        self.platform = platform
        self.platform_detail = platform_detail
        self.findings = findings
        self.error = error

    @property
    def has_error(self) -> bool:
        return bool(self.error)

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


# ---------------------------------------------------------------------------
# Audit engine
# ---------------------------------------------------------------------------

class AuditEngine:
    """
    Orchestrates the full audit lifecycle.

    Usage
    -----
        engine = AuditEngine()
        result = engine.run()
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
        Detect platform, load adapter, run checks, return AuditResult.

        Never raises — errors are captured in AuditResult.error.
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
            return AuditResult(
                platform=current_platform,
                platform_detail=platform_detail,
                findings=[],
                error=error_msg,
            )

        adapter_class = adapters[current_platform]
        adapter: PlatformAdapter = adapter_class()

        try:
            findings: list[Finding] = adapter.run_checks()
        except Exception as exc:  # pragma: no cover
            error_msg = f"Adapter '{adapter_class.__name__}' raised: {exc}"
            logger.exception(error_msg)
            return AuditResult(
                platform=current_platform,
                platform_detail=platform_detail,
                findings=[],
                error=error_msg,
            )

        return AuditResult(
            platform=current_platform,
            platform_detail=platform_detail,
            findings=findings,
        )
