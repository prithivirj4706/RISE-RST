"""
report/reporter.py
==================
Report generation for SENTINELAUDIT.

Status: PHASE 1 STUB — interface defined, implementation in Phase 2.
Implementation: assigned to the macOS + reporting contributor.

Planned output formats
----------------------
- Plain text (console)
- JSON  (machine-readable)
- HTML  (human-readable, browser-viewable)
- Markdown (GitHub / documentation friendly)

Interface contract
------------------
All reporters must accept:
  - AuditResult  (from core.engine)
  - ScoreResult  (from core.scoring)

And produce a report artefact (string, file, or both).
"""

from __future__ import annotations

# from core.engine  import AuditResult   # uncomment when implementing
# from core.scoring import ScoreResult   # uncomment when implementing


class BaseReporter:
    """
    Abstract base class for all report generators.

    Subclass this and implement generate() for each output format.
    """

    def generate(self, audit_result, score_result) -> str:
        """
        Generate and return the report as a string.

        Parameters
        ----------
        audit_result : AuditResult
        score_result : ScoreResult

        Returns
        -------
        str
            The full report content.
        """
        raise NotImplementedError("BaseReporter.generate() must be overridden.")


# class TextReporter(BaseReporter):
#     """Plain-text console report."""
#     def generate(self, audit_result, score_result) -> str:
#         raise NotImplementedError

# class JSONReporter(BaseReporter):
#     """Machine-readable JSON report."""
#     def generate(self, audit_result, score_result) -> str:
#         raise NotImplementedError

# class HTMLReporter(BaseReporter):
#     """Browser-viewable HTML report saved to reports/."""
#     def generate(self, audit_result, score_result) -> str:
#         raise NotImplementedError
