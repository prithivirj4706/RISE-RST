"""SentinelAudit -- cross-platform, evidence-first security auditor.

Pipeline:

    connector -> collector -> rule engine -> prioritizer -> report

The rule engine is the only component that decides PASS / FAIL / UNKNOWN, and
every verdict carries the command and raw output it was derived from.
"""

__version__ = "1.0.0"
