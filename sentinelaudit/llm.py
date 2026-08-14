"""Optional LLM explanation layer.

Strictly bounded. The language model:

* receives **only** structured findings the rule engine already adjudicated --
  rule_id, title, severity, status and the evidence excerpt. It never sees a
  credential, a hostname, a live shell, or a raw terminal transcript;
* returns **only** ``why_it_matters`` prose, validated against a JSON schema;
* cannot introduce a finding: any ``rule_id`` it returns that the engine did not
  produce is discarded before the prose is used;
* cannot change a verdict, a severity, an ordering, or a remediation command --
  those come from the deterministic tables and are never sent for review.

If the call fails, times out, returns malformed JSON, or is refused, the
prioritizer silently falls back to the static rationale. The audit is complete
and correct without this module ever running.

Reproducibility note: current Claude models reject the ``temperature``
parameter, so "temperature 0" is not the mechanism that keeps this tool
drift-free. Determinism is structural instead -- the LLM touches no field that
affects ordering or verdicts, so two runs order identically whether or not it
ran. See REPORT.md.
"""

from __future__ import annotations

import os

from .models import FAIL, Finding

DEFAULT_MODEL = "claude-opus-5"
MAX_TOKENS = 4000
TIMEOUT_SECONDS = 60

SYSTEM_PROMPT = """You are assisting a read-only security audit tool.

You are given security findings that a deterministic rule engine has ALREADY
adjudicated against real command output collected from a host. Your only job is
to explain, for each finding, why it matters to the operator of that host.

Rules:
- Do not decide or question whether a check passed or failed. The verdict is
  settled.
- Do not invent findings, rule IDs, file paths, or evidence.
- Do not write remediation commands. The tool supplies those from a vetted table.
- Two to three sentences per finding. Concrete and specific to the evidence
  shown: name the actual exposure, not generic hardening advice.
- Write for a system administrator who has to justify the fix to someone else.
"""

_SCHEMA = {
    "type": "object",
    "properties": {
        "explanations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string"},
                    "why_it_matters": {"type": "string"},
                },
                "required": ["rule_id", "why_it_matters"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["explanations"],
    "additionalProperties": False,
}


class LLMUnavailable(RuntimeError):
    """The explanation layer could not run. Never fatal."""


def _payload(findings: list[Finding]) -> list[dict[str, str]]:
    """The only thing the model ever sees. Note what is absent."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "evidence": f.evidence[:600],
        }
        for f in findings
        if f.status == FAIL
    ]


def explain(
    findings: list[Finding],
    model: str = DEFAULT_MODEL,
) -> tuple[dict[str, str], str]:
    """Return ``(explanations_by_rule_id, note)``.

    Raises :class:`LLMUnavailable` for every failure mode; the caller treats
    that as "use the static text" and records the reason in the report.
    """
    import json

    failures = _payload(findings)
    if not failures:
        return {}, "no failing findings to explain"

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise LLMUnavailable(
            "ANTHROPIC_API_KEY is not set in the environment "
            "(this tool never reads a key from a file in the repository)"
        )

    try:
        import anthropic
    except ImportError as exc:
        raise LLMUnavailable(
            "the anthropic package is not installed; run `pip install anthropic` "
            "or omit --llm"
        ) from exc

    client = anthropic.Anthropic(timeout=TIMEOUT_SECONDS)

    try:
        response = client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            output_config={
                "effort": "low",
                "format": {"type": "json_schema", "schema": _SCHEMA},
            },
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Explain why each of these confirmed findings matters.\n\n"
                        + json.dumps(failures, indent=2, sort_keys=True)
                    ),
                }
            ],
        )
    except Exception as exc:  # noqa: BLE001 - any API failure degrades gracefully
        raise LLMUnavailable(f"{type(exc).__name__}: {exc}") from exc

    # Claude's safety classifiers can decline security content. Check this
    # before touching response.content, which may be empty on a refusal.
    if response.stop_reason == "refusal":
        category = getattr(response.stop_details, "category", None)
        raise LLMUnavailable(
            f"the model declined to answer (category: {category or 'unspecified'})"
        )

    text = next((b.text for b in response.content if b.type == "text"), "")
    if not text:
        raise LLMUnavailable(f"empty response (stop_reason={response.stop_reason})")

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LLMUnavailable(f"malformed JSON from the model: {exc}") from exc

    known = {f.rule_id for f in findings}
    explanations: dict[str, str] = {}
    discarded: list[str] = []

    for row in parsed.get("explanations", []):
        rule_id = str(row.get("rule_id", "")).strip()
        prose = str(row.get("why_it_matters", "")).strip()
        if not rule_id or not prose:
            continue
        if rule_id not in known:
            # The model referenced a check that was never run. Drop it.
            discarded.append(rule_id)
            continue
        explanations[rule_id] = prose

    note = (
        f"LLM explanations applied to {len(explanations)} finding(s) using {model}; "
        "verdicts, severities, ordering and remediation commands are unaffected"
    )
    if discarded:
        note += (
            f"; discarded {len(discarded)} explanation(s) for rule IDs this run "
            f"never produced ({', '.join(sorted(discarded))})"
        )
    return explanations, note
