"""Rule registry -- one module per platform, one shared Rule shape."""

from __future__ import annotations

from .base import Context, Rule, Verdict

_LOADERS = {
    "linux": lambda: __import__(
        "sentinelaudit.rules.linux_rules", fromlist=["RULES"]
    ).RULES,
    "macos": lambda: __import__(
        "sentinelaudit.rules.macos_rules", fromlist=["RULES"]
    ).RULES,
    "windows": lambda: __import__(
        "sentinelaudit.rules.windows_rules", fromlist=["RULES"]
    ).RULES,
}


def load_rules(platform: str) -> list[Rule]:
    """Return the rule set for ``platform``, sorted by rule_id for determinism."""
    try:
        loader = _LOADERS[platform]
    except KeyError:
        raise ValueError(
            f"no rule set for platform {platform!r}; known: "
            + ", ".join(sorted(_LOADERS))
        ) from None

    rules = sorted(loader(), key=lambda r: r.rule_id)
    _validate(rules, platform)
    return rules


def _validate(rules: list[Rule], platform: str) -> None:
    """Fail fast on a malformed rule set rather than mid-audit."""
    from .. import allowlist

    seen: set[str] = set()
    for rule in rules:
        if rule.rule_id in seen:
            raise ValueError(f"duplicate rule_id {rule.rule_id!r} in {platform} rules")
        seen.add(rule.rule_id)
        if rule.platform != platform:
            raise ValueError(
                f"{rule.rule_id}: declared platform {rule.platform!r} does not "
                f"match its module ({platform})"
            )
        if not rule.commands:
            raise ValueError(f"{rule.rule_id}: declares no commands")
        if rule.primary_command not in rule.commands:
            raise ValueError(
                f"{rule.rule_id}: primary_command {rule.primary_command!r} is not "
                "in its own command list"
            )
        for cid in rule.commands:
            spec = allowlist.get(cid)  # raises if not allowlisted
            if spec.platform != platform:
                raise ValueError(
                    f"{rule.rule_id}: command {cid!r} belongs to platform "
                    f"{spec.platform!r}, not {platform!r}"
                )


__all__ = ["Context", "Rule", "Verdict", "load_rules"]
