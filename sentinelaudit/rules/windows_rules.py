"""Windows CIS-Benchmark-style rules.

Every command here is a PowerShell read cmdlet piped through ``Format-List``,
so all parsing reduces to reading ``Key : Value`` lines.

Honesty note carried into REPORT.md: unlike the Linux and macOS rule sets, these
parsers were written against documented ``Format-List`` output shapes and have
not been executed against a live Windows host. They are structured to degrade to
UNKNOWN rather than guess, so an unverified parser produces "we could not read
this" instead of a fabricated verdict.
"""

from __future__ import annotations

import re

from ..models import CRITICAL, HIGH, LOW, MEDIUM
from .base import Context, Rule, excerpt, verdict_fail, verdict_pass, verdict_unknown


def _fl_values(text: str, key: str) -> list[str]:
    """All values for ``key`` in PowerShell ``Format-List`` output."""
    rx = re.compile(rf"^\s*{re.escape(key)}\s*:\s*(.*?)\s*$", re.IGNORECASE)
    return [m.group(1) for m in (rx.match(ln) for ln in text.splitlines()) if m]


def _as_bool(value: str) -> bool | None:
    low = value.strip().lower()
    if low in ("true", "1", "yes", "enabled"):
        return True
    if low in ("false", "0", "no", "disabled"):
        return False
    return None


def _boolean_check(command_id: str, key: str, want: bool, label: str | None = None):
    """PASS when ``key`` equals ``want`` in every row of the output."""

    def _check(ctx: Context):
        res = ctx.usable(command_id)
        if res is None or not res.stdout:
            return verdict_unknown(ctx.why_unavailable(command_id), command_id)
        values = _fl_values(res.stdout, key)
        if not values:
            return verdict_unknown(
                f"{key} not present in the output of this command", command_id,
                excerpt(res.stdout, 6),
            )
        parsed = [_as_bool(v) for v in values]
        if any(p is None for p in parsed):
            return verdict_unknown(
                f"unrecognised {key} value(s): {values!r}", command_id,
                excerpt(res.stdout, 6),
            )
        name = label or key
        evidence = "\n".join(f"{name}: {v}" for v in values)
        return (verdict_pass if all(p is want for p in parsed) else verdict_fail)(
            evidence, command_id
        )

    return _check


def _check_firewall_profiles(ctx: Context):
    res = ctx.usable("windows.firewall_profiles")
    if res is None or not res.stdout:
        return verdict_unknown(ctx.why_unavailable("windows.firewall_profiles"),
                               "windows.firewall_profiles")
    names = _fl_values(res.stdout, "Name")
    states = _fl_values(res.stdout, "Enabled")
    if not names or len(names) != len(states):
        return verdict_unknown(
            "could not pair firewall profile names with their state",
            "windows.firewall_profiles", excerpt(res.stdout, 8),
        )
    pairs = sorted(zip(names, states))
    evidence = "\n".join(f"{n}: Enabled={s}" for n, s in pairs)
    disabled = [n for n, s in pairs if _as_bool(s) is not True]
    return (verdict_fail if disabled else verdict_pass)(
        evidence, "windows.firewall_profiles"
    )


def _check_rdp(ctx: Context):
    res = ctx.usable("windows.rdp")
    if res is None or not res.stdout:
        return verdict_unknown(ctx.why_unavailable("windows.rdp"), "windows.rdp")
    values = _fl_values(res.stdout, "fDenyTSConnections")
    if not values or not values[0].strip().isdigit():
        return verdict_unknown("fDenyTSConnections not readable", "windows.rdp",
                               excerpt(res.stdout, 6))
    deny = int(values[0].strip())
    evidence = f"fDenyTSConnections = {deny} (1 = Remote Desktop disabled)"
    return (verdict_pass if deny == 1 else verdict_fail)(evidence, "windows.rdp")


def _check_password_policy(ctx: Context):
    res = ctx.usable("windows.password_policy")
    if res is None or not res.stdout:
        return verdict_unknown(ctx.why_unavailable("windows.password_policy"),
                               "windows.password_policy")
    values = _fl_values(res.stdout, "MinimumPasswordLength")
    if not values or not values[0].strip().isdigit():
        return verdict_unknown(
            "MinimumPasswordLength not present in Win32_AccountPolicy output",
            "windows.password_policy", excerpt(res.stdout, 8),
        )
    minlen = int(values[0].strip())
    evidence = f"MinimumPasswordLength = {minlen}"
    return (verdict_pass if minlen >= 14 else verdict_fail)(
        evidence, "windows.password_policy"
    )


def _check_autoupdate(ctx: Context):
    res = ctx.usable("windows.autoupdate")
    if res is None or not res.stdout:
        return verdict_unknown(ctx.why_unavailable("windows.autoupdate"),
                               "windows.autoupdate")
    no_auto = _fl_values(res.stdout, "NoAutoUpdate")
    au = _fl_values(res.stdout, "AUOptions")
    lines = [f"NoAutoUpdate = {v}" for v in no_auto] + [f"AUOptions = {v}" for v in au]
    if not lines:
        return verdict_unknown(
            "neither NoAutoUpdate nor AUOptions is configured; the effective "
            "policy is whatever Windows Update defaults to and cannot be read "
            "from this key alone",
            "windows.autoupdate",
        )
    evidence = "\n".join(lines)
    if no_auto and no_auto[0].strip() == "1":
        return verdict_fail(evidence, "windows.autoupdate")
    if au and au[0].strip().isdigit():
        # 4 = download and install automatically.
        return (verdict_pass if int(au[0].strip()) >= 4 else verdict_fail)(
            evidence, "windows.autoupdate"
        )
    return verdict_pass(evidence, "windows.autoupdate")


def _check_bitlocker(ctx: Context):
    res = ctx.usable("windows.bitlocker")
    if res is None or not res.stdout:
        return verdict_unknown(
            "BitLocker status requires an elevated session on most hosts: "
            + ctx.why_unavailable("windows.bitlocker"),
            "windows.bitlocker",
        )
    values = _fl_values(res.stdout, "ProtectionStatus")
    if not values:
        return verdict_unknown("ProtectionStatus not readable", "windows.bitlocker",
                               excerpt(res.stdout, 6))
    state = values[0].strip()
    evidence = f"C: ProtectionStatus = {state}"
    return (verdict_pass if state.lower() in ("on", "1") else verdict_fail)(
        evidence, "windows.bitlocker"
    )


RULES: list[Rule] = [
    Rule(
        rule_id="CIS-Win-9.1.1",
        control_id="FW-001",
        platform="windows",
        title="Windows Firewall is enabled on all profiles",
        category="Network exposure",
        severity=HIGH,
        commands=("windows.firewall_profiles",),
        primary_command="windows.firewall_profiles",
        rationale=(
            "A disabled profile means the firewall silently stops applying the "
            "moment the machine joins a network of that type."
        ),
        remediation="Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
        parser=_check_firewall_profiles,
    ),
    Rule(
        rule_id="CIS-Win-18.9.47.4",
        control_id="AV-001",
        platform="windows",
        title="Microsoft Defender real-time protection is enabled",
        category="Endpoint protection",
        severity=CRITICAL,
        commands=("windows.defender",),
        primary_command="windows.defender",
        rationale=(
            "Real-time protection is the control that stops malware at write and "
            "execution time; with it off, detection happens only on a scheduled "
            "scan, if ever."
        ),
        remediation="Set-MpPreference -DisableRealtimeMonitoring $false",
        parser=_boolean_check("windows.defender", "RealTimeProtectionEnabled", True),
    ),
    Rule(
        rule_id="CIS-Win-18.3.1",
        control_id="SMB-001",
        platform="windows",
        title="SMBv1 server protocol is disabled",
        category="Legacy protocols",
        severity=HIGH,
        commands=("windows.smb1",),
        primary_command="windows.smb1",
        rationale=(
            "SMBv1 is the protocol WannaCry and NotPetya spread over. It has no "
            "remaining legitimate use on a modern network."
        ),
        remediation="Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        parser=_boolean_check("windows.smb1", "EnableSMB1Protocol", False),
    ),
    Rule(
        rule_id="CIS-Win-18.9.65.3.9.1",
        control_id="RDP-001",
        platform="windows",
        title="Remote Desktop is disabled",
        category="Network exposure",
        severity=HIGH,
        commands=("windows.rdp",),
        primary_command="windows.rdp",
        rationale=(
            "An exposed RDP listener is the single most commonly brute-forced "
            "entry point on internet-facing Windows hosts."
        ),
        remediation=(
            "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\"
            "Terminal Server' -Name fDenyTSConnections -Value 1"
        ),
        parser=_check_rdp,
    ),
    Rule(
        rule_id="CIS-Win-18.9.65.3.9.2",
        control_id="RDP-002",
        platform="windows",
        title="Network Level Authentication is required for RDP",
        category="Network exposure",
        severity=HIGH,
        commands=("windows.rdp_nla",),
        primary_command="windows.rdp_nla",
        rationale=(
            "Without NLA the host allocates a full session before the user "
            "authenticates, which is both a DoS and a pre-auth attack surface."
        ),
        remediation=(
            "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\"
            "Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1"
        ),
        parser=_boolean_check("windows.rdp_nla", "UserAuthentication", True),
    ),
    Rule(
        rule_id="CIS-Win-1.1.4",
        control_id="PWD-001",
        platform="windows",
        title="Minimum password length policy is set",
        category="Authentication policy",
        severity=MEDIUM,
        commands=("windows.password_policy",),
        primary_command="windows.password_policy",
        rationale=(
            "Without an enforced minimum length, a single short password on any "
            "local account undermines every other control on the host."
        ),
        remediation="net accounts /minpwlen:14",
        parser=_check_password_policy,
    ),
    Rule(
        rule_id="CIS-Win-18.9.108.2.2",
        control_id="UPD-001",
        platform="windows",
        title="Automatic security updates are enabled",
        category="Patch management",
        severity=MEDIUM,
        commands=("windows.autoupdate",),
        primary_command="windows.autoupdate",
        rationale=(
            "Most host compromises use a vulnerability with a patch already "
            "shipped. Unapplied security updates are the gap being exploited."
        ),
        remediation=(
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\"
            "CurrentVersion\\WindowsUpdate\\Auto Update' -Name AUOptions -Value 4"
        ),
        parser=_check_autoupdate,
    ),
    Rule(
        rule_id="CIS-Win-2.3.1.1",
        control_id="ACCT-002",
        platform="windows",
        title="Built-in Guest account is disabled",
        category="Account hygiene",
        severity=MEDIUM,
        commands=("windows.guest_account",),
        primary_command="windows.guest_account",
        rationale=(
            "The Guest account allows unauthenticated local sessions and is a "
            "well-known starting point for local privilege escalation chains."
        ),
        remediation="Disable-LocalUser -Name Guest",
        parser=_boolean_check("windows.guest_account", "Enabled", False,
                              label="Guest account enabled"),
    ),
    Rule(
        rule_id="CIS-Win-18.9.11.1",
        control_id="ENC-001",
        platform="windows",
        title="BitLocker protects the system volume",
        category="Data protection",
        severity=HIGH,
        commands=("windows.bitlocker",),
        primary_command="windows.bitlocker",
        rationale=(
            "Without full-disk encryption, anyone with physical access can read "
            "the entire volume from an external boot."
        ),
        remediation="Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256",
        parser=_check_bitlocker,
    ),
]
