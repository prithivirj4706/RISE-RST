"""macOS CIS-Benchmark-style rules.

Every parser in this file was written against real output captured from a macOS
15 host rather than from memory. Three of those captures changed the design:

* ``defaults read /Library/Preferences/com.apple.alf globalstate`` no longer
  exists on modern macOS, so ``socketfilterfw --getglobalstate`` is the primary
  firewall source and ``alf`` is only a fallback for older releases.
* ``netstat`` on macOS separates host and port with a **dot**, not a colon
  (``*.3306``), and lists established connections alongside listeners -- so the
  parser keeps LISTEN rows only.
* ``defaults read ... autoLoginUser`` exits non-zero when the key is absent, and
  absence is exactly the *secure* state, so that parser reads the raw result
  rather than treating a non-zero exit as unreadable.
"""

from __future__ import annotations

import re

from ..models import CRITICAL, HIGH, LOW, MEDIUM
from .base import (
    Context,
    Rule,
    excerpt,
    uncommented_lines,
    verdict_fail,
    verdict_pass,
    verdict_unknown,
)

EXPECTED_PUBLIC_PORTS = {80, 443}

# IANA dynamic/ephemeral range. Kernel-assigned source ports appear here and
# change on every reboot, so including them would make the evidence unstable
# without describing a real, durable exposure.
EPHEMERAL_FLOOR = 49152


def _domain_missing(result) -> bool:
    blob = f"{result.stdout}\n{result.stderr}".lower()
    return "does not exist" in blob


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------


def _check_firewall(ctx: Context):
    sfw = ctx.usable("macos.socketfilterfw_state")
    if sfw and sfw.stdout:
        line = sfw.stdout.splitlines()[0].strip()
        m = re.search(r"State\s*=\s*(\d+)", line)
        if m:
            state = int(m.group(1))
            return (verdict_pass if state >= 1 else verdict_fail)(
                line, "macos.socketfilterfw_state"
            )
        if "enabled" in line.lower():
            return verdict_pass(line, "macos.socketfilterfw_state")
        if "disabled" in line.lower():
            return verdict_fail(line, "macos.socketfilterfw_state")

    alf = ctx.usable("macos.alf_globalstate")
    if alf and alf.stdout.strip().isdigit():
        state = int(alf.stdout.strip())
        evidence = f"com.apple.alf globalstate = {state}"
        return (verdict_pass if state >= 1 else verdict_fail)(
            evidence, "macos.alf_globalstate"
        )

    return verdict_unknown(
        "firewall state not observable: "
        + ctx.why_unavailable("macos.socketfilterfw_state", "macos.alf_globalstate"),
        "macos.socketfilterfw_state",
    )


def _check_stealth(ctx: Context):
    res = ctx.usable("macos.socketfilterfw_stealth")
    if res is None or not res.stdout:
        return verdict_unknown(
            ctx.why_unavailable("macos.socketfilterfw_stealth"),
            "macos.socketfilterfw_stealth",
        )
    line = res.stdout.splitlines()[0].strip()
    low = line.lower()
    if low.endswith("on") or "enabled" in low:
        return verdict_pass(line, "macos.socketfilterfw_stealth")
    return verdict_fail(line, "macos.socketfilterfw_stealth")


# ---------------------------------------------------------------------------
# Platform integrity / encryption / app control
# ---------------------------------------------------------------------------


def _simple_state(command_id: str, pass_pattern: str, fail_pattern: str):
    def _check(ctx: Context):
        res = ctx.usable(command_id)
        if res is None or not res.stdout:
            return verdict_unknown(ctx.why_unavailable(command_id), command_id)
        line = res.stdout.splitlines()[0].strip()
        if re.search(pass_pattern, line, re.IGNORECASE):
            return verdict_pass(line, command_id)
        if re.search(fail_pattern, line, re.IGNORECASE):
            return verdict_fail(line, command_id)
        return verdict_unknown(f"unrecognised output: {line!r}", command_id, line)

    return _check


# ---------------------------------------------------------------------------
# Remote login
# ---------------------------------------------------------------------------


def _listen_rows(text: str) -> list[tuple[str, str, int]]:
    """(proto, local_endpoint, port) for LISTEN rows in macOS netstat output."""
    rows: list[tuple[str, str, int]] = []
    for line in text.splitlines():
        if "LISTEN" not in line:
            continue
        fields = line.split()
        if len(fields) < 4:
            continue
        proto, local = fields[0], fields[3]
        host, _, port = local.rpartition(".")
        if not port.isdigit():
            continue
        rows.append((proto, local, int(port)))
    return rows


def _check_remote_login(ctx: Context):
    res = ctx.usable("macos.remote_login")
    if res and res.stdout and "remote login" in res.stdout.lower():
        line = res.stdout.splitlines()[0].strip()
        return (verdict_fail if line.lower().endswith("on") else verdict_pass)(
            line, "macos.remote_login"
        )

    # systemsetup needs admin. Fall back to observed evidence: is anything
    # actually listening on 22?
    net = ctx.usable("macos.listening")
    if net and net.stdout:
        ssh_rows = sorted({local for _, local, port in _listen_rows(net.stdout)
                           if port == 22})
        if ssh_rows:
            return verdict_fail(
                "sshd is listening (systemsetup needs admin; verdict derived from "
                "the socket table):\n" + "\n".join(ssh_rows),
                "macos.listening",
            )
        return verdict_pass(
            "nothing is listening on TCP/22 (systemsetup needs admin; verdict "
            "derived from the socket table)",
            "macos.listening",
        )

    return verdict_unknown(
        "systemsetup requires administrator access and the socket table was "
        "also unreadable: "
        + ctx.why_unavailable("macos.remote_login", "macos.listening"),
        "macos.remote_login",
    )


# ---------------------------------------------------------------------------
# Updates
# ---------------------------------------------------------------------------


def _check_auto_updates(ctx: Context):
    lines: list[str] = []
    verdicts: list[bool] = []
    cid = "macos.update_critical"
    for command_id, label in (
        ("macos.update_critical", "CriticalUpdateInstall"),
        ("macos.update_macos_auto", "AutomaticallyInstallMacOSUpdates"),
    ):
        res = ctx.result(command_id)
        if res is None or not res.available:
            continue
        value = res.stdout.strip()
        if value.isdigit():
            lines.append(f"{label} = {value}")
            verdicts.append(value != "0")

    if not verdicts:
        return verdict_unknown(
            "no automatic-update preference is set on this host: "
            + ctx.why_unavailable("macos.update_critical", "macos.update_macos_auto"),
            cid,
        )
    evidence = "\n".join(lines)
    return (verdict_pass if all(verdicts) else verdict_fail)(evidence, cid)


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------


def _check_guest(ctx: Context):
    res = ctx.result("macos.guest_enabled")
    if res is None or not res.available:
        return verdict_unknown(ctx.why_unavailable("macos.guest_enabled"),
                               "macos.guest_enabled")
    if _domain_missing(res):
        return verdict_pass(
            "loginwindow GuestEnabled is unset, which leaves the Guest account "
            "disabled by default",
            "macos.guest_enabled",
        )
    value = res.stdout.strip()
    if not value.isdigit():
        return verdict_unknown(f"unrecognised output: {value!r}",
                               "macos.guest_enabled", value)
    return (verdict_pass if value == "0" else verdict_fail)(
        f"loginwindow GuestEnabled = {value}", "macos.guest_enabled"
    )


def _check_auto_login(ctx: Context):
    res = ctx.result("macos.auto_login")
    if res is None or not res.available:
        return verdict_unknown(ctx.why_unavailable("macos.auto_login"),
                               "macos.auto_login")
    if _domain_missing(res):
        # Absence of the key IS the secure state.
        return verdict_pass(
            "loginwindow autoLoginUser is unset, so no account logs in "
            "automatically at boot",
            "macos.auto_login",
        )
    account = res.stdout.strip()
    if not account:
        return verdict_unknown("empty autoLoginUser value", "macos.auto_login")
    return verdict_fail(f"autoLoginUser = {account}", "macos.auto_login")


# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------


def _parse_stat(line: str) -> tuple[str, int, str, str] | None:
    parts = line.split()
    if len(parts) != 4 or not parts[1].isdigit():
        return None
    return parts[0], int(parts[1], 8), parts[2], parts[3]


def _permission_check(command_id: str, max_mode: int, owner: str,
                      groups: tuple[str, ...]):
    def _check(ctx: Context):
        res = ctx.usable(command_id)
        if res is None or not res.stdout:
            return verdict_unknown(ctx.why_unavailable(command_id), command_id)
        parsed = _parse_stat(res.stdout.splitlines()[0])
        if parsed is None:
            return verdict_unknown(
                f"unrecognised stat output: {res.stdout.splitlines()[0]!r}", command_id
            )
        name, mode, user, group = parsed
        evidence = f"{name} mode={mode:04o} owner={user} group={group}"
        if (mode & ~max_mode) or user != owner or group not in groups:
            return verdict_fail(evidence, command_id)
        return verdict_pass(evidence, command_id)

    return _check


def _check_world_writable(ctx: Context):
    res = ctx.result("macos.world_writable")
    if res is None or not res.available:
        return verdict_unknown(ctx.why_unavailable("macos.world_writable"),
                               "macos.world_writable")
    files = sorted({ln.strip() for ln in res.stdout.splitlines() if ln.strip()})
    if files:
        return verdict_fail(excerpt("\n".join(files)), "macos.world_writable")
    if res.permission_denied:
        return verdict_unknown(
            "find could not traverse every audited path as this user, so an "
            "empty result cannot be trusted",
            "macos.world_writable",
            evidence=excerpt(res.stderr, 4),
        )
    return verdict_pass(
        "no world-writable files found under /etc or /usr/local/bin",
        "macos.world_writable",
    )


def _check_sudo_nopasswd(ctx: Context):
    main = ctx.usable("macos.sudoers")
    drop = ctx.result("macos.sudoers_d")

    hits: list[str] = []
    if main and main.stdout:
        hits += [f"/etc/sudoers: {ln}" for ln in uncommented_lines(main.stdout)
                 if "NOPASSWD" in ln.upper()]
    if drop and drop.available and drop.stdout:
        hits += [f"/etc/sudoers.d: {ln.strip()}" for ln in drop.stdout.splitlines()
                 if ln.strip() and not ln.lstrip().startswith("#")]

    hits = sorted(set(hits))
    if hits:
        return verdict_fail(excerpt("\n".join(hits), 8), "macos.sudoers")

    if main is None:
        # /etc/sudoers is mode 440 on macOS: unreadable without sudo. The
        # drop-in directory alone cannot prove the policy is clean.
        return verdict_unknown(
            "/etc/sudoers is not readable by the audit user (mode 440), so the "
            "absence of NOPASSWD grants cannot be confirmed from /etc/sudoers.d "
            "alone; this audit does not escalate privileges",
            "macos.sudoers",
            evidence="cat /etc/sudoers: Permission denied",
        )

    return verdict_pass(
        "no uncommented NOPASSWD grant in /etc/sudoers or /etc/sudoers.d",
        "macos.sudoers",
    )


# ---------------------------------------------------------------------------
# Network exposure
# ---------------------------------------------------------------------------


def _check_listening(ctx: Context):
    res = ctx.usable("macos.listening")
    if res is None or not res.stdout:
        return verdict_unknown(ctx.why_unavailable("macos.listening"),
                               "macos.listening")

    exposed: set[str] = set()
    for proto, local, port in _listen_rows(res.stdout):
        host = local.rpartition(".")[0]
        wildcard = host in ("*", "", "0.0.0.0")
        if not wildcard or port >= EPHEMERAL_FLOOR or port in EXPECTED_PUBLIC_PORTS:
            continue
        exposed.add(f"{proto} {local}")

    if exposed:
        return verdict_fail(
            "listening on all interfaces:\n" + excerpt("\n".join(sorted(exposed)), 10),
            "macos.listening",
        )
    return verdict_pass(
        "no unexpected service bound to a wildcard address below the ephemeral "
        f"port range ({EPHEMERAL_FLOOR})",
        "macos.listening",
    )


# ---------------------------------------------------------------------------
# Rule table
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    Rule(
        rule_id="CIS-Apple-5.1.1",
        control_id="INTEG-001",
        platform="macos",
        title="System Integrity Protection is enabled",
        category="Platform integrity",
        severity=CRITICAL,
        commands=("macos.sip",),
        primary_command="macos.sip",
        rationale=(
            "SIP is what stops even root from modifying system binaries and "
            "loading unsigned kernel extensions. With it off, a single admin "
            "compromise becomes a persistent, undetectable one."
        ),
        remediation=(
            "Reboot into Recovery (hold the power button), open Terminal and run: "
            "csrutil enable   # then reboot"
        ),
        parser=_simple_state("macos.sip", r"enabled", r"disabled"),
    ),
    Rule(
        rule_id="CIS-Apple-6.1.1",
        control_id="ACCT-003",
        platform="macos",
        title="Automatic login at boot is disabled",
        category="Account hygiene",
        severity=HIGH,
        commands=("macos.auto_login",),
        primary_command="macos.auto_login",
        rationale=(
            "Automatic login means physical possession of the machine is the "
            "only credential required, and it unlocks the login keychain."
        ),
        remediation=(
            "sudo defaults delete /Library/Preferences/com.apple.loginwindow "
            "autoLoginUser"
        ),
        parser=_check_auto_login,
    ),
    Rule(
        rule_id="CIS-Apple-2.6.1.1",
        control_id="ENC-001",
        platform="macos",
        title="FileVault full-disk encryption is enabled",
        category="Data protection",
        severity=HIGH,
        commands=("macos.filevault",),
        primary_command="macos.filevault",
        rationale=(
            "Without FileVault, anyone with physical access can read the entire "
            "disk from an external boot or by removing the drive."
        ),
        remediation="sudo fdesetup enable",
        parser=_simple_state("macos.filevault", r"\bis\s+On\b", r"\bis\s+Off\b"),
    ),
    Rule(
        rule_id="CIS-Apple-2.5.2.1",
        control_id="FW-001",
        platform="macos",
        title="Application Firewall is enabled",
        category="Network exposure",
        severity=HIGH,
        commands=("macos.socketfilterfw_state", "macos.alf_globalstate"),
        primary_command="macos.socketfilterfw_state",
        rationale=(
            "With the firewall off, every listening service on this machine is "
            "reachable from any network it joins, including untrusted Wi-Fi."
        ),
        remediation=(
            "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"
        ),
        parser=_check_firewall,
    ),
    Rule(
        rule_id="CIS-Apple-2.6.2",
        control_id="APP-001",
        platform="macos",
        title="Gatekeeper is enabled",
        category="Application control",
        severity=HIGH,
        commands=("macos.gatekeeper",),
        primary_command="macos.gatekeeper",
        rationale=(
            "Gatekeeper is the check that refuses unsigned and unnotarised "
            "binaries. Disabled, any downloaded executable runs unchallenged."
        ),
        remediation="sudo spctl --master-enable",
        parser=_simple_state("macos.gatekeeper", r"assessments enabled",
                             r"assessments disabled"),
    ),
    Rule(
        rule_id="CIS-Apple-5.4",
        control_id="SUDO-001",
        platform="macos",
        title="sudoers contains no blanket NOPASSWD grant",
        category="Privilege escalation",
        severity=HIGH,
        commands=("macos.sudoers", "macos.sudoers_d"),
        primary_command="macos.sudoers",
        rationale=(
            "A NOPASSWD grant removes the re-authentication step, so any process "
            "running as that user becomes root without a credential."
        ),
        remediation=(
            "sudo visudo   # remove the NOPASSWD entries shown in the evidence, "
            "or scope them to specific commands"
        ),
        parser=_check_sudo_nopasswd,
    ),
    Rule(
        rule_id="CIS-Apple-5.1.3",
        control_id="FS-002",
        platform="macos",
        title="No world-writable files in sensitive system paths",
        category="Filesystem permissions",
        severity=HIGH,
        commands=("macos.world_writable",),
        primary_command="macos.world_writable",
        rationale=(
            "Any local user can replace the contents of a world-writable file in "
            "a system path, turning a routine execution into privilege escalation."
        ),
        remediation="sudo chmod o-w <path>   # run per file listed in the evidence",
        parser=_check_world_writable,
    ),
    Rule(
        rule_id="CIS-Apple-1.2",
        control_id="UPD-001",
        platform="macos",
        title="Automatic security updates are enabled",
        category="Patch management",
        severity=MEDIUM,
        commands=("macos.update_critical", "macos.update_macos_auto"),
        primary_command="macos.update_critical",
        rationale=(
            "Most host compromises use a vulnerability with a patch already "
            "shipped. Unapplied security updates are the gap being exploited."
        ),
        remediation=(
            "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate "
            "CriticalUpdateInstall -bool true && sudo defaults write "
            "/Library/Preferences/com.apple.SoftwareUpdate "
            "AutomaticallyInstallMacOSUpdates -bool true"
        ),
        parser=_check_auto_updates,
    ),
    Rule(
        rule_id="CIS-Apple-2.4.1",
        control_id="SSH-001",
        platform="macos",
        title="Remote Login (SSH) is disabled",
        category="Network exposure",
        severity=MEDIUM,
        commands=("macos.remote_login", "macos.listening"),
        primary_command="macos.remote_login",
        rationale=(
            "Remote Login exposes an authenticated network entry point. If it is "
            "not deliberately in use it should not be listening."
        ),
        remediation="sudo systemsetup -setremotelogin off",
        parser=_check_remote_login,
    ),
    Rule(
        rule_id="CIS-Apple-6.1.3",
        control_id="ACCT-002",
        platform="macos",
        title="Guest account is disabled",
        category="Account hygiene",
        severity=MEDIUM,
        commands=("macos.guest_enabled",),
        primary_command="macos.guest_enabled",
        rationale=(
            "The Guest account allows unauthenticated local sessions and is a "
            "well-known starting point for local privilege escalation chains."
        ),
        remediation=(
            "sudo defaults write /Library/Preferences/com.apple.loginwindow "
            "GuestEnabled -bool false"
        ),
        parser=_check_guest,
    ),
    Rule(
        rule_id="CIS-Apple-2.5.2.3",
        control_id="NET-001",
        platform="macos",
        title="No unexpected service listens on all interfaces",
        category="Network exposure",
        severity=MEDIUM,
        commands=("macos.listening",),
        primary_command="macos.listening",
        rationale=(
            "A service bound to * is reachable from every network the machine "
            "joins. Binding to 127.0.0.1 limits the blast radius to this host."
        ),
        remediation=(
            "Bind the service to 127.0.0.1 in its own configuration "
            "(e.g. bind-address=127.0.0.1 for MySQL), then restart it"
        ),
        parser=_check_listening,
    ),
    Rule(
        rule_id="CIS-Apple-5.1.2",
        control_id="FS-001",
        platform="macos",
        title="/etc/passwd ownership and permissions are correct",
        category="Filesystem permissions",
        severity=MEDIUM,
        commands=("macos.stat_passwd",),
        primary_command="macos.stat_passwd",
        rationale=(
            "A writable /etc/passwd lets a local user add an account or change a "
            "UID to 0."
        ),
        remediation="sudo chown root:wheel /etc/passwd && sudo chmod 644 /etc/passwd",
        parser=_permission_check("macos.stat_passwd", 0o644, "root", ("wheel", "root")),
    ),
    Rule(
        rule_id="CIS-Apple-5.1.4",
        control_id="FS-004",
        platform="macos",
        title="/etc/sudoers ownership and permissions are correct",
        category="Filesystem permissions",
        severity=MEDIUM,
        commands=("macos.stat_sudoers",),
        primary_command="macos.stat_sudoers",
        rationale=(
            "A writable sudoers file is a direct, one-step path to root for any "
            "local user."
        ),
        remediation="sudo chown root:wheel /etc/sudoers && sudo chmod 440 /etc/sudoers",
        parser=_permission_check("macos.stat_sudoers", 0o440, "root", ("wheel", "root")),
    ),
    Rule(
        rule_id="CIS-Apple-2.5.2.2",
        control_id="FW-002",
        platform="macos",
        title="Firewall stealth mode is enabled",
        category="Network exposure",
        severity=LOW,
        commands=("macos.socketfilterfw_stealth",),
        primary_command="macos.socketfilterfw_stealth",
        rationale=(
            "Stealth mode drops unsolicited probes instead of answering them, "
            "which removes this host from casual network scans."
        ),
        remediation=(
            "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
        ),
        parser=_check_stealth,
    ),
]
