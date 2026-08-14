"""Linux CIS-Benchmark-style rules.

Eleven checks, each mapped to one or more allowlisted commands and a small
deterministic parser. Rule IDs follow CIS Distribution Independent Linux
Benchmark numbering so a reader can look the control up.
"""

from __future__ import annotations

import re

from ..models import CRITICAL, HIGH, LOW, MEDIUM
from .base import (
    Context,
    Rule,
    excerpt,
    keyword_value,
    matching_lines,
    uncommented_lines,
    verdict_fail,
    verdict_pass,
    verdict_unknown,
)

# Ports we accept on a wildcard bind without flagging. Anything else listening
# on 0.0.0.0 / [::] is reported for review.
EXPECTED_PUBLIC_PORTS = {22, 80, 443}


# ---------------------------------------------------------------------------
# 1. SSH root login
# ---------------------------------------------------------------------------


def _sshd_value(ctx: Context, key: str) -> tuple[str | None, str, str]:
    """Resolve an sshd setting, preferring effective config over the raw file.

    Returns (value, evidence, command_id). ``value`` is None when nothing
    readable was found.
    """
    eff = ctx.usable("linux.sshd_effective")
    if eff and eff.stdout:
        value = keyword_value(eff.stdout, key)
        if value is not None:
            return value.lower(), f"{key.lower()} {value.lower()}", "linux.sshd_effective"

    raw = ctx.usable("linux.sshd_config_file")
    if raw and raw.stdout:
        hits = [ln for ln in uncommented_lines(raw.stdout)
                if re.match(rf"^{key}\b", ln, re.IGNORECASE)]
        if hits:
            # Last directive wins in sshd_config only for the first occurrence;
            # OpenSSH takes the FIRST value, so cite that one.
            first = hits[0]
            value = first.split(None, 1)[1].strip().lower() if len(first.split()) > 1 else ""
            return value, f"/etc/ssh/sshd_config: {first}", "linux.sshd_config_file"
    return None, "", "linux.sshd_effective"


def _check_root_login(ctx: Context):
    value, evidence, cid = _sshd_value(ctx, "PermitRootLogin")
    if value is None:
        return verdict_unknown(
            "PermitRootLogin not observable: "
            + ctx.why_unavailable("linux.sshd_effective", "linux.sshd_config_file"),
            cid,
        )
    if value == "no":
        return verdict_pass(evidence, cid)
    return verdict_fail(evidence, cid)


# ---------------------------------------------------------------------------
# 2. SSH password authentication
# ---------------------------------------------------------------------------


def _check_password_auth(ctx: Context):
    value, evidence, cid = _sshd_value(ctx, "PasswordAuthentication")
    if value is None:
        return verdict_unknown(
            "PasswordAuthentication not observable: "
            + ctx.why_unavailable("linux.sshd_effective", "linux.sshd_config_file"),
            cid,
        )
    return (verdict_pass if value == "no" else verdict_fail)(evidence, cid)


# ---------------------------------------------------------------------------
# 3. Password policy
# ---------------------------------------------------------------------------


def _check_password_policy(ctx: Context):
    pwq = ctx.usable("linux.pwquality")
    defs = ctx.usable("linux.login_defs")
    if pwq is None and defs is None:
        return verdict_unknown(
            "no password policy source readable: "
            + ctx.why_unavailable("linux.pwquality", "linux.login_defs"),
            "linux.login_defs",
        )

    minlen: int | None = None
    lines: list[str] = []
    cid = "linux.login_defs"

    if pwq and pwq.stdout:
        raw = keyword_value("\n".join(uncommented_lines(pwq.stdout)), "minlen")
        if raw and raw.lstrip("= ").strip().isdigit():
            minlen = int(raw.lstrip("= ").strip())
            lines.append(f"/etc/security/pwquality.conf: minlen = {minlen}")
            cid = "linux.pwquality"

    if defs and defs.stdout:
        raw = keyword_value(defs.stdout, "PASS_MIN_LEN")
        if raw and raw.isdigit():
            candidate = int(raw)
            lines.append(f"/etc/login.defs: PASS_MIN_LEN {candidate}")
            if minlen is None:
                minlen = candidate
                cid = "linux.login_defs"
        maxdays = keyword_value(defs.stdout, "PASS_MAX_DAYS")
        if maxdays:
            lines.append(f"/etc/login.defs: PASS_MAX_DAYS {maxdays}")

    if minlen is None:
        return verdict_unknown(
            "neither pwquality minlen nor PASS_MIN_LEN is set; the effective "
            "policy is decided by PAM modules this audit does not read",
            cid,
            evidence="\n".join(lines) or "(no minimum-length directive found)",
        )

    evidence = "\n".join(lines)
    return (verdict_pass if minlen >= 14 else verdict_fail)(evidence, cid)


# ---------------------------------------------------------------------------
# 4. World-writable files
# ---------------------------------------------------------------------------


def _check_world_writable(ctx: Context):
    res = ctx.result("linux.world_writable")
    if res is None or not res.available:
        return verdict_unknown(
            ctx.why_unavailable("linux.world_writable"), "linux.world_writable"
        )
    files = sorted({ln.strip() for ln in res.stdout.splitlines() if ln.strip()})
    if files:
        return verdict_fail(excerpt("\n".join(files)), "linux.world_writable")
    if res.permission_denied:
        return verdict_unknown(
            "find could not traverse every audited path as this user, so an "
            "empty result cannot be trusted",
            "linux.world_writable",
            evidence=excerpt(res.stderr, 4),
        )
    return verdict_pass(
        "no world-writable files found under /etc, /usr/bin, /usr/sbin, /usr/local/bin",
        "linux.world_writable",
    )


# ---------------------------------------------------------------------------
# 5 & 6. Sensitive file permissions
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
        too_open = mode & ~max_mode
        if too_open or user != owner or group not in groups:
            return verdict_fail(evidence, command_id)
        return verdict_pass(evidence, command_id)

    return _check


# ---------------------------------------------------------------------------
# 7. Firewall
# ---------------------------------------------------------------------------

_FW_SOURCES = (
    "linux.ufw_status",
    "linux.firewalld_state",
    "linux.nft_ruleset",
    "linux.iptables_rules",
)


def _check_firewall(ctx: Context):
    ufw = ctx.usable("linux.ufw_status")
    if ufw and ufw.stdout:
        line = next((ln.strip() for ln in ufw.stdout.splitlines()
                     if ln.lower().startswith("status:")), "")
        if line:
            active = line.lower().endswith("active")
            return (verdict_pass if active else verdict_fail)(line, "linux.ufw_status")

    fwd = ctx.usable("linux.firewalld_state")
    if fwd and fwd.stdout:
        state = fwd.stdout.strip().splitlines()[0]
        return (verdict_pass if state == "running" else verdict_fail)(
            f"firewall-cmd --state: {state}", "linux.firewalld_state"
        )

    nft = ctx.usable("linux.nft_ruleset")
    if nft and nft.stdout.strip():
        has_rules = any("chain" in ln for ln in nft.stdout.splitlines())
        if has_rules:
            return verdict_pass(excerpt(nft.stdout, 8), "linux.nft_ruleset")

    ipt = ctx.usable("linux.iptables_rules")
    if ipt and ipt.stdout.strip():
        policies = sorted(matching_lines(ipt.stdout, r"^-P "))
        rules = [ln for ln in ipt.stdout.splitlines() if ln.startswith("-A")]
        evidence = excerpt("\n".join(policies + sorted(rules)), 10)
        default_drop = any(re.match(r"^-P INPUT (DROP|REJECT)", p) for p in policies)
        if default_drop or rules:
            return verdict_pass(evidence, "linux.iptables_rules")
        return verdict_fail(
            evidence or "iptables -S: default ACCEPT policy, no rules",
            "linux.iptables_rules",
        )

    return verdict_unknown(
        "no firewall backend produced readable state (ufw, firewalld, nft and "
        "iptables all typically require root): " + ctx.why_unavailable(*_FW_SOURCES),
        "linux.ufw_status",
    )


# ---------------------------------------------------------------------------
# 8. Automatic security updates
# ---------------------------------------------------------------------------

_UPDATE_SOURCES = (
    "linux.apt_auto_upgrades",
    "linux.unattended_upgrades_unit",
    "linux.dnf_automatic_unit",
)


def _check_auto_updates(ctx: Context):
    apt = ctx.usable("linux.apt_auto_upgrades")
    if apt and apt.stdout:
        value = keyword_value(apt.stdout, 'APT::Periodic::Unattended-Upgrade')
        line = next((ln.strip() for ln in apt.stdout.splitlines()
                     if "Unattended-Upgrade" in ln), apt.stdout.splitlines()[0])
        enabled = bool(value and value.strip('"; ') not in ("0", ""))
        return (verdict_pass if enabled else verdict_fail)(line, "linux.apt_auto_upgrades")

    for cid in ("linux.unattended_upgrades_unit", "linux.dnf_automatic_unit"):
        unit = ctx.result(cid)
        if unit and unit.available and unit.stdout:
            state = unit.stdout.strip().splitlines()[0]
            evidence = f"{cid.rsplit('.', 1)[-1]}: {state}"
            if state in ("enabled", "enabled-runtime", "static"):
                return verdict_pass(evidence, cid)
            return verdict_fail(evidence, cid)

    return verdict_unknown(
        "no automatic-update mechanism observable on this host: "
        + ctx.why_unavailable(*_UPDATE_SOURCES),
        "linux.apt_auto_upgrades",
    )


# ---------------------------------------------------------------------------
# 9. Empty passwords
# ---------------------------------------------------------------------------


def _check_empty_passwords(ctx: Context):
    res = ctx.result("linux.empty_passwords")
    if res is None or not res.available:
        return verdict_unknown(
            ctx.why_unavailable("linux.empty_passwords"), "linux.empty_passwords"
        )
    if res.permission_denied or (res.exit_code != 0 and not res.stdout):
        return verdict_unknown(
            "/etc/shadow is not readable by the audit user; this check needs "
            "elevated read access and is intentionally not escalated",
            "linux.empty_passwords",
            evidence=excerpt(res.stderr, 3) or "(permission denied)",
        )
    accounts = sorted({ln.strip() for ln in res.stdout.splitlines() if ln.strip()})
    if accounts:
        return verdict_fail(
            "accounts with an empty password hash: " + ", ".join(accounts),
            "linux.empty_passwords",
        )
    return verdict_pass(
        "no account in /etc/shadow has an empty password field",
        "linux.empty_passwords",
    )


# ---------------------------------------------------------------------------
# 10. sudoers NOPASSWD
# ---------------------------------------------------------------------------


def _check_sudo_nopasswd(ctx: Context):
    main = ctx.usable("linux.sudoers")
    drop = ctx.result("linux.sudoers_d")
    if main is None and (drop is None or not drop.available):
        return verdict_unknown(
            ctx.why_unavailable("linux.sudoers", "linux.sudoers_d"), "linux.sudoers"
        )

    hits: list[str] = []
    if main and main.stdout:
        hits += [f"/etc/sudoers: {ln}" for ln in uncommented_lines(main.stdout)
                 if "NOPASSWD" in ln.upper()]
    if drop and drop.available and drop.stdout:
        hits += [f"/etc/sudoers.d: {ln.strip()}" for ln in drop.stdout.splitlines()
                 if ln.strip() and not ln.lstrip().startswith("#")]

    if main is None and drop is not None and drop.permission_denied:
        return verdict_unknown(
            "sudoers policy is not readable by the audit user",
            "linux.sudoers",
            evidence=excerpt(drop.stderr, 3),
        )

    hits = sorted(set(hits))
    if hits:
        return verdict_fail(excerpt("\n".join(hits), 8), "linux.sudoers")

    if main is None:
        # /etc/sudoers is where a blanket NOPASSWD grant normally lives. If it
        # is unreadable, an empty /etc/sudoers.d proves nothing -- reporting
        # PASS here would be a fabricated verdict.
        return verdict_unknown(
            "/etc/sudoers is not readable by the audit user, so the absence of "
            "NOPASSWD grants cannot be confirmed from /etc/sudoers.d alone; "
            "this audit does not escalate privileges",
            "linux.sudoers",
            evidence=excerpt(drop.stderr, 3) if drop else "cat /etc/sudoers: Permission denied",
        )

    return verdict_pass(
        "no uncommented NOPASSWD grant in /etc/sudoers or /etc/sudoers.d",
        "linux.sudoers",
    )


# ---------------------------------------------------------------------------
# 11. Unexpected listening services
# ---------------------------------------------------------------------------

_WILDCARD_PREFIXES = ("0.0.0.0:", "*:", "[::]:", ":::", "::")


def _split_endpoint(endpoint: str) -> tuple[str, int] | None:
    host, _, port = endpoint.rpartition(":")
    if not port.isdigit():
        return None
    return host, int(port)


def _check_listening(ctx: Context):
    # An empty socket table is a real observation ("nothing is listening"), not
    # an unreadable one -- so prefer any source that ran cleanly, even with no
    # output, over falling through to UNKNOWN.
    res = ctx.usable("linux.listening") or ctx.usable("linux.listening_fallback")
    if res is None:
        return verdict_unknown(
            ctx.why_unavailable("linux.listening", "linux.listening_fallback"),
            "linux.listening",
        )

    if not res.stdout.strip():
        return verdict_pass(
            f"{res.command_id} reported no listening TCP/UDP sockets at all",
            res.command_id,
        )

    exposed: set[str] = set()
    parsed_rows = 0
    for line in res.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        # ss -tulnH: Netid State Recv-Q Send-Q Local:Port Peer:Port
        # netstat -tuln: Proto Recv-Q Send-Q Local Address Foreign Address State
        candidates = [f for f in fields if ":" in f]
        if not candidates:
            continue
        local = candidates[0]
        parsed = _split_endpoint(local)
        if parsed is None:
            continue
        parsed_rows += 1
        host, port = parsed
        wildcard = local.startswith(_WILDCARD_PREFIXES) or host in ("", "*", "0.0.0.0", "::", "[::]")
        if wildcard and port not in EXPECTED_PUBLIC_PORTS:
            exposed.add(f"{fields[0]} {local}")

    if parsed_rows == 0:
        # The command exited cleanly but produced nothing this parser
        # recognises as a host:port socket table -- for example a BSD `netstat`
        # answering with the UNIX-domain socket table instead. Reporting PASS
        # from output we could not read would be a fabricated verdict.
        return verdict_unknown(
            f"{res.command_id} produced no recognisable TCP/UDP socket rows, so "
            "the absence of wildcard binds cannot be confirmed",
            res.command_id,
            evidence=excerpt(res.stdout, 4),
        )

    if exposed:
        return verdict_fail(
            "listening on all interfaces:\n" + excerpt("\n".join(sorted(exposed)), 10),
            res.command_id,
        )
    return verdict_pass(
        "no unexpected service bound to a wildcard address (allowed: "
        + ", ".join(str(p) for p in sorted(EXPECTED_PUBLIC_PORTS)) + ")",
        res.command_id,
    )


# ---------------------------------------------------------------------------
# Rule table
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    Rule(
        rule_id="CIS-5.2.10",
        control_id="SSH-001",
        platform="linux",
        title="SSH root login disabled",
        category="SSH hardening",
        severity=CRITICAL,
        commands=("linux.sshd_effective", "linux.sshd_config_file"),
        primary_command="linux.sshd_effective",
        rationale=(
            "A leaked or brute-forced root credential grants full remote access "
            "with no separate privilege-escalation step and no attribution to a "
            "named user."
        ),
        remediation=(
            "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' "
            "/etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload sshd"
        ),
        parser=_check_root_login,
    ),
    Rule(
        rule_id="CIS-5.2.11",
        control_id="SSH-002",
        platform="linux",
        title="SSH password authentication disabled",
        category="SSH hardening",
        severity=HIGH,
        commands=("linux.sshd_effective", "linux.sshd_config_file"),
        primary_command="linux.sshd_effective",
        rationale=(
            "Password authentication exposes every account to online guessing. "
            "Key-based authentication removes that attack surface entirely."
        ),
        remediation=(
            "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' "
            "/etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload sshd"
        ),
        parser=_check_password_auth,
    ),
    Rule(
        rule_id="CIS-5.4.1",
        control_id="PWD-001",
        platform="linux",
        title="Minimum password length policy is set",
        category="Authentication policy",
        severity=MEDIUM,
        commands=("linux.pwquality", "linux.login_defs"),
        primary_command="linux.login_defs",
        rationale=(
            "Without an enforced minimum length, a single short password on any "
            "account undermines every other control on the host."
        ),
        remediation=(
            "sudo sed -i 's/^#\\?\\s*minlen.*/minlen = 14/' "
            "/etc/security/pwquality.conf"
        ),
        parser=_check_password_policy,
    ),
    Rule(
        rule_id="CIS-6.1.10",
        control_id="FS-002",
        platform="linux",
        title="No world-writable files in sensitive system paths",
        category="Filesystem permissions",
        severity=HIGH,
        commands=("linux.world_writable",),
        primary_command="linux.world_writable",
        rationale=(
            "Any local user can replace the contents of a world-writable file in "
            "a system path, turning a routine execution into privilege escalation."
        ),
        remediation="sudo chmod o-w <path>   # run per file listed in the evidence",
        parser=_check_world_writable,
    ),
    Rule(
        rule_id="CIS-6.1.2",
        control_id="FS-001",
        platform="linux",
        title="/etc/passwd ownership and permissions are correct",
        category="Filesystem permissions",
        severity=MEDIUM,
        commands=("linux.stat_passwd",),
        primary_command="linux.stat_passwd",
        rationale=(
            "A writable /etc/passwd lets a local user add an account or change a "
            "UID to 0."
        ),
        remediation="sudo chown root:root /etc/passwd && sudo chmod 644 /etc/passwd",
        parser=_permission_check("linux.stat_passwd", 0o644, "root", ("root",)),
    ),
    Rule(
        rule_id="CIS-6.1.3",
        control_id="FS-003",
        platform="linux",
        title="/etc/shadow ownership and permissions are correct",
        category="Filesystem permissions",
        severity=HIGH,
        commands=("linux.stat_shadow",),
        primary_command="linux.stat_shadow",
        rationale=(
            "/etc/shadow holds password hashes. Any read access by a non-root "
            "user turns into offline cracking of every account on the host."
        ),
        remediation="sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow",
        parser=_permission_check("linux.stat_shadow", 0o640, "root", ("root", "shadow")),
    ),
    Rule(
        rule_id="CIS-3.5.1",
        control_id="FW-001",
        platform="linux",
        title="Host firewall is active",
        category="Network exposure",
        severity=HIGH,
        commands=_FW_SOURCES,
        primary_command="linux.ufw_status",
        rationale=(
            "Without a host firewall every listening service is reachable from "
            "any network the host is attached to, including services the "
            "operator does not know are running."
        ),
        remediation="sudo ufw enable   # or: sudo systemctl enable --now firewalld",
        parser=_check_firewall,
    ),
    Rule(
        rule_id="CIS-1.9",
        control_id="UPD-001",
        platform="linux",
        title="Automatic security updates are enabled",
        category="Patch management",
        severity=MEDIUM,
        commands=_UPDATE_SOURCES,
        primary_command="linux.apt_auto_upgrades",
        rationale=(
            "Most host compromises use a vulnerability with a patch already "
            "shipped. Unapplied security updates are the gap being exploited."
        ),
        remediation=(
            "sudo apt-get install -y unattended-upgrades && "
            "sudo dpkg-reconfigure -plow unattended-upgrades"
        ),
        parser=_check_auto_updates,
    ),
    Rule(
        rule_id="CIS-6.2.1",
        control_id="ACCT-001",
        platform="linux",
        title="No accounts have empty passwords",
        category="Account hygiene",
        severity=CRITICAL,
        commands=("linux.empty_passwords",),
        primary_command="linux.empty_passwords",
        rationale=(
            "An account with an empty password hash can be used for local login "
            "with no credential at all, and often for su into other accounts."
        ),
        remediation="sudo passwd -l <account>   # run per account listed in the evidence",
        parser=_check_empty_passwords,
    ),
    Rule(
        rule_id="CIS-5.3.4",
        control_id="SUDO-001",
        platform="linux",
        title="sudoers contains no blanket NOPASSWD grant",
        category="Privilege escalation",
        severity=HIGH,
        commands=("linux.sudoers", "linux.sudoers_d"),
        primary_command="linux.sudoers",
        rationale=(
            "A NOPASSWD grant removes the re-authentication step, so any process "
            "running as that user -- including a hijacked shell -- becomes root "
            "without a credential."
        ),
        remediation=(
            "sudo visudo   # remove the NOPASSWD entries shown in the evidence, "
            "or scope them to specific commands"
        ),
        parser=_check_sudo_nopasswd,
    ),
    Rule(
        rule_id="CIS-3.2.1",
        control_id="NET-001",
        platform="linux",
        title="No unexpected service listens on all interfaces",
        category="Network exposure",
        severity=MEDIUM,
        commands=("linux.listening", "linux.listening_fallback"),
        primary_command="linux.listening",
        rationale=(
            "A service bound to 0.0.0.0 is reachable from every network the host "
            "touches. Binding to localhost limits the blast radius to the host."
        ),
        remediation=(
            "Bind the service to 127.0.0.1 in its own configuration, or block the "
            "port: sudo ufw deny <port>"
        ),
        parser=_check_listening,
    ),
]
