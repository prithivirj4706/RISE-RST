"""The fixed, versioned command allowlist -- the entire safety model.

Three properties are enforced here, at import time, over every command in the
registry. If any of them fails the process refuses to start:

1. **No shell, ever.** Commands are stored as argv lists and executed with
   ``exec``-style APIs. The SSH transport is the one place a string is
   unavoidable, so :func:`render_ssh` shell-quotes each token and then asserts
   the string round-trips back to the exact same argv via ``shlex.split``.
2. **Read-only binaries only.** ``argv[0]`` must appear in
   :data:`READ_ONLY_BINARIES`, and binaries that have both read and write modes
   (``systemctl``, ``defaults``, ``ufw``, ``powershell`` ...) are additionally
   constrained to a whitelist of read subcommands / flags.
3. **Nothing is constructed at runtime.** Every argv in this file is a literal.
   No rule, config file, CLI argument, or LLM response can add to or alter this
   list. Adding a command is a deliberate, reviewable edit to this file.

ALLOWLIST_VERSION is bumped whenever the command set changes.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

ALLOWLIST_VERSION = "1.0.0"


@dataclass(frozen=True)
class CommandSpec:
    command_id: str
    argv: tuple[str, ...]
    platform: str  # "linux" | "macos" | "windows"
    description: str
    optional: bool = True  # the binary may legitimately not exist on a target

    @property
    def display(self) -> str:
        return " ".join(shlex.quote(tok) for tok in self.argv)


# ---------------------------------------------------------------------------
# Read-only policy
# ---------------------------------------------------------------------------

READ_ONLY_BINARIES = {
    # POSIX shared
    "id", "uname", "cat", "stat", "find", "awk", "grep", "getent", "netstat",
    # Linux
    "ss", "sshd", "ufw", "firewall-cmd", "iptables", "nft", "systemctl", "sysctl",
    # macOS
    "sw_vers", "defaults", "csrutil", "fdesetup", "spctl", "systemsetup",
    "launchctl", "socketfilterfw",
    # Windows
    "powershell",
}

# Binaries that can mutate state in some modes: pin them to read subcommands.
SUBCOMMAND_POLICY: dict[str, set[str]] = {
    "systemctl": {"is-enabled", "is-active", "status", "show", "list-unit-files"},
    "ufw": {"status"},
    "firewall-cmd": {"--state", "--list-all"},
    "iptables": {"-S", "-L", "-n", "-t"},
    "nft": {"list"},
    "defaults": {"read"},
    "spctl": {"--status"},
    "csrutil": {"status"},
    "fdesetup": {"status"},
    "launchctl": {"print", "print-disabled", "list"},
    "sshd": {"-T", "-C"},
}

# Flags that turn an otherwise-read-only binary into a writer.
BANNED_TOKENS: dict[str, set[str]] = {
    "find": {"-exec", "-execdir", "-delete", "-ok", "-okdir", "-fls", "-fprint",
             "-fprintf", "-fprint0"},
    "grep": set(),
    "systemsetup": set(),  # handled by the -get prefix rule below
    "socketfilterfw": set(),
}

_BINARY_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")

# awk programs can write files or shell out; forbid both.
_AWK_BANNED = ("system(", "print >", "printf >", "close(", "|&", "| \"")

# PowerShell: only read verbs survive.
_PS_ALLOWED_VERBS = {
    "get", "select", "where", "foreach", "convertto", "convertfrom", "format",
    "sort", "measure", "test", "resolve", "out",
}
_PS_VERB_NOUN_RE = re.compile(r"\b([A-Za-z]+)-[A-Za-z]+\b")
_PS_BANNED_SUBSTRINGS = (
    "out-file", "set-content", "add-content", "remove-item", "new-item",
    "invoke-expression", "iex ", "start-process", "restart-", "stop-",
    ">", "reg add", "reg delete", "net user", "net localgroup",
)


class AllowlistViolation(RuntimeError):
    """Raised when a command would break the read-only contract."""


def assert_read_only(spec: CommandSpec) -> None:
    """Validate one spec against the read-only policy. Raises on violation."""
    if not spec.argv:
        raise AllowlistViolation(f"{spec.command_id}: empty argv")

    binary = spec.argv[0].rsplit("/", 1)[-1]
    if not _BINARY_RE.match(binary):
        raise AllowlistViolation(f"{spec.command_id}: suspicious binary {binary!r}")
    if binary not in READ_ONLY_BINARIES:
        raise AllowlistViolation(
            f"{spec.command_id}: {binary!r} is not in READ_ONLY_BINARIES"
        )

    args = spec.argv[1:]

    for banned in BANNED_TOKENS.get(binary, set()):
        if banned in args:
            raise AllowlistViolation(f"{spec.command_id}: banned token {banned!r}")

    allowed = SUBCOMMAND_POLICY.get(binary)
    if allowed is not None:
        # Every dash-flag and the first positional must come from the policy set.
        positional_seen = False
        for tok in args:
            if tok.startswith("-"):
                if tok not in allowed and not tok.startswith("--"):
                    raise AllowlistViolation(
                        f"{spec.command_id}: flag {tok!r} not allowed for {binary}"
                    )
                if tok.startswith("--") and tok not in allowed:
                    raise AllowlistViolation(
                        f"{spec.command_id}: flag {tok!r} not allowed for {binary}"
                    )
            elif not positional_seen:
                positional_seen = True
                if tok not in allowed:
                    raise AllowlistViolation(
                        f"{spec.command_id}: subcommand {tok!r} not allowed for {binary}"
                    )

    if binary == "systemsetup":
        for tok in args:
            if tok.startswith("-") and not tok.startswith("-get"):
                raise AllowlistViolation(
                    f"{spec.command_id}: systemsetup may only use -get* flags"
                )

    if binary == "socketfilterfw":
        for tok in args:
            if not tok.startswith("--get"):
                raise AllowlistViolation(
                    f"{spec.command_id}: socketfilterfw may only use --get* flags"
                )

    if binary == "awk":
        program = " ".join(args)
        low = program.lower()
        for bad in _AWK_BANNED:
            if bad in low:
                raise AllowlistViolation(
                    f"{spec.command_id}: awk program contains {bad!r}"
                )

    if binary == "powershell":
        if "-NoProfile" not in args or "-NonInteractive" not in args:
            raise AllowlistViolation(
                f"{spec.command_id}: powershell must use -NoProfile -NonInteractive"
            )
        script = args[args.index("-Command") + 1] if "-Command" in args else ""
        low = script.lower()
        for bad in _PS_BANNED_SUBSTRINGS:
            if bad in low:
                raise AllowlistViolation(
                    f"{spec.command_id}: powershell script contains {bad!r}"
                )
        # Quoted literals (registry paths etc.) are data, not cmdlet names.
        bare = re.sub(r"'[^']*'|\"[^\"]*\"", " ", script)
        for verb in _PS_VERB_NOUN_RE.findall(bare):
            if verb.lower() not in _PS_ALLOWED_VERBS:
                raise AllowlistViolation(
                    f"{spec.command_id}: powershell verb {verb!r} is not read-only"
                )

    # Round-trip guarantee for the SSH transport.
    rendered = render_ssh(spec.argv)
    if shlex.split(rendered) != list(spec.argv):
        raise AllowlistViolation(
            f"{spec.command_id}: argv does not survive shell quoting round-trip"
        )


def render_ssh(argv: tuple[str, ...] | list[str]) -> str:
    """Shell-quote argv into a single string for the SSH transport."""
    return " ".join(shlex.quote(tok) for tok in argv)


# ---------------------------------------------------------------------------
# The commands
# ---------------------------------------------------------------------------


def _c(cid: str, argv: list[str], platform: str, desc: str, optional: bool = True):
    return CommandSpec(cid, tuple(argv), platform, desc, optional)


_PS = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]


LINUX_COMMANDS: list[CommandSpec] = [
    _c("linux.identity", ["id", "-un"], "linux",
       "Effective username of the auditing account", optional=False),
    _c("linux.os_release", ["cat", "/etc/os-release"], "linux",
       "Distribution identity", optional=False),
    _c("linux.kernel", ["uname", "-sr"], "linux", "Kernel name and release",
       optional=False),

    _c("linux.sshd_effective", ["sshd", "-T"], "linux",
       "Effective sshd configuration after includes and matches"),
    _c("linux.sshd_config_file", ["cat", "/etc/ssh/sshd_config"], "linux",
       "Raw sshd_config, used when sshd -T is unavailable"),

    _c("linux.login_defs", ["cat", "/etc/login.defs"], "linux",
       "Shadow-suite password ageing policy"),
    _c("linux.pwquality", ["cat", "/etc/security/pwquality.conf"], "linux",
       "libpwquality complexity policy"),

    _c("linux.world_writable", [
        "find", "/etc", "/usr/bin", "/usr/sbin", "/usr/local/bin",
        "-xdev", "-type", "f", "-perm", "-0002", "-print",
    ], "linux", "World-writable files in sensitive system paths"),

    _c("linux.stat_passwd", ["stat", "-c", "%n %a %U %G", "/etc/passwd"], "linux",
       "Ownership and mode of /etc/passwd"),
    _c("linux.stat_shadow", ["stat", "-c", "%n %a %U %G", "/etc/shadow"], "linux",
       "Ownership and mode of /etc/shadow"),

    _c("linux.ufw_status", ["ufw", "status", "verbose"], "linux", "ufw firewall state"),
    _c("linux.firewalld_state", ["firewall-cmd", "--state"], "linux",
       "firewalld state"),
    _c("linux.iptables_rules", ["iptables", "-S"], "linux", "iptables rule dump"),
    _c("linux.nft_ruleset", ["nft", "list", "ruleset"], "linux", "nftables rule dump"),

    _c("linux.apt_auto_upgrades", ["cat", "/etc/apt/apt.conf.d/20auto-upgrades"],
       "linux", "APT unattended-upgrades toggles"),
    _c("linux.unattended_upgrades_unit",
       ["systemctl", "is-enabled", "unattended-upgrades.service"], "linux",
       "unattended-upgrades unit state"),
    _c("linux.dnf_automatic_unit",
       ["systemctl", "is-enabled", "dnf-automatic.timer"], "linux",
       "dnf-automatic timer state"),

    _c("linux.empty_passwords",
       ["awk", "-F:", '($2 == "") { print $1 }', "/etc/shadow"], "linux",
       "Accounts with an empty password hash"),

    _c("linux.sudoers", ["cat", "/etc/sudoers"], "linux", "Main sudoers policy"),
    _c("linux.sudoers_d", ["grep", "-r", "-h", "-E", "NOPASSWD", "/etc/sudoers.d"],
       "linux", "NOPASSWD grants in sudoers drop-ins"),

    _c("linux.listening", ["ss", "-tulnH"], "linux",
       "Listening TCP/UDP sockets (no PIDs, to keep output stable)"),
    _c("linux.listening_fallback", ["netstat", "-tuln"], "linux",
       "Listening sockets, fallback for hosts without ss"),
]


MACOS_COMMANDS: list[CommandSpec] = [
    _c("macos.identity", ["id", "-un"], "macos",
       "Effective username of the auditing account", optional=False),
    _c("macos.os_version", ["sw_vers"], "macos", "macOS product version",
       optional=False),
    _c("macos.kernel", ["uname", "-sr"], "macos", "Kernel name and release",
       optional=False),

    _c("macos.alf_globalstate",
       ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
       "macos", "Application Firewall global state (0=off,1=on,2=block-all)"),
    _c("macos.socketfilterfw_state",
       ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
       "macos", "Application Firewall state via socketfilterfw"),
    _c("macos.socketfilterfw_stealth",
       ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
       "macos", "Application Firewall stealth mode"),

    _c("macos.sip", ["csrutil", "status"], "macos", "System Integrity Protection"),
    _c("macos.filevault", ["fdesetup", "status"], "macos", "FileVault disk encryption"),
    _c("macos.gatekeeper", ["spctl", "--status"], "macos", "Gatekeeper assessment"),

    _c("macos.remote_login", ["systemsetup", "-getremotelogin"], "macos",
       "Remote Login (SSH) toggle"),
    _c("macos.sshd_service", ["launchctl", "print-disabled", "system"], "macos",
       "Disabled system launch daemons, used to infer SSH state without root"),

    # Read individual keys rather than the whole SoftwareUpdate domain: the full
    # dump carries timestamps and error counters that change between runs and
    # would make evidence non-reproducible.
    _c("macos.update_critical",
       ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
        "CriticalUpdateInstall"],
       "macos", "Whether critical security responses install automatically"),
    _c("macos.update_macos_auto",
       ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
        "AutomaticallyInstallMacOSUpdates"],
       "macos", "Whether macOS updates install automatically"),

    _c("macos.guest_enabled",
       ["defaults", "read", "/Library/Preferences/com.apple.loginwindow",
        "GuestEnabled"],
       "macos", "Guest account state"),
    _c("macos.auto_login",
       ["defaults", "read", "/Library/Preferences/com.apple.loginwindow",
        "autoLoginUser"],
       "macos", "Account configured for automatic login at boot, if any"),

    _c("macos.stat_passwd", ["stat", "-f", "%N %Lp %Su %Sg", "/etc/passwd"], "macos",
       "Ownership and mode of /etc/passwd"),
    _c("macos.stat_sudoers", ["stat", "-f", "%N %Lp %Su %Sg", "/etc/sudoers"], "macos",
       "Ownership and mode of /etc/sudoers"),

    _c("macos.sudoers", ["cat", "/etc/sudoers"], "macos", "Main sudoers policy"),
    _c("macos.sudoers_d", ["grep", "-r", "-h", "-E", "NOPASSWD", "/etc/sudoers.d"],
       "macos", "NOPASSWD grants in sudoers drop-ins"),

    _c("macos.world_writable", [
        "find", "/etc", "/usr/local/bin", "-xdev", "-type", "f", "-perm", "-0002",
        "-print",
    ], "macos", "World-writable files in sensitive system paths"),

    _c("macos.listening", ["netstat", "-an", "-p", "tcp"], "macos",
       "TCP socket table; the parser keeps only LISTEN rows"),
]


WINDOWS_COMMANDS: list[CommandSpec] = [
    _c("windows.identity", [*_PS, "$env:USERNAME"], "windows",
       "Effective username of the auditing account", optional=False),
    _c("windows.os_version", [
        *_PS,
        "Get-CimInstance Win32_OperatingSystem | Select-Object -Property Caption,Version | Format-List",
    ], "windows", "Windows edition and build", optional=False),

    _c("windows.firewall_profiles", [
        *_PS,
        "Get-NetFirewallProfile | Select-Object -Property Name,Enabled | Format-List",
    ], "windows", "Per-profile Windows Firewall state"),

    _c("windows.defender", [
        *_PS,
        "Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled,AntivirusEnabled,AntispywareEnabled | Format-List",
    ], "windows", "Microsoft Defender real-time protection state"),

    _c("windows.smb1", [
        *_PS,
        "Get-SmbServerConfiguration | Select-Object -Property EnableSMB1Protocol | Format-List",
    ], "windows", "SMBv1 server protocol state"),

    _c("windows.rdp", [
        *_PS,
        "Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' | Select-Object -Property fDenyTSConnections | Format-List",
    ], "windows", "Remote Desktop listener state"),

    _c("windows.rdp_nla", [
        *_PS,
        "Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' | Select-Object -Property UserAuthentication | Format-List",
    ], "windows", "Network Level Authentication requirement for RDP"),

    _c("windows.password_policy", [
        *_PS,
        "Get-CimInstance -ClassName Win32_AccountPolicy -ErrorAction SilentlyContinue | Format-List",
    ], "windows", "Local account password policy"),

    _c("windows.autoupdate", [
        *_PS,
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' -ErrorAction SilentlyContinue | Select-Object -Property AUOptions,NoAutoUpdate | Format-List",
    ], "windows", "Windows Update automatic-install configuration"),

    _c("windows.guest_account", [
        *_PS,
        "Get-LocalUser -Name Guest | Select-Object -Property Name,Enabled | Format-List",
    ], "windows", "Built-in Guest account state"),

    _c("windows.bitlocker", [
        *_PS,
        "Get-BitLockerVolume -MountPoint C: | Select-Object -Property MountPoint,ProtectionStatus | Format-List",
    ], "windows", "BitLocker protection status of the system volume"),
]


# Platform-neutral probes. These are the only commands run before the target's
# operating system is known, so they must be safe and present nearly everywhere.
PROBE_COMMANDS: list[CommandSpec] = [
    _c("probe.uname", ["uname", "-s"], "probe", "Kernel name, for OS detection"),
    _c("probe.windows", [*_PS, "$env:OS"], "probe",
       "Windows OS marker, for OS detection"),
]


ALL_COMMANDS: list[CommandSpec] = (
    PROBE_COMMANDS + LINUX_COMMANDS + MACOS_COMMANDS + WINDOWS_COMMANDS
)

COMMANDS_BY_ID: dict[str, CommandSpec] = {c.command_id: c for c in ALL_COMMANDS}

if len(COMMANDS_BY_ID) != len(ALL_COMMANDS):
    raise AllowlistViolation("duplicate command_id in the allowlist")

# Fail closed at import time: a mutating command can never even be defined.
for _spec in ALL_COMMANDS:
    assert_read_only(_spec)


def commands_for(platform: str) -> list[CommandSpec]:
    return [c for c in ALL_COMMANDS if c.platform == platform]


def get(command_id: str) -> CommandSpec:
    try:
        return COMMANDS_BY_ID[command_id]
    except KeyError:
        raise AllowlistViolation(
            f"{command_id!r} is not in the allowlist (version {ALLOWLIST_VERSION})"
        ) from None
