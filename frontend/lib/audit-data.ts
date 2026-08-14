export type Status = "PASS" | "FAIL" | "UNKNOWN"
export type Severity = "critical" | "high" | "medium" | "low"
export type Platform = "linux" | "macos" | "windows"

export type Finding = {
  rule_id: string
  title: string
  category: string
  command: string
  status: Status
  evidence: string
  severity_hint: Severity
}

export type FixItem = {
  priority: number
  rule_id: string
  category: string
  finding: string
  why_it_matters: string
  fix_command: string
  evidence_ref: string
  severity: Severity
}

export type Target = {
  host: string
  transport: string
  os: string
  kernel: string
  user: string
}

export type PlatformMeta = {
  id: Platform
  label: string
  short: string
  benchmark: string
  /** 1 = highest priority. Linux is the primary target of the agent. */
  priority: number
  recommended?: boolean
}

export type PlatformData = {
  meta: PlatformMeta
  target: Target
  /** Fixed, versioned, read-only command allowlist for this platform. */
  allowlist: string[]
  findings: Finding[]
  fixList: FixItem[]
}

/* -------------------------------------------------------------------------- */
/*  LINUX  — primary, highest-priority target                                 */
/* -------------------------------------------------------------------------- */

const LINUX: PlatformData = {
  meta: {
    id: "linux",
    label: "Linux",
    short: "Ubuntu / Debian / RHEL",
    benchmark: "CIS Distribution Independent Linux Benchmark",
    priority: 1,
    recommended: true,
  },
  target: {
    host: "audit-target-01",
    transport: "SSH (key-based)",
    os: "Ubuntu 22.04.4 LTS",
    kernel: "5.15.0-107-generic",
    user: "auditor (read-only)",
  },
  allowlist: [
    "whoami",
    "sshd -T",
    "stat -c '%a %U %G' /etc/passwd /etc/shadow",
    "find /etc /usr/bin /usr/sbin -xdev -type f -perm -0002",
    "grep -E '^PASS_(MIN_LEN|MAX_DAYS)' /etc/login.defs",
    "awk -F: '($2==\"\"){print $1}' /etc/shadow",
    "ufw status",
    "systemctl is-enabled unattended-upgrades",
    "grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/",
    "ss -tuln",
  ],
  findings: [
    {
      rule_id: "CIS-1.2.1",
      title: "Automatic security updates enabled",
      category: "Patch management",
      command: "systemctl is-enabled unattended-upgrades",
      status: "FAIL",
      evidence: "disabled",
      severity_hint: "medium",
    },
    {
      rule_id: "CIS-3.5.1",
      title: "Host firewall is active",
      category: "Firewall",
      command: "ufw status",
      status: "FAIL",
      evidence: "Status: inactive",
      severity_hint: "high",
    },
    {
      rule_id: "CIS-5.1.2",
      title: "No unexpected service listening on all interfaces",
      category: "Network exposure",
      command: "ss -tuln",
      status: "PASS",
      evidence: "LISTEN 0 128 127.0.0.1:5432 ... 0.0.0.0:22 (ssh only)",
      severity_hint: "medium",
    },
    {
      rule_id: "CIS-5.2.10",
      title: "SSH root login disabled",
      category: "SSH hardening",
      command: "sshd -T | grep -i permitrootlogin",
      status: "FAIL",
      evidence: "permitrootlogin yes",
      severity_hint: "critical",
    },
    {
      rule_id: "CIS-5.2.11",
      title: "SSH password authentication disabled",
      category: "SSH hardening",
      command: "sshd -T | grep -i passwordauthentication",
      status: "FAIL",
      evidence: "passwordauthentication yes",
      severity_hint: "high",
    },
    {
      rule_id: "CIS-5.4.1",
      title: "Password minimum length policy set",
      category: "Password policy",
      command: "grep -E '^PASS_MIN_LEN' /etc/login.defs",
      status: "UNKNOWN",
      evidence: "no matching line; /etc/login.defs unreadable (permission denied)",
      severity_hint: "medium",
    },
    {
      rule_id: "CIS-6.1.2",
      title: "/etc/passwd ownership & permissions correct",
      category: "File permissions",
      command: "stat -c '%a %U %G' /etc/passwd",
      status: "PASS",
      evidence: "644 root root",
      severity_hint: "high",
    },
    {
      rule_id: "CIS-6.1.3",
      title: "/etc/shadow permissions restricted",
      category: "File permissions",
      command: "stat -c '%a %U %G' /etc/shadow",
      status: "FAIL",
      evidence: "666 root shadow",
      severity_hint: "critical",
    },
    {
      rule_id: "CIS-6.1.9",
      title: "No world-writable files in system paths",
      category: "File permissions",
      command: "find /etc /usr/bin /usr/sbin -xdev -type f -perm -0002",
      status: "FAIL",
      evidence: "/usr/local/bin/deploy.sh",
      severity_hint: "high",
    },
    {
      rule_id: "CIS-6.2.1",
      title: "No accounts with empty passwords",
      category: "Accounts",
      command: "awk -F: '($2==\"\"){print $1}' /etc/shadow",
      status: "PASS",
      evidence: "(no output — zero empty-password accounts)",
      severity_hint: "critical",
    },
    {
      rule_id: "CIS-6.2.8",
      title: "sudoers has no blanket NOPASSWD wildcard",
      category: "Privilege escalation",
      command: "grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/",
      status: "FAIL",
      evidence: "/etc/sudoers.d/deploy: deploy ALL=(ALL) NOPASSWD: ALL",
      severity_hint: "high",
    },
  ],
  fixList: [
    {
      priority: 1,
      rule_id: "CIS-6.1.3",
      category: "File permissions",
      severity: "critical",
      finding: "/etc/shadow is world-writable (mode 666).",
      why_it_matters:
        "Any local user can rewrite password hashes, trivially granting themselves root or locking others out.",
      fix_command: "sudo chown root:shadow /etc/shadow && sudo chmod 0640 /etc/shadow",
      evidence_ref: "CIS-6.1.3",
    },
    {
      priority: 2,
      rule_id: "CIS-5.2.10",
      category: "SSH hardening",
      severity: "critical",
      finding: "Root login over SSH is permitted (permitrootlogin yes).",
      why_it_matters:
        "A leaked or brute-forced root credential grants full remote access with no separate privilege step.",
      fix_command:
        "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
      evidence_ref: "CIS-5.2.10",
    },
    {
      priority: 3,
      rule_id: "CIS-3.5.1",
      category: "Firewall",
      severity: "high",
      finding: "The host firewall (ufw) is inactive.",
      why_it_matters:
        "Every listening service is reachable from anywhere with no default-deny, widening the attack surface.",
      fix_command: "sudo ufw default deny incoming && sudo ufw allow 22/tcp && sudo ufw enable",
      evidence_ref: "CIS-3.5.1",
    },
    {
      priority: 4,
      rule_id: "CIS-5.2.11",
      category: "SSH hardening",
      severity: "high",
      finding: "SSH password authentication is enabled (passwordauthentication yes).",
      why_it_matters:
        "Passwords are brute-forceable over the network; key-based auth removes that entire class of attack.",
      fix_command:
        "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
      evidence_ref: "CIS-5.2.11",
    },
    {
      priority: 5,
      rule_id: "CIS-6.2.8",
      category: "Privilege escalation",
      severity: "high",
      finding: "A sudoers rule grants blanket NOPASSWD ALL to the 'deploy' user.",
      why_it_matters:
        "A single compromised deploy account becomes instant, password-less root over the whole system.",
      fix_command:
        "sudo sed -i 's/NOPASSWD: ALL/ALL/' /etc/sudoers.d/deploy && sudo visudo -cf /etc/sudoers.d/deploy",
      evidence_ref: "CIS-6.2.8",
    },
    {
      priority: 6,
      rule_id: "CIS-6.1.9",
      category: "File permissions",
      severity: "high",
      finding: "A world-writable file exists in a system path (/usr/local/bin/deploy.sh).",
      why_it_matters:
        "Any user can edit a script that likely runs with elevated privileges, enabling arbitrary code execution.",
      fix_command: "sudo chmod o-w /usr/local/bin/deploy.sh",
      evidence_ref: "CIS-6.1.9",
    },
    {
      priority: 7,
      rule_id: "CIS-1.2.1",
      category: "Patch management",
      severity: "medium",
      finding: "Automatic security updates are disabled.",
      why_it_matters:
        "Known-CVE packages linger unpatched between manual maintenance windows, extending exposure.",
      fix_command: "sudo systemctl enable --now unattended-upgrades",
      evidence_ref: "CIS-1.2.1",
    },
  ],
}

/* -------------------------------------------------------------------------- */
/*  macOS                                                                     */
/* -------------------------------------------------------------------------- */

const MACOS: PlatformData = {
  meta: {
    id: "macos",
    label: "macOS",
    short: "Ventura / Sonoma",
    benchmark: "CIS Apple macOS Benchmark",
    priority: 2,
  },
  target: {
    host: "mac-target-07",
    transport: "SSH (key-based)",
    os: "macOS 14.5 Sonoma",
    kernel: "Darwin 23.5.0",
    user: "auditor (read-only)",
  },
  allowlist: [
    "whoami",
    "spctl --status",
    "fdesetup status",
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
    "sudo softwareupdate --schedule",
    "systemsetup -getremotelogin",
    "sysadminctl -screenLock status",
    "sudo launchctl list | grep -i screensharing",
    "pmset -g | grep -i 'destroyfvkeyonstandby'",
    "spctl --assess --type install",
  ],
  findings: [
    {
      rule_id: "CIS-1.1",
      title: "Automatic macOS updates enabled",
      category: "Patch management",
      command: "sudo softwareupdate --schedule",
      status: "FAIL",
      evidence: "Automatic checking for updates is turned off",
      severity_hint: "medium",
    },
    {
      rule_id: "CIS-2.5.1",
      title: "FileVault full-disk encryption enabled",
      category: "Disk encryption",
      command: "fdesetup status",
      status: "FAIL",
      evidence: "FileVault is Off.",
      severity_hint: "critical",
    },
    {
      rule_id: "CIS-2.6.3",
      title: "Application Layer Firewall enabled",
      category: "Firewall",
      command: "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
      status: "FAIL",
      evidence: "Firewall is disabled. (State = 0)",
      severity_hint: "high",
    },
    {
      rule_id: "CIS-2.4.1",
      title: "Remote Login (SSH) restricted",
      category: "Remote access",
      command: "systemsetup -getremotelogin",
      status: "FAIL",
      evidence: "Remote Login: On (open to all users)",
      severity_hint: "high",
    },
    {
      rule_id: "CIS-2.3.1",
      title: "Gatekeeper enabled",
      category: "Application control",
      command: "spctl --status",
      status: "PASS",
      evidence: "assessments enabled",
      severity_hint: "high",
    },
    {
      rule_id: "CIS-5.8",
      title: "Screen lock requires password immediately",
      category: "Session security",
      command: "sysadminctl -screenLock status",
      status: "FAIL",
      evidence: "screenLock delay is set to 300 seconds",
      severity_hint: "medium",
    },
    {
      rule_id: "CIS-2.4.10",
      title: "Screen Sharing disabled",
      category: "Remote access",
      command: "sudo launchctl list | grep -i screensharing",
      status: "PASS",
      evidence: "(no output — screen sharing not loaded)",
      severity_hint: "medium",
    },
    {
      rule_id: "CIS-2.5.2",
      title: "Destroy FileVault key on standby",
      category: "Disk encryption",
      command: "pmset -g | grep -i 'destroyfvkeyonstandby'",
      status: "UNKNOWN",
      evidence: "no matching key returned (setting not present)",
      severity_hint: "low",
    },
  ],
  fixList: [
    {
      priority: 1,
      rule_id: "CIS-2.5.1",
      category: "Disk encryption",
      severity: "critical",
      finding: "FileVault full-disk encryption is turned off.",
      why_it_matters:
        "A lost or stolen Mac exposes every file on disk in plaintext — encryption is the single biggest protection for a laptop.",
      fix_command: "sudo fdesetup enable",
      evidence_ref: "CIS-2.5.1",
    },
    {
      priority: 2,
      rule_id: "CIS-2.6.3",
      category: "Firewall",
      severity: "high",
      finding: "The built-in application firewall is disabled.",
      why_it_matters:
        "Without it, any listening app accepts inbound connections from the network with no gate.",
      fix_command:
        "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
      evidence_ref: "CIS-2.6.3",
    },
    {
      priority: 3,
      rule_id: "CIS-2.4.1",
      category: "Remote access",
      severity: "high",
      finding: "Remote Login (SSH) is on and open to all users.",
      why_it_matters:
        "An always-on remote shell open to everyone is a prime target for credential attacks.",
      fix_command: "sudo systemsetup -setremotelogin off",
      evidence_ref: "CIS-2.4.1",
    },
    {
      priority: 4,
      rule_id: "CIS-1.1",
      category: "Patch management",
      severity: "medium",
      finding: "Automatic macOS software updates are turned off.",
      why_it_matters:
        "Security patches for known vulnerabilities are delayed until someone remembers to update manually.",
      fix_command: "sudo softwareupdate --schedule on",
      evidence_ref: "CIS-1.1",
    },
    {
      priority: 5,
      rule_id: "CIS-5.8",
      category: "Session security",
      severity: "medium",
      finding: "Screen lock does not require a password immediately (300s delay).",
      why_it_matters:
        "An unattended, unlocked Mac stays accessible to anyone walking by for five minutes.",
      fix_command: "sudo sysadminctl -screenLock immediate -password -",
      evidence_ref: "CIS-5.8",
    },
  ],
}

/* -------------------------------------------------------------------------- */
/*  Windows                                                                    */
/* -------------------------------------------------------------------------- */

const WINDOWS: PlatformData = {
  meta: {
    id: "windows",
    label: "Windows",
    short: "Server 2022 / 11",
    benchmark: "CIS Microsoft Windows Benchmark",
    priority: 3,
  },
  target: {
    host: "WIN-TARGET-03",
    transport: "WinRM (Kerberos)",
    os: "Windows Server 2022",
    kernel: "Build 20348.2461",
    user: "auditor (read-only)",
  },
  allowlist: [
    "whoami",
    "Get-MpComputerStatus",
    "Get-NetFirewallProfile",
    "(Get-BitLockerVolume -MountPoint C:).ProtectionStatus",
    "Get-ItemProperty 'HKLM:\\...\\WindowsUpdate\\AU' -Name NoAutoUpdate",
    "Get-ItemProperty 'HKLM:\\...\\Terminal Server\\WinStations\\RDP-Tcp' UserAuthentication",
    "Get-SmbServerConfiguration | Select EnableSMB1Protocol",
    "net accounts",
    "Get-ItemProperty 'HKLM:\\...\\System' -Name EnableLUA",
    "Get-LocalUser | Where PasswordRequired -eq $false",
  ],
  findings: [
    {
      rule_id: "CIS-18.9.47",
      title: "Microsoft Defender real-time protection on",
      category: "Endpoint protection",
      command: "Get-MpComputerStatus",
      status: "PASS",
      evidence: "RealTimeProtectionEnabled : True",
      severity_hint: "high",
    },
    {
      rule_id: "CIS-9.1.1",
      title: "Windows Firewall enabled (all profiles)",
      category: "Firewall",
      command: "Get-NetFirewallProfile",
      status: "FAIL",
      evidence: "Public profile Enabled : False",
      severity_hint: "high",
    },
    {
      rule_id: "CIS-18.10.9",
      title: "BitLocker drive encryption on OS volume",
      category: "Disk encryption",
      command: "(Get-BitLockerVolume -MountPoint C:).ProtectionStatus",
      status: "FAIL",
      evidence: "ProtectionStatus : Off",
      severity_hint: "critical",
    },
    {
      rule_id: "CIS-18.9.108",
      title: "Automatic Updates enabled",
      category: "Patch management",
      command: "Get-ItemProperty ...\\WindowsUpdate\\AU -Name NoAutoUpdate",
      status: "FAIL",
      evidence: "NoAutoUpdate : 1",
      severity_hint: "medium",
    },
    {
      rule_id: "CIS-2.3.7.4",
      title: "RDP requires Network Level Authentication",
      category: "Remote access",
      command: "Get-ItemProperty ...\\RDP-Tcp UserAuthentication",
      status: "FAIL",
      evidence: "UserAuthentication : 0",
      severity_hint: "critical",
    },
    {
      rule_id: "CIS-18.3.1",
      title: "SMBv1 protocol disabled",
      category: "Network protocols",
      command: "Get-SmbServerConfiguration | Select EnableSMB1Protocol",
      status: "FAIL",
      evidence: "EnableSMB1Protocol : True",
      severity_hint: "high",
    },
    {
      rule_id: "CIS-1.2.2",
      title: "Account lockout threshold configured",
      category: "Account policy",
      command: "net accounts",
      status: "FAIL",
      evidence: "Lockout threshold: Never",
      severity_hint: "medium",
    },
    {
      rule_id: "CIS-2.3.17.1",
      title: "User Account Control (UAC) enabled",
      category: "Privilege escalation",
      command: "Get-ItemProperty ...\\System -Name EnableLUA",
      status: "PASS",
      evidence: "EnableLUA : 1",
      severity_hint: "high",
    },
    {
      rule_id: "CIS-1.1.4",
      title: "No local accounts without a required password",
      category: "Accounts",
      command: "Get-LocalUser | Where PasswordRequired -eq $false",
      status: "UNKNOWN",
      evidence: "query returned access-denied for 1 built-in account (WDAGUtilityAccount)",
      severity_hint: "medium",
    },
  ],
  fixList: [
    {
      priority: 1,
      rule_id: "CIS-2.3.7.4",
      category: "Remote access",
      severity: "critical",
      finding: "RDP allows connections without Network Level Authentication.",
      why_it_matters:
        "Attackers can reach the logon screen and exploit it without any credentials first — a well-known RDP attack path.",
      fix_command:
        "Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
      evidence_ref: "CIS-2.3.7.4",
    },
    {
      priority: 2,
      rule_id: "CIS-18.10.9",
      category: "Disk encryption",
      severity: "critical",
      finding: "BitLocker is off on the OS volume (C:).",
      why_it_matters:
        "A stolen disk or VHD exposes every file in plaintext without drive encryption.",
      fix_command: "Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector",
      evidence_ref: "CIS-18.10.9",
    },
    {
      priority: 3,
      rule_id: "CIS-9.1.1",
      category: "Firewall",
      severity: "high",
      finding: "The Windows Firewall Public profile is disabled.",
      why_it_matters:
        "On untrusted networks the machine accepts inbound traffic with no default-deny protection.",
      fix_command: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
      evidence_ref: "CIS-9.1.1",
    },
    {
      priority: 4,
      rule_id: "CIS-18.3.1",
      category: "Network protocols",
      severity: "high",
      finding: "The legacy SMBv1 protocol is enabled.",
      why_it_matters:
        "SMBv1 is the protocol exploited by WannaCry/EternalBlue and has no place on a modern host.",
      fix_command: "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
      evidence_ref: "CIS-18.3.1",
    },
    {
      priority: 5,
      rule_id: "CIS-18.9.108",
      category: "Patch management",
      severity: "medium",
      finding: "Automatic Updates are disabled (NoAutoUpdate = 1).",
      why_it_matters:
        "Known-CVE patches wait for manual intervention, leaving a widening exposure window.",
      fix_command:
        "Set-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoUpdate -Value 0",
      evidence_ref: "CIS-18.9.108",
    },
    {
      priority: 6,
      rule_id: "CIS-1.2.2",
      category: "Account policy",
      severity: "medium",
      finding: "No account lockout threshold is set (lockout: Never).",
      why_it_matters:
        "Passwords can be brute-forced indefinitely because failed attempts never lock the account.",
      fix_command: "net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15",
      evidence_ref: "CIS-1.2.2",
    },
  ],
}

/* -------------------------------------------------------------------------- */

export const PLATFORMS: Record<Platform, PlatformData> = {
  linux: LINUX,
  macos: MACOS,
  windows: WINDOWS,
}

/** Display / selection order — Linux first as the highest-priority target. */
export const PLATFORM_ORDER: Platform[] = ["linux", "macos", "windows"]

export const DEFAULT_PLATFORM: Platform = "linux"
