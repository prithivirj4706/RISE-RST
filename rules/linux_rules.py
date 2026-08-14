"""
rules/linux_rules.py
====================
Linux security rule definitions for SENTINELAUDIT.

Status: PHASE 1 STUB — structure only.
Implementation: assigned to the Linux + Windows contributor.

How to add a rule
-----------------
1. Define a RuleSpec dataclass instance below.
2. Implement a check function with signature:
       def check_<name>(collector: CommandCollector) -> Finding
3. The function MUST use only commands from LinuxAdapter.ALLOWED_COMMANDS.
4. The function MUST return a Finding with real command evidence.
5. Register the function in LINUX_RULES so the adapter can discover it.

Rule ID naming convention
-------------------------
  Category prefix + sequential number
  FW-001   Firewall
  SSH-001  SSH hardening
  USR-001  User / account policies
  PKG-001  Package management / updates
  FS-001   File system permissions
  NET-001  Network configuration
  SVC-001  System services
  LOG-001  Logging / auditing
  KRN-001  Kernel parameters
  CRY-001  Cryptography / TLS
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Imports (add as rules are implemented)
# ---------------------------------------------------------------------------
# from core.collector import CommandCollector
# from core.models    import Finding

# ---------------------------------------------------------------------------
# Rule registry
#
# Each entry maps a rule_id to a callable that accepts a CommandCollector
# and returns a Finding.
#
# Example (once implemented):
#
#   LINUX_RULES: dict[str, Callable[[CommandCollector], Finding]] = {
#       "FW-001":  check_firewall_enabled,
#       "SSH-001": check_ssh_root_login_disabled,
#   }
# ---------------------------------------------------------------------------

LINUX_RULES: dict = {}

# ---------------------------------------------------------------------------
# Rule stubs — implement and uncomment one by one
# ---------------------------------------------------------------------------

# def check_firewall_enabled(collector: CommandCollector) -> Finding:
#     """FW-001 — Verify that ufw (or iptables) is active."""
#     raise NotImplementedError("FW-001 not yet implemented.")

# def check_ssh_root_login_disabled(collector: CommandCollector) -> Finding:
#     """SSH-001 — PermitRootLogin must be 'no' in sshd_config."""
#     raise NotImplementedError("SSH-001 not yet implemented.")

# def check_ssh_password_auth_disabled(collector: CommandCollector) -> Finding:
#     """SSH-002 — PasswordAuthentication must be 'no'."""
#     raise NotImplementedError("SSH-002 not yet implemented.")

# def check_ssh_protocol_version(collector: CommandCollector) -> Finding:
#     """SSH-003 — Only SSH protocol 2 should be allowed."""
#     raise NotImplementedError("SSH-003 not yet implemented.")

# def check_unattended_upgrades(collector: CommandCollector) -> Finding:
#     """PKG-001 — Automatic security updates should be enabled."""
#     raise NotImplementedError("PKG-001 not yet implemented.")

# def check_world_writable_files(collector: CommandCollector) -> Finding:
#     """FS-001 — No world-writable files should exist outside /tmp."""
#     raise NotImplementedError("FS-001 not yet implemented.")

# def check_suid_binaries(collector: CommandCollector) -> Finding:
#     """FS-002 — List unexpected SUID/SGID binaries."""
#     raise NotImplementedError("FS-002 not yet implemented.")

# def check_empty_password_accounts(collector: CommandCollector) -> Finding:
#     """USR-001 — No accounts should have empty passwords."""
#     raise NotImplementedError("USR-001 not yet implemented.")

# def check_kernel_address_randomisation(collector: CommandCollector) -> Finding:
#     """KRN-001 — ASLR should be enabled (randomize_va_space = 2)."""
#     raise NotImplementedError("KRN-001 not yet implemented.")

# def check_coredumps_disabled(collector: CommandCollector) -> Finding:
#     """KRN-002 — Core dumps should be restricted."""
#     raise NotImplementedError("KRN-002 not yet implemented.")
