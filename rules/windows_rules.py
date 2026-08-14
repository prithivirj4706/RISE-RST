"""
rules/windows_rules.py
======================
Windows security rule definitions for SENTINELAUDIT.

Status: PHASE 1 STUB — structure only.
Implementation: assigned to the Linux + Windows contributor.

How to add a rule
-----------------
1. Define a check function:
       def check_<name>(collector: CommandCollector) -> Finding
2. Use only commands from WindowsAdapter.ALLOWED_COMMANDS.
3. Return a Finding with real command evidence.
4. Register in WINDOWS_RULES.

Rule ID naming convention
-------------------------
  FW-WIN-001   Windows Firewall
  DEF-WIN-001  Windows Defender / AV
  UAC-WIN-001  User Account Control
  UPD-WIN-001  Windows Update / patching
  RDP-WIN-001  Remote Desktop
  AUD-WIN-001  Audit policy / event logging
  FS-WIN-001   File system / NTFS permissions
  SVC-WIN-001  Services and scheduled tasks
  NET-WIN-001  Network configuration
  CRY-WIN-001  Cryptography / TLS / Bitlocker
"""

from __future__ import annotations

WINDOWS_RULES: dict = {}

# Stubs (implement and uncomment):

# def check_windows_firewall_enabled(collector) -> Finding:
#     """FW-WIN-001 — Windows Firewall must be active on all profiles."""
#     raise NotImplementedError

# def check_windows_defender_enabled(collector) -> Finding:
#     """DEF-WIN-001 — Windows Defender real-time protection must be on."""
#     raise NotImplementedError

# def check_uac_enabled(collector) -> Finding:
#     """UAC-WIN-001 — User Account Control must be enabled."""
#     raise NotImplementedError

# def check_windows_update_enabled(collector) -> Finding:
#     """UPD-WIN-001 — Automatic updates must be enabled."""
#     raise NotImplementedError

# def check_rdp_nla_required(collector) -> Finding:
#     """RDP-WIN-001 — NLA must be required for Remote Desktop."""
#     raise NotImplementedError

# def check_bitlocker_enabled(collector) -> Finding:
#     """CRY-WIN-001 — BitLocker must be enabled on system drive."""
#     raise NotImplementedError
