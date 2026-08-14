"""
rules/macos_rules.py
====================
macOS security rule definitions for SENTINELAUDIT.

Status: PHASE 1 STUB — structure only.
Implementation: assigned to the macOS + reporting contributor.

How to add a rule
-----------------
1. Define a check function:
       def check_<name>(collector: CommandCollector) -> Finding
2. Use only commands from MacOSAdapter.ALLOWED_COMMANDS.
3. Return a Finding with real command evidence.
4. Register in MACOS_RULES.

Rule ID naming convention
-------------------------
  FW-MAC-001   Application Firewall
  SIP-MAC-001  System Integrity Protection
  GK-MAC-001   Gatekeeper
  FV-MAC-001   FileVault
  SSH-MAC-001  SSH / Remote Login
  UPD-MAC-001  Software Update
  AUD-MAC-001  Audit / logging (auditd / unified logging)
  NET-MAC-001  Network / sharing settings
  SVC-MAC-001  System services / launch daemons
  APP-MAC-001  Application permissions / SandBox
"""

from __future__ import annotations

MACOS_RULES: dict = {}

# Stubs (implement and uncomment):

# def check_application_firewall_enabled(collector) -> Finding:
#     """FW-MAC-001 — macOS Application Firewall must be enabled."""
#     raise NotImplementedError

# def check_sip_enabled(collector) -> Finding:
#     """SIP-MAC-001 — System Integrity Protection must not be disabled."""
#     raise NotImplementedError

# def check_gatekeeper_enabled(collector) -> Finding:
#     """GK-MAC-001 — Gatekeeper must be enabled."""
#     raise NotImplementedError

# def check_filevault_enabled(collector) -> Finding:
#     """FV-MAC-001 — FileVault disk encryption must be active."""
#     raise NotImplementedError

# def check_remote_login_disabled(collector) -> Finding:
#     """SSH-MAC-001 — Remote Login (SSH) should be disabled unless required."""
#     raise NotImplementedError

# def check_software_update_enabled(collector) -> Finding:
#     """UPD-MAC-001 — Automatic software updates should be enabled."""
#     raise NotImplementedError
