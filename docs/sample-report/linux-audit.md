# SentinelAudit Report

**Target:** `docker://sa-linux` (transport: docker, platform: linux)  
**Generated:** 2026-08-14T06:53:31Z  
**Fingerprint:** `0345692fcc663946b1b327a4be0191b8002d489ec7d440585ed61cb1e489ebd4`  
**Tool:** SentinelAudit 1.0.0 (schema 1.0)

> The fingerprint is a SHA-256 over every part of this report except the
> timestamp. Two runs against an unchanged target produce the same value.

## Security score

### 0/100 (grade F)

| Severity | Failing |
| --- | --- |
| CRITICAL | 2 |
| HIGH | 5 |
| MEDIUM | 3 |
| LOW | 0 |

- Rules evaluated: **11**
- Passed: **1** &nbsp;|&nbsp; Failed: **10** &nbsp;|&nbsp; Unknown: **0**
- 11 of 11 rules reached a PASS/FAIL verdict; 0 returned UNKNOWN and are excluded from the score.
- Deduction weights: {'CRITICAL': 25, 'HIGH': 12, 'MEDIUM': 6, 'LOW': 2}

## Prioritized remediation plan

Ordered by severity, then rule ID. Every item below traces to one rule, one command, and one captured evidence snippet.

### 1. [CRITICAL] CIS-5.2.10 — SSH hardening

**Finding.** SSH root login disabled failed. Observed: permitrootlogin yes

**Why it matters.** A leaked or brute-forced root credential grants full remote access with no separate privilege-escalation step and no attribution to a named user.

**Evidence** (`sshd -T`):

```
permitrootlogin yes
```

**Fix:**

```
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload sshd
```

<sub>evidence_ref: `CIS-5.2.10`</sub>

### 2. [CRITICAL] CIS-6.2.1 — Account hygiene

**Finding.** No accounts have empty passwords failed. Observed: accounts with an empty password hash: brokenacct

**Why it matters.** An account with an empty password hash can be used for local login with no credential at all, and often for su into other accounts.

**Evidence** (`awk -F: '($2 == "") { print $1 }' /etc/shadow`):

```
accounts with an empty password hash: brokenacct
```

**Fix:**

```
sudo passwd -l <account>   # run per account listed in the evidence
```

<sub>evidence_ref: `CIS-6.2.1`</sub>

### 3. [HIGH] CIS-3.5.1 — Network exposure

**Finding.** Host firewall is active failed. Observed: -P FORWARD ACCEPT

**Why it matters.** Without a host firewall every listening service is reachable from any network the host is attached to, including services the operator does not know are running.

**Evidence** (`iptables -S`):

```
-P FORWARD ACCEPT
-P INPUT ACCEPT
-P OUTPUT ACCEPT
```

**Fix:**

```
sudo ufw enable   # or: sudo systemctl enable --now firewalld
```

<sub>evidence_ref: `CIS-3.5.1`</sub>

### 4. [HIGH] CIS-5.2.11 — SSH hardening

**Finding.** SSH password authentication disabled failed. Observed: passwordauthentication yes

**Why it matters.** Password authentication exposes every account to online guessing. Key-based authentication removes that attack surface entirely.

**Evidence** (`sshd -T`):

```
passwordauthentication yes
```

**Fix:**

```
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload sshd
```

<sub>evidence_ref: `CIS-5.2.11`</sub>

### 5. [HIGH] CIS-5.3.4 — Privilege escalation

**Finding.** sudoers contains no blanket NOPASSWD grant failed. Observed: /etc/sudoers.d: deploy ALL=(ALL) NOPASSWD: ALL

**Why it matters.** A NOPASSWD grant removes the re-authentication step, so any process running as that user -- including a hijacked shell -- becomes root without a credential.

**Evidence** (`cat /etc/sudoers`):

```
/etc/sudoers.d: deploy ALL=(ALL) NOPASSWD: ALL
```

**Fix:**

```
sudo visudo   # remove the NOPASSWD entries shown in the evidence, or scope them to specific commands
```

<sub>evidence_ref: `CIS-5.3.4`</sub>

### 6. [HIGH] CIS-6.1.10 — Filesystem permissions

**Finding.** No world-writable files in sensitive system paths failed. Observed: /etc/world-writable-example

**Why it matters.** Any local user can replace the contents of a world-writable file in a system path, turning a routine execution into privilege escalation.

**Evidence** (`find /etc /usr/bin /usr/sbin /usr/local/bin -xdev -type f -perm -0002 -print`):

```
/etc/world-writable-example
```

**Fix:**

```
sudo chmod o-w <path>   # run per file listed in the evidence
```

<sub>evidence_ref: `CIS-6.1.10`</sub>

### 7. [HIGH] CIS-6.1.3 — Filesystem permissions

**Finding.** /etc/shadow ownership and permissions are correct failed. Observed: /etc/shadow mode=0644 owner=root group=shadow

**Why it matters.** /etc/shadow holds password hashes. Any read access by a non-root user turns into offline cracking of every account on the host.

**Evidence** (`stat -c '%n %a %U %G' /etc/shadow`):

```
/etc/shadow mode=0644 owner=root group=shadow
```

**Fix:**

```
sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow
```

<sub>evidence_ref: `CIS-6.1.3`</sub>

### 8. [MEDIUM] CIS-1.9 — Patch management

**Finding.** Automatic security updates are enabled failed. Observed: APT::Periodic::Unattended-Upgrade "0";

**Why it matters.** Most host compromises use a vulnerability with a patch already shipped. Unapplied security updates are the gap being exploited.

**Evidence** (`cat /etc/apt/apt.conf.d/20auto-upgrades`):

```
APT::Periodic::Unattended-Upgrade "0";
```

**Fix:**

```
sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades
```

<sub>evidence_ref: `CIS-1.9`</sub>

### 9. [MEDIUM] CIS-3.2.1 — Network exposure

**Finding.** No unexpected service listens on all interfaces failed. Observed: listening on all interfaces:

**Why it matters.** A service bound to 0.0.0.0 is reachable from every network the host touches. Binding to localhost limits the blast radius to the host.

**Evidence** (`ss -tulnH`):

```
listening on all interfaces:
tcp 0.0.0.0:8080
```

**Fix:**

```
Bind the service to 127.0.0.1 in its own configuration, or block the port: sudo ufw deny <port>
```

<sub>evidence_ref: `CIS-3.2.1`</sub>

### 10. [MEDIUM] CIS-5.4.1 — Authentication policy

**Finding.** Minimum password length policy is set failed. Observed: /etc/login.defs: PASS_MIN_LEN 4

**Why it matters.** Without an enforced minimum length, a single short password on any account undermines every other control on the host.

**Evidence** (`cat /etc/login.defs`):

```
/etc/login.defs: PASS_MIN_LEN 4
/etc/login.defs: PASS_MAX_DAYS 99999
```

**Fix:**

```
sudo sed -i 's/^#\?\s*minlen.*/minlen = 14/' /etc/security/pwquality.conf
```

<sub>evidence_ref: `CIS-5.4.1`</sub>

## All findings

| Rule | Control | Status | Severity | Title | Evidence (first line) |
| --- | --- | --- | --- | --- | --- |
| `CIS-5.2.10` | SSH-001 | **FAIL** | CRITICAL | SSH root login disabled | `permitrootlogin yes` |
| `CIS-6.2.1` | ACCT-001 | **FAIL** | CRITICAL | No accounts have empty passwords | `accounts with an empty password hash: brokenacct` |
| `CIS-3.5.1` | FW-001 | **FAIL** | HIGH | Host firewall is active | `-P FORWARD ACCEPT` |
| `CIS-5.2.11` | SSH-002 | **FAIL** | HIGH | SSH password authentication disabled | `passwordauthentication yes` |
| `CIS-5.3.4` | SUDO-001 | **FAIL** | HIGH | sudoers contains no blanket NOPASSWD grant | `/etc/sudoers.d: deploy ALL=(ALL) NOPASSWD: ALL` |
| `CIS-6.1.10` | FS-002 | **FAIL** | HIGH | No world-writable files in sensitive system paths | `/etc/world-writable-example` |
| `CIS-6.1.3` | FS-003 | **FAIL** | HIGH | /etc/shadow ownership and permissions are correct | `/etc/shadow mode=0644 owner=root group=shadow` |
| `CIS-1.9` | UPD-001 | **FAIL** | MEDIUM | Automatic security updates are enabled | `APT::Periodic::Unattended-Upgrade "0";` |
| `CIS-3.2.1` | NET-001 | **FAIL** | MEDIUM | No unexpected service listens on all interfaces | `listening on all interfaces:` |
| `CIS-5.4.1` | PWD-001 | **FAIL** | MEDIUM | Minimum password length policy is set | `/etc/login.defs: PASS_MIN_LEN 4` |
| `CIS-6.1.2` | FS-001 | **PASS** | MEDIUM | /etc/passwd ownership and permissions are correct | `/etc/passwd mode=0644 owner=root group=root` |

## Unknown verdicts

Every rule reached a PASS or FAIL verdict on this target.

## Passing checks

Recorded for completeness -- a passing check needs no remediation.

- `CIS-6.1.2` /etc/passwd ownership and permissions are correct — /etc/passwd mode=0644 owner=root group=root

## Command log

Every command below came from the fixed allowlist and is strictly read-only. Each is tagged with the rules it feeds.

| Command | Exit | Available | Feeds |
| --- | --- | --- | --- |
| `cat /etc/apt/apt.conf.d/20auto-upgrades` | 0 | yes | CIS-1.9 |
| `systemctl is-enabled dnf-automatic.timer` | 127 | no | CIS-1.9 |
| `awk -F: '($2 == "") { print $1 }' /etc/shadow` | 0 | yes | CIS-6.2.1 |
| `firewall-cmd --state` | 127 | no | CIS-3.5.1 |
| `iptables -S` | 0 | yes | CIS-3.5.1 |
| `ss -tulnH` | 0 | yes | CIS-3.2.1 |
| `netstat -tuln` | 127 | no | CIS-3.2.1 |
| `cat /etc/login.defs` | 0 | yes | CIS-5.4.1 |
| `nft list ruleset` | 127 | no | CIS-3.5.1 |
| `cat /etc/security/pwquality.conf` | 1 | yes | CIS-5.4.1 |
| `cat /etc/ssh/sshd_config` | 0 | yes | CIS-5.2.10, CIS-5.2.11 |
| `sshd -T` | 0 | yes | CIS-5.2.10, CIS-5.2.11 |
| `stat -c '%n %a %U %G' /etc/passwd` | 0 | yes | CIS-6.1.2 |
| `stat -c '%n %a %U %G' /etc/shadow` | 0 | yes | CIS-6.1.3 |
| `cat /etc/sudoers` | 0 | yes | CIS-5.3.4 |
| `grep -r -h -E NOPASSWD /etc/sudoers.d` | 0 | yes | CIS-5.3.4 |
| `ufw status verbose` | 127 | no | CIS-3.5.1 |
| `systemctl is-enabled unattended-upgrades.service` | 127 | no | CIS-1.9 |
| `find /etc /usr/bin /usr/sbin /usr/local/bin -xdev -type f -perm -0002 -print` | 0 | yes | CIS-6.1.10 |

## Notes

- linux.dnf_automatic_unit: skipped -- binary not available on target
- linux.firewalld_state: skipped -- binary not available on target
- linux.listening_fallback: skipped -- binary not available on target
- linux.nft_ruleset: skipped -- binary not available on target
- linux.ufw_status: skipped -- binary not available on target
- linux.unattended_upgrades_unit: skipped -- binary not available on target
- Command allowlist version 1.0.0; 19 commands executed, all read-only and validated at both import time and execution time.

