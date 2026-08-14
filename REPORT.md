# SentinelAudit — Project Report

**Problem statement:** CIS Audit Agent — build an agent that audits hosts against
CIS-Benchmark-style rules and turns raw read-only command output into a
prioritized, copy-paste-ready remediation plan.

---

## 1. What we built

SentinelAudit is a read-only security auditing agent that opens one session to a
target (over SSH, `docker exec`, or locally), runs a fixed allowlist of strictly
read-only commands, evaluates ~11 CIS-Benchmark-style rules per platform with
small deterministic parsers, and emits `report.json` plus `report.md` containing
a severity-ranked remediation plan. Every fix-list item carries its rule ID, the
exact command that was run, the raw output excerpt that produced the verdict,
and a vetted remediation command — so a reader can check any item against the
evidence rather than trusting the tool. A rule that cannot be read produces
`UNKNOWN` with a logged reason, never a guessed PASS or FAIL. Each report carries
a SHA-256 fingerprint over everything except the timestamp, so "did this run
drift?" is a string comparison; three consecutive runs against an unchanged
target produced byte-identical fingerprints on both Linux and macOS. A
`--reaudit` mode diffs against the previous report and reports
FIXED / STILL_FAILING / NEW / REGRESSED with the score delta.

**What works:** the whole path, end to end, on Linux (verified against real
Docker targets) and macOS (verified against the development host). All three
transports open real sessions. The allowlist validator, the determinism
guarantee, graceful degradation, re-audit, and the optional LLM layer are all
implemented and exercised.

**What does not:** the 9 Windows rules have never been executed against a real
Windows host — they are written to documented PowerShell `Format-List` output
shapes and are structured to return UNKNOWN rather than guess, but they are
unverified. See §6.

### Architecture

```
              python main.py --target <host | docker://ctr | local>
                                   │
                    ┌──────────────▼──────────────┐
                    │ connector                   │  one read-only session
                    │   local | ssh | docker exec │  ssh uses ControlMaster:
                    └──────────────┬──────────────┘  one auth for ~20 commands
                                   │
                    ┌──────────────▼──────────────┐
                    │ detector                    │  uname -s over the connector
                    └──────────────┬──────────────┘  (target's OS, not ours)
                                   │
                    ┌──────────────▼──────────────┐
                    │ collector                   │  fixed allowlist, argv only,
                    │   → stdout/stderr/exit code │  no shell, each tagged with
                    └──────────────┬──────────────┘  the rules it feeds
                                   │
                    ┌──────────────▼──────────────┐
                    │ rule engine                 │  THE ONLY component that
                    │   → PASS / FAIL / UNKNOWN   │  decides a verdict
                    │     + evidence              │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │ prioritizer                 │  ranks; never re-judges
                    │   (deterministic + optional │  LLM writes prose only
                    │    LLM prose)               │
                    └──────────────┬──────────────┘
                                   │
                      report.json + report.md + fingerprint
                                   │
                              --reaudit → diff
```

---

## 2. The rule set

### Linux — 11 rules (verified against real targets)

| Rule ID | What is checked | Command(s) read | How the parser decides |
| --- | --- | --- | --- |
| `CIS-5.2.10` | SSH root login disabled | `sshd -T`, fallback `cat /etc/ssh/sshd_config` | PASS iff effective `permitrootlogin` is exactly `no`. Falls back to the **first** `PermitRootLogin` directive in the file (OpenSSH takes the first). UNKNOWN if neither source is readable. |
| `CIS-5.2.11` | SSH password auth disabled | same two | PASS iff `passwordauthentication no`. |
| `CIS-5.4.1` | Minimum password length set | `cat /etc/security/pwquality.conf`, `cat /etc/login.defs` | Prefers pwquality `minlen`, else `PASS_MIN_LEN`. PASS iff ≥ 14. Commented lines are skipped. UNKNOWN when neither directive exists — the effective policy then lives in PAM modules this audit does not read. |
| `CIS-6.1.10` | No world-writable files in system paths | `find /etc /usr/bin /usr/sbin /usr/local/bin -xdev -type f -perm -0002 -print` | FAIL listing sorted paths if any. PASS on empty. UNKNOWN if `find` hit permission errors, because an empty result would then be untrustworthy. |
| `CIS-6.1.2` | `/etc/passwd` ownership + mode | `stat -c '%n %a %U %G' /etc/passwd` | PASS iff mode ⊆ 0644 and owner `root:root`. |
| `CIS-6.1.3` | `/etc/shadow` ownership + mode | `stat -c …  /etc/shadow` | PASS iff mode ⊆ 0640 and owner `root`, group `root`/`shadow`. |
| `CIS-3.5.1` | Host firewall active | `ufw status verbose` → `firewall-cmd --state` → `nft list ruleset` → `iptables -S` | First readable backend wins. ufw: `Status: active`. firewalld: `running`. nft: any `chain`. iptables: default DROP/REJECT on INPUT, or any rules. UNKNOWN when all four are unreadable (all normally require root). |
| `CIS-1.9` | Automatic security updates | `cat /etc/apt/apt.conf.d/20auto-upgrades`, `systemctl is-enabled unattended-upgrades.service`, `… dnf-automatic.timer` | APT: `Unattended-Upgrade` ≠ `0`. Unit: `enabled`/`enabled-runtime`/`static`. UNKNOWN if no mechanism is observable. |
| `CIS-6.2.1` | No accounts with empty passwords | `awk -F: '($2 == "") { print $1 }' /etc/shadow` | FAIL listing account names. PASS on empty output with exit 0. **UNKNOWN on permission denied** — this check needs elevated read access and the agent never escalates. |
| `CIS-5.3.4` | No blanket NOPASSWD in sudoers | `cat /etc/sudoers`, `grep -r -h -E NOPASSWD /etc/sudoers.d` | FAIL on any uncommented NOPASSWD line. **UNKNOWN if `/etc/sudoers` itself is unreadable** — an empty `sudoers.d` alone cannot prove the policy is clean. |
| `CIS-3.2.1` | No unexpected wildcard listener | `ss -tulnH`, fallback `netstat -tuln` | Parses host/port; flags wildcard binds (`0.0.0.0`, `*`, `[::]`) on ports outside {22, 80, 443}. Cleanly-empty output = PASS (nothing listening). Non-empty but zero parseable socket rows = UNKNOWN. |

### macOS — 14 rules (verified against macOS 15.6.1)

SIP (`csrutil status`), automatic login (`defaults read … autoLoginUser`),
FileVault (`fdesetup status`), Application Firewall
(`socketfilterfw --getglobalstate`, `alf globalstate` fallback), Gatekeeper
(`spctl --status`), sudoers NOPASSWD, world-writable files, automatic updates
(`CriticalUpdateInstall` + `AutomaticallyInstallMacOSUpdates`), Remote Login,
Guest account, wildcard listeners, `/etc/passwd` and `/etc/sudoers` modes,
firewall stealth mode.

Three parsers were rewritten after observing real output rather than assuming it:

* `defaults read /Library/Preferences/com.apple.alf globalstate` **no longer
  exists** on macOS 15 — `socketfilterfw --getglobalstate` became primary.
* macOS `netstat` separates host and port with a **dot** (`*.3306`), not a
  colon, and lists established connections alongside listeners — the parser
  keeps `LISTEN` rows only.
* `defaults read … autoLoginUser` exits non-zero when the key is absent, and
  **absence is the secure state** — that parser reads the raw result rather than
  treating a non-zero exit as unreadable.

### Windows — 9 rules (**not verified against a real host**)

Firewall profiles, Defender real-time protection, SMBv1, RDP listener, RDP NLA,
password policy, automatic updates, Guest account, BitLocker. All are read-only
PowerShell cmdlets piped through `Format-List`, so parsing is `Key : Value`.
Every parser returns UNKNOWN on any output it does not recognise.

---

## 3. Methods and decisions

| Decision | Chosen | Rejected | Why |
| --- | --- | --- | --- |
| **Transport** | One `Connector` interface with three implementations: `local`, `ssh`, `docker exec` | SSH-only | The interface costs ~40 lines and makes the tool testable against disposable containers while still auditing real remote hosts. `docker exec` takes an argv vector directly, so there is no shell on the target at all. |
| **SSH session** | OpenSSH `ControlMaster` — one authentication, ~20 multiplexed commands, torn down on close | One `ssh` invocation per command | "One read-only session" should be literally true. Also ~20× fewer authentications. |
| **SSH client** | Shelled-out OpenSSH | `paramiko` | Zero dependencies; the tool runs with a bare Python 3.10+. Host-key verification, `BatchMode`, and `IdentitiesOnly` come free and correct. |
| **Command representation** | argv lists, executed `shell=False` | Shell strings | No quoting bugs, no word splitting, no injection surface. SSH is the one place a string is unavoidable — so the validator asserts every argv survives `shlex.quote` → `shlex.split` unchanged. |
| **Read-only enforcement** | Three layers, validated **at import time** | Code review + convention | (1) `argv[0]` must be in `READ_ONLY_BINARIES`; (2) dual-mode binaries pinned to read subcommands (`systemctl is-enabled`, `defaults read`, `ufw status`, PowerShell read verbs only); (3) banned tokens per binary (`find -exec/-delete`, `awk` with `system(` or redirection). A mutating command cannot be *defined* — the module raises on import. Re-validated again at execution time. |
| **Prioritizer** | Deterministic by default; LLM optional and bounded to prose | LLM decides ranking or verdicts | Ordering is `(severity_rank, rule_id)` — structural, so it cannot drift. The LLM never sees a shell, a credential, or a raw transcript, and any rule ID it returns that this run did not produce is discarded. |
| **Remediation commands** | Static known-good table, always | LLM-authored fix commands | A wrong-but-confident `sudo` command is the most dangerous thing this tool could emit. The table is the stretch-goal cross-check, applied to 100% of rules rather than a subset. |
| **Score** | Deterministic weights, and **refuses to grade below 60% coverage** | Always emit a letter grade | An early run reported *"100/100, grade A"* after failing to read 9 of 11 checks. That is precisely the confidently-wrong output this project exists to avoid, so low coverage now yields `INSUFFICIENT-DATA`. |

### On "temperature 0"

The handout suggests a low or zero LLM temperature for reproducibility. **Current
Claude models reject the `temperature` parameter outright** (HTTP 400), so that
lever no longer exists. We got determinism structurally instead: the LLM touches
no field that affects ordering, verdicts, severities, or fix commands, so two
runs order identically whether or not it ran, and whether or not it produced the
same words. The fingerprint is computed over the stable payload and proves it.

### Credential hygiene

No credential is ever in the repository. The SSH key arrives as a **path** from
`--key` or `SENTINEL_SSH_KEY`, and only the path is recorded in the report; key
material is never read by this tool. `ANTHROPIC_API_KEY` is read from the
environment only. Host-key verification is **on by default**; `--insecure-host-key`
prints a warning to stderr and records it in the report's notes.

---

## 4. Results — 8 real audit runs

| # | Target | Transport / user | Findings | Correct? |
| --- | --- | --- | --- | --- |
| 1 | macOS 15.6.1 (dev host) | local | 4 FAIL / 9 PASS / 1 UNKNOWN, 68/100 C | Yes. Firewall off, FileVault off, MySQL on `*.3306`/`*.33060`, stealth mode off — all four independently confirmed by hand. |
| 2 | `sentinel-vulnerable` (ubuntu:22.04) | docker, root | 7 FAIL / 2 PASS / 2 UNKNOWN, 0/100 F | Yes. Caught **all 7** baked-in misconfigurations: root login, empty-password account, password auth, NOPASSWD grant, world-writable file, shadow mode 644, `PASS_MIN_LEN 4`. |
| 3 | `sentinel-hardened` (ubuntu:22.04) | docker, root | 0 FAIL / 10 PASS / 1 UNKNOWN, 100/100 A | Yes. The single UNKNOWN is the firewall check — no ufw/iptables in the image, correctly not guessed. |
| 4 | `sentinel-vulnerable` after operator fixed 3 issues | docker, root, `--reaudit` | 3 FIXED, 4 STILL_FAILING, 0→32/100 | Yes. Exactly the three remediated controls flipped; nothing else moved. |
| 5 | `sentinel-vulnerable` as unprivileged `nobody` | docker, non-root | 3 FAIL / 4 PASS / 4 UNKNOWN, 57/100 D | Yes, and this is the most informative run — see below. |
| 6 | `192.0.2.1:2222` (unreachable) | ssh | No report, **exit 2** | Yes. `ssh: connect to host 192.0.2.1 port 2222: Connection refused`. Fails loudly (Req 9). |
| 7 | `docker://nope`, daemon down | docker | No report, **exit 2** | Yes. Names the daemon socket in the error. |
| 8 | macOS host with Linux rules forced (`--platform linux`) | local | 11 UNKNOWN, grade withheld | Yes — after two bug fixes. See below. |

### Run 5 in detail — the degradation case

Under an unprivileged audit user the tool did the right thing on every axis:

* `CIS-6.2.1` (empty passwords) → **UNKNOWN**, `/etc/shadow` unreadable — not a fabricated PASS.
* `CIS-5.3.4` (sudoers) → **UNKNOWN**, `/etc/sudoers` unreadable.
* `CIS-5.2.10` → still **FAIL**, but the evidence source *automatically switched*
  from `sshd -T` (needs root) to `/etc/ssh/sshd_config`, and the report cites the
  file it actually read.
* `CIS-6.1.2/6.1.3` → **PASS**, because `stat` works without read permission.

### Two false PASSes we found and fixed

Both were caught by run 8 — deliberately pointing the Linux rule set at a macOS
host — and both are the exact failure mode the handout warns about in §6.3
("a parser can silently match the wrong line and report a PASS that isn't real").

1. **`CIS-3.2.1` listening services.** macOS `netstat -tuln` **exits 0** and
   prints the *UNIX-domain socket table* — a completely different table with no
   TCP endpoints. The parser found no wildcard binds and reported PASS. Fixed:
   output that produces zero parseable socket rows is now UNKNOWN, and only a
   *cleanly empty* table counts as "nothing listening".
2. **`CIS-5.3.4` sudoers.** With `/etc/sudoers` unreadable and `/etc/sudoers.d`
   empty, the parser reported PASS. But a blanket NOPASSWD grant normally lives
   in `/etc/sudoers` itself, so an empty drop-in directory proves nothing. Fixed
   to UNKNOWN. (The macOS parser already handled this; the Linux one did not.)

Both bugs were invisible on a correctly-matched platform and only appeared when
we deliberately fed the agent a mismatched target.

### Known false positive (by design)

`CIS-5.2.10` reports **FAIL** for `PermitRootLogin prohibit-password`. CIS 5.2.10
requires exactly `no`, so this is defensible and the evidence line shows the real
value — but many deliberately hardened hosts use key-only root login, and those
operators will read this as a false positive. We chose strict CIS conformance
over our own judgement and surfaced the actual value so a reader can override.

### Known false negative (by design)

macOS `NET-001` ignores wildcard binds on ports ≥ 49152 (the IANA ephemeral
range). Kernel-assigned source ports appear there and change on every reboot, so
including them would make evidence unstable without describing a durable
exposure. A genuinely exposed service on a high port would be missed.

---

## 5. How we worked

**Build sequence (actual).** The pipe was built before the logic, as the handout
advises: allowlist + validator → connectors → a rule engine returning real
verdicts → report. The first end-to-end run produced a real, correct report
against the local macOS host on the first attempt, and every subsequent change
improved something that already worked.

**Verified before assuming.** Before writing a single macOS parser we ran the
candidate commands by hand and read the output. That decision paid for itself
three times over (§2) — `alf globalstate` does not exist on macOS 15, macOS
`netstat` uses dot-separated ports, and `autoLoginUser` treats absence as the
secure state. Guessing any of those would have produced a plausible parser that
silently reported the wrong verdict.

**Dead end 1 — `temperature=0` for reproducibility.** The planned no-drift
mechanism was a zero-temperature LLM call. Current Claude models reject
`temperature` with a 400, so the approach is impossible. Abandoned in favour of
structural determinism plus a report fingerprint, which is a stronger guarantee
anyway: it holds even if the model is swapped, and it is *checkable* by a judge
in one command instead of trusted.

**Dead end 2 — `defaults read com.apple.alf globalstate` as the macOS firewall
source.** Every macOS hardening guide still cites it; it returns
"does not exist" on macOS 15. Kept only as a fallback for older releases.

> **To be completed by the team:** planned-vs-actual timings against the Part 8
> checkpoints, and who owned which component. That is your record to write, not
> ours to invent.

---

## 6. Limitations and next steps

1. **Windows is unverified.** 9 rules written to documented `Format-List` shapes,
   never executed against a real host. They degrade to UNKNOWN rather than guess,
   but "degrades safely" is not "works". *Next:* run against a Windows Sandbox or
   an evaluation VM and correct the parsers against real output — the same
   exercise that fixed three macOS parsers.
2. **Sudo-gated evidence is skipped, not handled.** `/etc/shadow`, `ufw status`
   and `iptables -S` all need root, so on a normal audit account four to five
   rules are UNKNOWN. *Next:* support an explicit, allowlisted `sudo -n` prefix
   for a named subset of read commands, requiring a documented NOPASSWD entry
   scoped to exactly those commands — so the elevation is reviewable and narrow
   rather than "run the agent as root".
3. **The firewall rule is effectively untestable in the Docker harness.**
   Containers share the host netfilter namespace and ship no ufw/iptables, so
   `CIS-3.5.1` is UNKNOWN on every container target. *Next:* add a VM-based
   target (Lima/Multipass) so the firewall and auto-update rules get real
   PASS/FAIL coverage.
4. **No mid-run disconnect recovery.** If the target drops partway through, the
   remaining commands each fail individually and land as UNKNOWN with a reason —
   correct and non-crashing, but the report does not distinguish "this one
   command was unavailable" from "the host vanished at command 12". *Next:*
   detect consecutive transport failures and mark the run explicitly partial.
5. **`EXPECTED_PUBLIC_PORTS` is hardcoded** to {22, 80, 443}. A web server on
   8080 is flagged on every host. *Next:* a per-target expected-services file,
   itself versioned and reviewable, so the exception is documented rather than
   implicit.
6. **Rule coverage is intentionally narrow** — ~11 controls, not the full CIS
   benchmark. Every one is grounded and evidenced; we would rather add the 12th
   rule with real output in hand than ship 40 unverified parsers.

---

## 7. How to run it

Requires **Python 3.10+**. No dependencies for the core audit.

```bash
git clone <repo> && cd RISE-RST

# Audit this machine
python3 main.py --target local

# Audit a remote host (key-based auth, host-key checking on)
export SENTINEL_SSH_KEY=~/.ssh/audit_ed25519
python3 main.py --target audit@10.0.0.5

# Audit a local container
python3 main.py --target docker://my-container

# Re-audit and see what changed since the last report
python3 main.py --target local --reaudit

# Inspect the safety surface without contacting anything
python3 main.py --list-commands
python3 main.py --list-rules
```

Reports land in `reports/audit_<timestamp>.{json,md}`.

**Reproduce the test targets:**

```bash
docker build -f targets/Dockerfile.vulnerable -t sentinel-vulnerable targets/
docker build -f targets/Dockerfile.hardened   -t sentinel-hardened   targets/
docker run -d --name sa-vuln sentinel-vulnerable
docker run -d --name sa-hard sentinel-hardened

python3 main.py --target docker://sa-vuln    # expect 0/100, 7 findings
python3 main.py --target docker://sa-hard    # expect 100/100, 0 findings
```

**Verify the no-drift claim yourself:**

```bash
python3 main.py --target local --quiet
python3 main.py --target local --quiet
# compare the two printed fingerprints — they will be identical
```

**Optional LLM explanations** (the tool scores identically without this):

```bash
export ANTHROPIC_API_KEY=...
python3 main.py --target local --llm
```

**Exit codes:** `0` audit completed · `1` internal error · `2` connector could
not establish a session · `3` OS not identified · `4` usage error.
