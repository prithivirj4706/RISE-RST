# SENTINELAUDIT

**Cross-Platform Security Auditing Agent — Phase 1 Foundation**

---

## What is SENTINELAUDIT?

SENTINELAUDIT is an **evidence-first, cross-platform security auditing agent**.
It collects real command output from the target machine, evaluates it against
deterministic rules, and produces human-readable `PASS / FAIL / UNKNOWN` findings
with a transparent security score — no guessing, no AI magic.

```
TARGET MACHINE
      ↓
READ-ONLY COMMANDS
      ↓
DETERMINISTIC RULE ENGINE
      ↓
PASS / FAIL / UNKNOWN
      ↓
EVIDENCE
      ↓
SEVERITY / SCORE
      ↓
REPORT
      ↓
RE-AUDIT
```

---

## Core Principles

| Principle | Detail |
|---|---|
| **Evidence first** | Every verdict is backed by captured command output |
| **Deterministic rules** | `PASS / FAIL / UNKNOWN` is decided by code, never by an LLM |
| **Read-only** | The tool never modifies the target machine |
| **No arbitrary execution** | Only pre-approved commands can run |
| **No automatic remediation** | The tool reports; a human decides what to fix |

---

## Architecture

```
main.py                     ← CLI entry point
│
core/
│   models.py               ← Finding dataclass (shared schema)
│   detector.py             ← OS detection (stdlib only)
│   collector.py            ← Safe command runner (whitelist, no shell=True)
│   engine.py               ← Orchestrates detection → adapter → findings
│   scoring.py              ← Deterministic penalty-based scoring
│
platforms/
│   linux.py                ← Linux adapter   (primary platform)
│   windows.py              ← Windows adapter (secondary)
│   macos.py                ← macOS adapter   (secondary)
│
rules/
│   linux_rules.py          ← Linux security rule functions
│   windows_rules.py        ← Windows security rule functions
│   macos_rules.py          ← macOS security rule functions
│
report/
│   reporter.py             ← Report generator (Phase 2)
│   re_audit.py             ← Delta comparison between audits (Phase 2)
│
tests/                      ← pytest test suite
reports/                    ← Generated report output (gitignored)
```

---

## Platform Coverage

| Platform | Status |
|---|---|
| **Linux** | Primary — most complete rule coverage |
| **Windows** | Supported via platform adapter; rules in progress |
| **macOS** | Supported via platform adapter; rules in progress |

---

## Finding Schema

Every security rule — on every platform — returns the same `Finding` object:

```python
Finding(
    rule_id     = "FW-001",           # unique rule identifier
    platform    = "linux",            # "linux" | "windows" | "macos"
    title       = "Firewall Enabled", # human-readable description
    status      = "PASS",             # PASS | FAIL | UNKNOWN
    severity    = "HIGH",             # CRITICAL | HIGH | MEDIUM | LOW
    command     = "ufw status",       # exact command run (audit trail)
    evidence    = "<captured stdout>",# real command output, never fabricated
    remediation = "Enable ufw …",     # recommendation shown on FAIL/UNKNOWN
)
```

**The schema is frozen in Phase 1.** All contributors must use it as-is.

---

## Security Score

| Range | Grade |
|---|---|
| 90–100 | A — Excellent |
| 75–89  | B — Good |
| 50–74  | C — Fair |
| 25–49  | D — Poor |
| 0–24   | F — Critical |

Scoring is a simple transparent **penalty model**:

| Severity | FAIL penalty | UNKNOWN penalty |
|---|---|---|
| CRITICAL | −25 | −12 |
| HIGH | −15 | −7 |
| MEDIUM | −8 | −4 |
| LOW | −3 | −1 |

No ML. No LLM. Same input → same score, every time.

---

## Quick Start

```bash
# Clone and enter the project
git clone <repo-url>
cd sentinelaudit

# Install dependencies
pip install -r requirements.txt

# Run the auditor
python main.py

# Run the test suite
pytest tests/ -v
```

---

## Phase 1 Status

This is the **Phase 1 core foundation**. Only pipeline smoke-test (demo)
checks are implemented. They are clearly labelled `[DEMO]` in the output.

**What works:**
- OS detection
- Safe command execution abstraction
- Platform adapter dispatch (Linux / Windows / macOS)
- Finding schema and validation
- Deterministic scoring
- CLI output

**What is coming (Phase 2+):**
- Full Linux security rules (SSH, firewall, kernel params, file permissions…)
- Full Windows security rules (Defender, UAC, BitLocker…)
- Full macOS security rules (SIP, FileVault, Gatekeeper…)
- JSON / HTML / Markdown reports
- Re-audit delta comparison
- CI/CD integration

---

## Contributing

### Adding a new Linux rule (example)

1. Add the command to `ALLOWED_COMMANDS` in `platforms/linux.py`.
2. Implement `_check_<name>(self) -> Finding` in `LinuxAdapter`.
3. Call it from `run_checks()`.
4. Define the rule spec in `rules/linux_rules.py`.
5. Write a test in `tests/`.

**Rule ID conventions:**
- `FW-001` Firewall · `SSH-001` SSH · `USR-001` Users · `PKG-001` Packages
- `FS-001` File system · `NET-001` Network · `KRN-001` Kernel · `LOG-001` Logging

---

## What SENTINELAUDIT will NEVER do

- Execute arbitrary shell commands
- Modify the target machine
- Use an LLM to decide PASS / FAIL
- Automatically remediate issues
- Accept commands from user input at runtime

---

*SENTINELAUDIT — Evidence first, always.*
