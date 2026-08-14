# SENTINELAUDIT

**Cross-Platform, Evidence-First Security Auditing Agent**

Point it at a host. It runs a fixed allowlist of strictly read-only commands,
evaluates CIS-Benchmark-style rules with deterministic parsers, and produces
`PASS / FAIL / UNKNOWN` findings - each one backed by the real captured output
of the command that produced it. No guessing, no LLM verdicts.

```
TARGET  ->  READ-ONLY COMMANDS  ->  DETERMINISTIC RULES  ->  PASS/FAIL/UNKNOWN
                                                                   |
        RE-AUDIT  <-  REPORT  <-  SEVERITY / SCORE  <-  EVIDENCE  <-+
```

---

## Integration status - read before building on this branch

This branch currently contains **two implementations**, developed in parallel
against the same PRD and merged here with unrelated histories. Both run. Neither
has been deleted. **They have not yet been reconciled.**

| | Track A - `core/` | Track B - `sentinelaudit/` |
|---|---|---|
| Entry point | `python main_core.py` | `python main.py` |
| Execution | local `subprocess` only | **`local` / `ssh` / `docker exec`** |
| Command safety | `ALLOWED_COMMANDS` map per adapter | allowlist validated **at import time** |
| Rules | `rules/*.py` | `sentinelaudit/rules/*.py` (11 Linux, 14 macOS, 9 Windows) |
| Scoring | penalty model, **penalises UNKNOWN** | penalty model, **UNKNOWN costs nothing**; withholds the grade below 60% coverage |
| Reporting | `report/reporter.py` | `report.json` + `report.md` + SHA-256 fingerprint |
| Re-audit | `report/re_audit.py` | `--reaudit`: FIXED / STILL_FAILING / NEW / REGRESSED |
| Tests | `pytest tests/` | verified against live macOS + 2 Docker targets |

**Reconciliation is the next task.** See [MERGE_NOTES.md](MERGE_NOTES.md) for a
file-by-file plan and the open decisions - chiefly: does UNKNOWN cost score points?

---

## Core principles

| Principle | Detail |
|---|---|
| **Evidence first** | Every verdict is backed by captured command output |
| **Deterministic rules** | `PASS / FAIL / UNKNOWN` is decided by code, never by an LLM |
| **Read-only** | The tool never modifies the target machine |
| **No arbitrary execution** | Only pre-approved commands can run |
| **No automatic remediation** | The tool reports; a human decides what to fix |

---

## Quick start

Python 3.10+. Track B needs **no dependencies**; Track A and the tests need `pytest`.

```bash
pip install -r requirements.txt      # pytest, for tests + main_core.py

# Track B - full pipeline, remote-capable
python main.py --target local                  # audit this machine
python main.py --target audit@10.0.0.5         # audit a remote host over SSH
python main.py --target docker://my-container  # audit a local container
python main.py --target local --reaudit        # diff against the last report

# Track A - local engine
python main_core.py

# Tests
pytest tests/ -v
```

Reports are written to `reports/audit_<timestamp>.{json,md}`.

---

## Finding schema

Both tracks emit the same core fields, so reports stay comparable:

```python
Finding(
    rule_id     = "FW-001",            # unique rule identifier
    platform    = "linux",             # "linux" | "windows" | "macos"
    title       = "Firewall Enabled",  # human-readable description
    status      = "PASS",              # PASS | FAIL | UNKNOWN
    severity    = "HIGH",              # CRITICAL | HIGH | MEDIUM | LOW
    command     = "ufw status",        # exact command run (audit trail)
    evidence    = "<captured stdout>", # real command output, never fabricated
    remediation = "Enable ufw ...",    # recommendation shown on FAIL
)
```

Track B additionally carries `control_id` - the portable cross-platform control
(`FW-001`) - alongside a CIS-style `rule_id` (`CIS-3.5.1`), plus `command_id`,
`rationale`, and a `reason` for every UNKNOWN. Track A's rule-ID convention
(`FW-001`, `SSH-001`, `USR-001`, `FS-001`, `NET-001`, `KRN-001`, `LOG-001`) is
preserved as Track B's `control_id`, so the two line up.

---

## The safety model (Track B)

Enforced in `sentinelaudit/allowlist.py`, validated **at import time** - a
mutating command cannot even be defined:

1. **No shell, ever.** Commands are argv lists run with `exec`-style APIs. SSH is
   the one place a string is unavoidable, so every argv is asserted to survive a
   `shlex.quote` -> `shlex.split` round-trip unchanged.
2. **Read-only binaries only.** `argv[0]` must be in `READ_ONLY_BINARIES`, and
   dual-mode binaries (`systemctl`, `defaults`, `ufw`, `powershell`, ...) are
   pinned to read subcommands. `find` may not carry `-exec`/`-delete`; `awk`
   programs may not contain `system(` or redirection; PowerShell is restricted
   to read verbs.
3. **Nothing is constructed at runtime.** Every argv is a literal. No rule,
   config value, CLI flag, or LLM response can add to the list.

```bash
python main.py --list-commands   # the entire allowlist
python main.py --list-rules      # every rule, every platform
```

---

## Reproducibility

Every Track B report carries a **fingerprint** - SHA-256 over the whole report
except the timestamp:

```bash
python main.py --target local --quiet
python main.py --target local --quiet
# identical fingerprints => zero drift
```

Ordering is structural (`severity_rank`, then `rule_id`), so it cannot drift.
Note that `temperature=0` - the usual LLM determinism lever - is **not
available**: current Claude models reject the parameter outright. Determinism is
guaranteed by construction instead of by sampling settings.

---

## Security score

| Range | Grade |
|---|---|
| 90-100 | A - Excellent |
| 75-89 | B - Good |
| 60-74 | C - Fair |
| 40-59 | D - Poor |
| 0-39 | F - Critical |

Transparent penalty model. No ML, no LLM - same input, same score, every time.
Track B withholds the letter grade entirely when fewer than 60% of rules reached
a verdict, so a mostly-unreadable target cannot report "100/100, grade A".

**Open decision:** Track A also penalises UNKNOWN (CRITICAL -12, HIGH -7, ...);
Track B does not, on the grounds that an audit which could not read something has
not found a problem. Pick one - see MERGE_NOTES.md.

---

## Platform coverage

| Platform | Rules (Track B) | Verified against a real host |
|---|---|---|
| **Linux** | 11 | yes - Docker `ubuntu:22.04`, hardened + deliberately vulnerable |
| **macOS** | 14 | yes - macOS 15.6.1 |
| **Windows** | 9 | **no** - parsers written to documented output shapes |

Windows rules return UNKNOWN rather than guess, so the untested path degrades to
"could not read this" rather than a fabricated verdict.

Reproduce the Linux test targets:

```bash
docker build -f targets/Dockerfile.vulnerable -t sentinel-vulnerable targets/
docker build -f targets/Dockerfile.hardened   -t sentinel-hardened   targets/
docker run -d --name sa-vuln sentinel-vulnerable
docker run -d --name sa-hard sentinel-hardened

python main.py --target docker://sa-vuln    # expect 0/100, 7 findings
python main.py --target docker://sa-hard    # expect 100/100, 0 findings
```

---

## Optional LLM layer

Off by default. The tool scores identically without it.

```bash
export ANTHROPIC_API_KEY=...     # never stored in the repo
python main.py --target local --llm
```

The model receives **only** structured findings the rule engine already
adjudicated. It never sees a credential, a hostname, a shell, or a raw
transcript, and returns **only** `why_it_matters` prose. Any rule ID it mentions
that this run did not produce is discarded. Verdicts, severities, ordering and
remediation commands come from deterministic tables and are never sent for
review. Any failure falls back to the static rationale.

---

## Exit codes (Track B)

| Code | Meaning |
|---|---|
| 0 | audit completed (FAIL findings are a successful audit) |
| 1 | unexpected internal error |
| 2 | the connector could not establish a session |
| 3 | the target OS could not be identified |
| 4 | usage or configuration error |

---

## Contributing

### Adding a rule to Track A

1. Add the command to `ALLOWED_COMMANDS` in `platforms/<os>.py`.
2. Implement `_check_<name>(self) -> Finding` in the adapter.
3. Call it from `run_checks()`.
4. Define the rule spec in `rules/<os>_rules.py`.
5. Write a test in `tests/`.

### Adding a rule to Track B

1. Add the command to the relevant list in `sentinelaudit/allowlist.py`
   (validated read-only at import time - a mutating command will raise).
2. Write a parser in `sentinelaudit/rules/<os>_rules.py` returning
   `verdict_pass` / `verdict_fail` / `verdict_unknown` with the evidence.
3. Append a `Rule(...)` to `RULES`, declaring the command IDs it may read.
4. Run `python main.py --list-rules` to confirm validation passes.

---

## What SENTINELAUDIT will NEVER do

- Execute arbitrary shell commands
- Modify the target machine
- Use an LLM to decide PASS / FAIL
- Automatically remediate issues
- Accept commands from user input at runtime

---

*SENTINELAUDIT - Evidence first, always.*
