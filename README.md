# SentinelAudit

**A read-only, evidence-first security auditor.**

Point it at a host. It runs a fixed allowlist of strictly read-only commands,
evaluates CIS-Benchmark-style rules with deterministic parsers, and produces a
prioritized remediation plan in which **every item traces back to one rule, one
command, and that command's real captured output**.

It does not fix anything. It does not guess. When it cannot read something it
says `UNKNOWN` and tells you why.

```
connector ──▶ collector ──▶ rule engine ──▶ prioritizer ──▶ report.json
  (ssh /       (fixed        (PASS/FAIL/     (rank +          report.md
   docker /     allowlist,    UNKNOWN +       remediation)
   local)       read-only)    evidence)
```

---

## Quick start

No dependencies. Python 3.10+, standard library only.

```bash
python3 main.py --target local
```

Audit a remote host over SSH:

```bash
python3 main.py --target audit@10.0.0.5 --key ~/.ssh/audit_ed25519
```

Audit a local container:

```bash
python3 main.py --target docker://vulnerable-ubuntu
```

Re-audit after fixing something, and see what actually changed:

```bash
python3 main.py --target local --reaudit
```

Reports are written to `reports/audit_<timestamp>.json` and `.md`.

---

## What makes a finding trustworthy

Every fix-list item carries the full chain:

```
Rule ID  ──▶  Command  ──▶  Raw output  ──▶  Verdict  ──▶  Severity  ──▶  Fix
```

A real finding from a live run:

```
CIS-Apple-2.5.2.1   Application Firewall is enabled
  command:  /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
  evidence: Firewall is disabled. (State = 0)
  verdict:  FAIL          severity: HIGH
  fix:      sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
```

Nothing in that item could have been produced without running the command.

---

## The safety model

Enforced in [`sentinelaudit/allowlist.py`](sentinelaudit/allowlist.py), validated
at **import time** — a mutating command cannot even be defined:

1. **No shell, ever.** Commands are argv lists executed with `exec`-style APIs.
   The SSH transport is the one place a string is unavoidable, so every argv is
   asserted to survive a `shlex.quote` → `shlex.split` round-trip unchanged.
2. **Read-only binaries only.** `argv[0]` must be in `READ_ONLY_BINARIES`, and
   dual-mode binaries (`systemctl`, `defaults`, `ufw`, `powershell`, …) are
   pinned to read subcommands. `find` may not carry `-exec`/`-delete`; `awk`
   programs may not contain `system(` or output redirection; PowerShell scripts
   are restricted to read verbs.
3. **Nothing is constructed at runtime.** Every argv is a literal in that file.
   No rule, config value, CLI argument, or LLM response can add to it.

Credentials never enter the repository: the SSH key path comes from `--key` or
`SENTINEL_SSH_KEY` and only the *path* is ever recorded. Host-key checking is on
by default; `--insecure-host-key` prints a loud warning and records it in the
report.

---

## Reproducibility

Every report carries a **fingerprint** — a SHA-256 over the entire report except
the timestamp:

```bash
python3 main.py --target local --quiet
python3 main.py --target local --quiet
# identical fingerprints => zero drift
```

Ordering is structural, not stochastic: findings sort by
`(severity_rank, rule_id)`. The optional LLM layer cannot affect it — it only
supplies prose.

---

## Coverage

| Platform | Rules | Verified against a real host |
| --- | --- | --- |
| Linux | 11 | yes — Docker (`ubuntu:22.04`) |
| macOS | 14 | yes — macOS 15.6.1 |
| Windows | 9 | **no** — parsers written to documented output shapes |

Windows rules are structured to return `UNKNOWN` rather than guess, so the
untested path degrades to "could not read this" rather than a fabricated
verdict. See REPORT.md for the honest limitations.

```bash
python3 main.py --list-rules              # every rule, every platform
python3 main.py --list-commands           # the entire allowlist
```

---

## The optional LLM layer

Off by default. The tool scores identically without it.

```bash
export ANTHROPIC_API_KEY=...      # never stored in the repo
python3 main.py --target local --llm
```

The model receives **only** structured findings the rule engine already
adjudicated — rule ID, title, severity, status, evidence excerpt. It never sees
a credential, a hostname, a shell, or a raw transcript. It returns **only**
`why_it_matters` prose, schema-validated; any rule ID it mentions that this run
did not produce is discarded. Verdicts, severities, ordering and remediation
commands come from deterministic tables and are never sent for review. Any
failure — missing key, timeout, malformed JSON, model refusal — falls back to
the static rationale and is recorded in the report's notes.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | audit completed (FAIL findings are a successful audit) |
| 1 | unexpected internal error |
| 2 | the connector could not establish a session |
| 3 | the target OS could not be identified |
| 4 | usage or configuration error |

---

## Layout

```
main.py                     entrypoint
sentinelaudit/
  allowlist.py              the fixed command allowlist + read-only validator
  models.py                 CommandResult / Finding / FixItem / AuditReport
  engine.py                 collect once, evaluate deterministically
  prioritizer.py            rank failures, attach evidence + fix command
  scoring.py                deterministic score, refuses to grade low coverage
  reporter.py               report.json + report.md + fingerprint
  diff.py                   re-audit comparison
  llm.py                    optional explanation layer (bounded)
  cli.py                    argument parsing and the run flow
  connectors/               local | ssh | docker  (one interface)
  platforms/detector.py     OS detection over the connector
  rules/                    linux (11) | macos (14) | windows (9)
```
