# Merge notes — two implementations, one branch

`integration` now contains two complete implementations of the same PRD, merged
with `--allow-unrelated-histories`. **Nothing was deleted.** Both run today.
This file is the reconciliation plan.

## What happened

Two tracks were built in parallel against the same design document:

- **Track A** (`core/`, `platforms/`, `rules/`, `report/`, `tests/`) — commits
  `26ee45e` (Phase 1 foundation) and `05d659d` (Phase 2 orchestration + scoring).
- **Track B** (`sentinelaudit/`, `targets/`) — commit `392b3ea`.

They share no git ancestor, so nothing auto-resolved. Three files collided and
were resolved by hand:

| File | Resolution |
| --- | --- |
| `main.py` | Track B's entrypoint. It defaults to `--target local`, so a bare `python main.py` still performs a local audit exactly as Track A's did. |
| `main_core.py` | **New file** — Track A's original `main.py`, preserved verbatim so its pipeline stays runnable. |
| `.gitignore` | Union. Kept Track A's `reports/*.ext` form (so `reports/.gitkeep` stays tracked) and added credential patterns. |
| `README.md` | Rewritten to document both tracks honestly rather than pick a winner. |

Everything else merged cleanly because the paths do not overlap
(`rules/` vs `sentinelaudit/rules/`, `platforms/` vs `sentinelaudit/platforms/`).

## Why this is not the final state

Two engines, two rule sets, and two scoring models in one repo is a liability at
demo time — a judge asking "which one runs?" is a question we should not need to
answer. Reconcile before the freeze.

## Recommended reconciliation

Keep Track A's **project structure** (it is what the team's README and tests
already document) and port Track B's **capabilities** into it. Concretely:

| Take from | What | Why |
| --- | --- | --- |
| A | `core/` package layout, `tests/`, `conftest.py`, `requirements.txt` | Already the documented contract; the test suite is real. |
| B | `sentinelaudit/connectors/` | Track A cannot audit a remote host at all. This is worth 15 marks under the handout ("connector runs clean, strictly read-only") plus Requirement 9. |
| B | `sentinelaudit/allowlist.py` | Import-time validation is strictly stronger than a per-adapter `ALLOWED_COMMANDS` dict — a mutating command cannot be *defined*, let alone run. |
| B | report fingerprint + structural ordering | Requirement 6/10 (no drift) is worth 10 marks and scores **zero on partial credit**. The fingerprint makes it checkable in one command. |
| B | `--reaudit` diff | Explicit stretch goal in the handout. |
| B | the 34 verified rule parsers | Verified against live macOS and two Docker Linux targets; three were rewritten after observing real output contradicted the documented behaviour. |
| A | rule-ID convention (`FW-001`, `SSH-001`, …) | Already preserved as Track B's `control_id`; make it primary and keep the CIS ID as a secondary field. |

Rough shape of the work: move `sentinelaudit/connectors/` to `core/connectors/`,
have `core/collector.py` accept a connector instead of calling `subprocess`
directly, and re-point Track B's rule modules at `core`'s `Finding`. The rule
parsers themselves are pure functions over captured output and should port
unchanged.

## Open decisions (need a human call)

1. **Does UNKNOWN cost score points?**
   Track A: yes (CRITICAL −12, HIGH −7, MEDIUM −4, LOW −1).
   Track B: no — an audit that could not read something has not found a problem;
   instead it reports coverage and **withholds the letter grade below 60%**.
   These give materially different scores on the same host. Pick one. Track B's
   rationale: penalising UNKNOWN means an unprivileged audit account silently
   looks like an insecure host, which is a different claim than the evidence
   supports.

2. **One entrypoint or two?** Currently `main.py` (Track B) and `main_core.py`
   (Track A). Ship one.

3. **Grade bands differ.** Track A: C is 50–74, D is 25–49. Track B: C is 60–74,
   D is 40–59. Trivial, but they must match.

4. **`requirements.txt`** lists only `pytest`. Track B needs nothing at runtime;
   the optional LLM layer needs `anthropic`, which should be an extra, not a
   hard dependency — the audit must run on a bare Python.

## Verification status carried over from Track B

| Target | Result |
| --- | --- |
| macOS 15.6.1 (dev host) | 4 FAIL / 9 PASS / 1 UNKNOWN — 68/100 |
| `sentinel-vulnerable` (ubuntu:22.04) | caught all 7 baked-in misconfigurations — 0/100 |
| `sentinel-hardened` (ubuntu:22.04) | 10 PASS / 1 UNKNOWN — 100/100 |
| Re-audit after 3 fixes applied | 3 FIXED, 4 STILL_FAILING, 0→32 |
| Unprivileged `nobody` user | shadow/sudoers reads → UNKNOWN; SSH evidence auto-fell back to the config file |
| Unreachable SSH host | no report, exit 2 |
| Docker daemon down | no report, exit 2 |
| Linux rules forced onto macOS | 11 UNKNOWN, grade withheld |

Two false PASSes were found and fixed during that testing (macOS `netstat -tuln`
returns the UNIX-socket table with exit 0; an unreadable `/etc/sudoers` with an
empty `sudoers.d`). Both are written up in [REPORT.md](REPORT.md) §4 — the
handout awards marks for exactly that kind of explanation, so keep it.
