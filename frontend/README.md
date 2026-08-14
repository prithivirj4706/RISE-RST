# SentinelAudit Console

Next.js front end for the SentinelAudit engine.

**It does not audit anything itself.** `POST /api/audit` shells out to the Python
engine at the repository root (`python3 main.py --target … --out …`) and returns
that engine's `report.json`. Verdicts, ordering, severities and remediation
commands are all produced by the deterministic rule engine.

## Run

```bash
cd frontend
npm install
npm run dev          # http://localhost:3000
```

The engine must be runnable from the repo root (`python3 main.py --target local`).
Override with `SENTINEL_ROOT` / `SENTINEL_PYTHON` if needed.

## What the API accepts

```jsonc
{ "transport": "local" }
{ "transport": "docker", "container": "sa-vuln" }
{ "transport": "ssh", "host": "10.0.0.5", "username": "audit",
  "keyPath": "~/.ssh/audit_ed25519", "port": 22, "insecureHostKey": false }
```

It **rejects**, with an explanation rather than silent failure:

| Rejected | Why |
|---|---|
| `commands: []` | Commands come from the engine's fixed, import-time-validated allowlist. A client-supplied command list is a remote-code-execution hole. |
| `password`, `privateKey`, `passphrase` | Key-based auth only. The connector runs `PasswordAuthentication=no`; only a key *path* is sent, never key material. |
| shell metacharacters in host/user/container | Validated against a strict charset before reaching `execFile` (argv array, no shell). |

## Design

Tokens in `app/globals.css` come from the `ui-ux-pro-max` skill for the brief
"security audit console / live terminal / developer tool": Dark Mode (OLED),
"code dark + run green" (`#0F172A` / `#22C55E`), JetBrains Mono, motion dial 4/10.
The same palette backs the engine's generated HTML report, so the console and
the artifact it produces read as one product.

Fonts are self-hosted via `next/font` rather than the skill's suggested Google
Fonts `@import`, so the console has no runtime CDN dependency.
