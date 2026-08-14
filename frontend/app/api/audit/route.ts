/**
 * POST /api/audit — return a real SentinelAudit report.
 *
 * This route does not audit anything itself. It runs the Python engine at the
 * repository root and maps its report.json onto the shape this UI already
 * expects, so every component renders unchanged.
 *
 * Why it works this way
 * ---------------------
 * The previous implementation re-implemented auditing in TypeScript and asked
 * a language model to assign PASS/FAIL. Three problems disappear by delegating
 * to the engine instead:
 *
 *   1. Verdicts are deterministic. PASS/FAIL/UNKNOWN comes from the engine's
 *      parsers reading real captured output, never from a model. The engine
 *      also emits a SHA-256 fingerprint over everything but the timestamp, so
 *      two runs against an unchanged target are provably identical.
 *   2. Commands come from a fixed allowlist validated read-only at import time
 *      — a mutating command cannot even be defined. The `commands` field this
 *      UI sends is therefore ignored rather than executed.
 *   3. No credential reaches this process. Local and Docker targets need none;
 *      SSH uses a key *path* read from the server environment.
 *
 * Target selection reuses the existing "Host / IP" field:
 *
 *   local | localhost | 127.0.0.1        → audit the machine running this app
 *   docker://<name>   or  docker:<name>  → audit a local container
 *   anything else                        → treated as an SSH host
 */

import { execFile } from "node:child_process"
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { promisify } from "node:util"

import { NextResponse } from "next/server"

const run = promisify(execFile)

export const runtime = "nodejs"
export const maxDuration = 120

const AUDIT_TIMEOUT_MS = 100_000
const MAX_BUFFER = 12 * 1024 * 1024

/** Repo root — this app lives in <repo>/frontend. */
const REPO_ROOT = process.env.SENTINEL_ROOT ?? path.resolve(process.cwd(), "..")
const PYTHON = process.env.SENTINEL_PYTHON ?? "python3"
/** Key path for SSH targets. A path only — never key material. */
const SSH_KEY = process.env.SENTINEL_SSH_KEY ?? ""

/** Only plain host / container tokens ever reach argv. */
const SAFE = /^[A-Za-z0-9._@:-]{1,255}$/

type Body = {
  host?: string
  port?: number
  username?: string
  authMethod?: "key" | "password"
  /** Accepted by the form, deliberately never forwarded. */
  password?: string
  privateKey?: string
  passphrase?: string
  commands?: string[]
}

function bad(message: string, status = 400) {
  return NextResponse.json({ error: message }, { status })
}

export async function POST(req: Request) {
  let body: Body
  try {
    body = (await req.json()) as Body
  } catch {
    return bad("Invalid JSON body")
  }

  const raw = (body.host ?? "").trim()
  if (!raw) return bad("Enter a target: 'local', 'docker://<container>', or a hostname.")

  let target: string
  let transport: "local" | "docker" | "ssh"

  if (/^(local|localhost|127\.0\.0\.1)$/i.test(raw)) {
    transport = "local"
    target = "local"
  } else if (/^docker:(\/\/)?/i.test(raw)) {
    const name = raw.replace(/^docker:(\/\/)?/i, "").trim()
    if (!name) return bad("Enter a container name, e.g. docker://sa-linux")
    if (!SAFE.test(name)) return bad("Container name contains unsupported characters")
    transport = "docker"
    target = `docker://${name}`
  } else {
    if (!SAFE.test(raw)) return bad("Host contains unsupported characters")
    transport = "ssh"
    const user = (body.username ?? "").trim()
    if (user && !SAFE.test(user)) return bad("Username contains unsupported characters")
    target = user ? `${user}@${raw}` : raw
  }

  if (transport === "ssh" && !SSH_KEY) {
    return bad(
      "SSH targets need key-based authentication. The engine runs with " +
        "PasswordAuthentication=no, so a typed password or pasted key cannot be " +
        "used. Set SENTINEL_SSH_KEY to a private-key path on the server and " +
        "restart, or target 'local' or 'docker://<container>' instead.",
    )
  }

  const args = ["main.py", "--target", target, "--quiet"]
  if (transport === "ssh") {
    const port = Number(body.port) || 22
    if (!Number.isInteger(port) || port < 1 || port > 65535) return bad("Invalid port")
    args.push("--port", String(port), "--key", SSH_KEY)
  }

  const outDir = await mkdtemp(path.join(tmpdir(), "sentinel-web-"))
  args.push("--out", outDir)

  try {
    try {
      // execFile with an argv array: no shell, so nothing here is injectable.
      await run(PYTHON, args, {
        cwd: REPO_ROOT,
        timeout: AUDIT_TIMEOUT_MS,
        maxBuffer: MAX_BUFFER,
      })
    } catch (err) {
      const e = err as { code?: number; stderr?: string; killed?: boolean; message?: string }
      if (e.killed) return bad("The audit timed out before the engine finished.", 504)
      const stderr = (e.stderr ?? "").trim()
      const first = stderr.split("\n").find((l) => l.trim()) ?? e.message ?? "unknown error"
      // The engine's exit codes are meaningful — surface them faithfully.
      if (e.code === 2) return bad(first.replace(/^connector error:\s*/, ""), 502)
      if (e.code === 3) return bad("Could not identify the target's OS: " + first, 502)
      if (e.code === 4) return bad("Configuration error: " + first)
      return bad("Audit failed: " + first, 500)
    }

    const files = (await readdir(outDir)).filter(
      (f) => f.startsWith("audit_") && f.endsWith(".json"),
    )
    if (files.length === 0) return bad("The engine produced no report.", 500)
    files.sort()
    const report = JSON.parse(await readFile(path.join(outDir, files[files.length - 1]), "utf8"))

    return NextResponse.json({
      target: {
        host: report.target?.label ?? target,
        transport: report.target?.transport ?? transport,
        user: report.target?.remote_user ?? report.target?.user ?? "",
        port: Number(report.target?.port) || (transport === "ssh" ? Number(body.port) || 22 : 0),
      },
      results: (report.commands ?? []).map((c: Record<string, unknown>) => ({
        command: c.command,
        exitCode: c.exit_code ?? null,
        stdout: c.stdout ?? "",
        stderr: c.stderr ?? "",
      })),
      findings: (report.findings ?? []).map((f: Record<string, unknown>) => ({
        rule_id: f.rule_id,
        title: f.title,
        category: f.category,
        command: f.command,
        status: f.status,
        // UNKNOWN carries the reason the engine logged, so the UI shows why.
        evidence:
          f.status === "UNKNOWN" && f.reason ? String(f.reason) : String(f.evidence ?? ""),
        severity_hint: String(f.severity ?? "low").toLowerCase(),
      })),
      fixList: (report.fix_list ?? []).map((f: Record<string, unknown>) => ({
        priority: f.priority,
        rule_id: f.rule_id,
        category: f.category,
        finding: f.finding,
        why_it_matters: f.why_it_matters,
        fix_command: f.fix_command,
        evidence_ref: f.evidence_ref,
        severity: String(f.severity ?? "low").toLowerCase(),
      })),
      // Extras this UI does not render today, but which prove the run is real.
      platform: report.platform,
      fingerprint: report.fingerprint,
      score: report.score,
      summary: report.summary,
    })
  } finally {
    await rm(outDir, { recursive: true, force: true }).catch(() => {})
  }
}
