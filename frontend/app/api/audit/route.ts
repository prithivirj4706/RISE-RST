/**
 * POST /api/audit — run a real SentinelAudit audit and return its report.
 *
 * This route does NOT audit anything itself. It shells out to the verified
 * Python engine at the repository root and returns that engine's report.json.
 *
 * That is the whole point, and it is a deliberate reversal of the previous
 * implementation, which re-implemented auditing in TypeScript and asked an LLM
 * to assign PASS/FAIL. Three contract violations disappear as a result:
 *
 *   1. VERDICTS ARE DETERMINISTIC. PASS/FAIL/UNKNOWN comes from the Python rule
 *      engine's parsers, never from a model. "The prioritizer must never mark a
 *      rule PASS/FAIL itself." Reports are also reproducible — the engine emits
 *      a SHA-256 fingerprint over everything but the timestamp, returned below
 *      as `fingerprint` so the UI can prove two runs matched.
 *
 *   2. COMMANDS COME FROM A FIXED ALLOWLIST. This route accepts no command list
 *      at all. The client cannot influence what runs on the target; the engine's
 *      import-time-validated allowlist decides, and nothing else can add to it.
 *
 *   3. NO PASSWORDS. Key-based auth only. We pass a key *path*; key material
 *      never enters this process, this request, or the browser.
 *
 * The engine is invoked with execFile (argv array, no shell), so nothing here
 * can be shell-injected either.
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

/** Repo root — the frontend lives in <repo>/frontend. */
const REPO_ROOT = process.env.SENTINEL_ROOT ?? path.resolve(process.cwd(), "..")
const PYTHON = process.env.SENTINEL_PYTHON ?? "python3"

type Transport = "local" | "ssh" | "docker"

type AuditRequest = {
  transport?: Transport
  host?: string
  port?: number
  username?: string
  /** Path to a private key. Never key material. */
  keyPath?: string
  container?: string
  /** Throwaway targets only; surfaced loudly in the report notes. */
  insecureHostKey?: boolean
}

function bad(message: string, status = 400) {
  return NextResponse.json({ error: message }, { status })
}

/** Reject anything that isn't a plain host/user/container token. */
const SAFE = /^[A-Za-z0-9._@:-]{1,255}$/
const SAFE_PATH = /^[A-Za-z0-9._/~-]{1,512}$/

export async function POST(req: Request) {
  let body: AuditRequest
  try {
    body = (await req.json()) as AuditRequest
  } catch {
    return bad("Invalid JSON body")
  }

  // Reject the parameters the old contract accepted, with an explanation rather
  // than silently ignoring them — a client still sending these is relying on
  // behaviour that was removed on purpose.
  const legacy = body as Record<string, unknown>
  if (Array.isArray(legacy.commands)) {
    return bad(
      "This endpoint no longer accepts a command list. Commands come from the " +
        "engine's fixed, import-time-validated allowlist so the client cannot " +
        "influence what runs on the target.",
    )
  }
  if (legacy.password || legacy.privateKey || legacy.passphrase) {
    return bad(
      "Password and inline-key authentication are not supported. Pass `keyPath` " +
        "(a path on the server) and use key-based auth.",
    )
  }

  const transport: Transport = body.transport ?? "local"

  // ---- build the target argument -------------------------------------
  let target: string
  if (transport === "local") {
    target = "local"
  } else if (transport === "docker") {
    const c = (body.container ?? "").trim()
    if (!c) return bad("Container name is required")
    if (!SAFE.test(c)) return bad("Container name contains unsupported characters")
    target = `docker://${c}`
  } else if (transport === "ssh") {
    const host = (body.host ?? "").trim()
    const user = (body.username ?? "").trim()
    if (!host) return bad("Host is required")
    if (!SAFE.test(host)) return bad("Host contains unsupported characters")
    if (user && !SAFE.test(user)) return bad("Username contains unsupported characters")
    target = user ? `${user}@${host}` : host
  } else {
    return bad("Unknown transport")
  }

  const args = ["main.py", "--target", target, "--quiet"]

  if (transport === "ssh") {
    const port = Number(body.port) || 22
    if (!Number.isInteger(port) || port < 1 || port > 65535) return bad("Invalid port")
    args.push("--port", String(port))
    const keyPath = (body.keyPath ?? "").trim()
    if (keyPath) {
      if (!SAFE_PATH.test(keyPath)) return bad("Key path contains unsupported characters")
      args.push("--key", keyPath)
    }
    if (body.insecureHostKey) args.push("--insecure-host-key")
  }

  // ---- run the engine into a scratch report dir -----------------------
  const outDir = await mkdtemp(path.join(tmpdir(), "sentinel-web-"))
  args.push("--out", outDir)

  try {
    try {
      await run(PYTHON, args, {
        cwd: REPO_ROOT,
        timeout: AUDIT_TIMEOUT_MS,
        maxBuffer: MAX_BUFFER,
      })
    } catch (err) {
      const e = err as { code?: number; stderr?: string; killed?: boolean; message?: string }
      if (e.killed) {
        return bad("The audit timed out before the engine finished.", 504)
      }
      // The engine's exit codes are meaningful; surface them faithfully.
      const stderr = (e.stderr ?? "").trim()
      const first = stderr.split("\n").find((l) => l.trim()) ?? e.message ?? "unknown error"
      if (e.code === 2) return bad(`Connector error: ${first}`, 502)
      if (e.code === 3) return bad(`Could not identify the target's OS: ${first}`, 502)
      if (e.code === 4) return bad(`Configuration error: ${first}`)
      return bad(`Audit failed: ${first}`, 500)
    }

    const files = (await readdir(outDir)).filter(
      (f) => f.startsWith("audit_") && f.endsWith(".json"),
    )
    if (files.length === 0) {
      return bad("The engine produced no report.", 500)
    }
    files.sort()
    const raw = await readFile(path.join(outDir, files[files.length - 1]), "utf8")
    const report = JSON.parse(raw)

    // ---- map the engine's report onto the UI contract -----------------
    return NextResponse.json({
      target: {
        host: report.target?.label ?? target,
        transport: report.target?.transport ?? transport,
        user: report.target?.remote_user ?? report.target?.user ?? "",
        port: Number(report.target?.port) || (transport === "ssh" ? Number(body.port) || 22 : 0),
        platform: report.platform,
      },
      // Reproducibility proof, straight from the engine.
      fingerprint: report.fingerprint,
      generatedAt: report.generated_at,
      score: report.score,
      summary: report.summary,
      notes: report.notes ?? [],
      results: (report.commands ?? []).map((c: Record<string, unknown>) => ({
        command: c.command,
        exitCode: c.exit_code ?? null,
        stdout: c.stdout ?? "",
        stderr: c.stderr ?? "",
        available: c.available ?? true,
        commandId: c.command_id,
      })),
      findings: (report.findings ?? []).map((f: Record<string, unknown>) => ({
        rule_id: f.rule_id,
        control_id: f.control_id,
        title: f.title,
        category: f.category,
        command: f.command,
        status: f.status,
        evidence: f.evidence,
        severity_hint: String(f.severity ?? "low").toLowerCase(),
        reason: f.reason ?? null,
      })),
      fixList: (report.fix_list ?? []).map((f: Record<string, unknown>) => ({
        priority: f.priority,
        rule_id: f.rule_id,
        category: f.category,
        finding: f.finding,
        why_it_matters: f.why_it_matters,
        fix_command: f.fix_command,
        evidence_ref: f.evidence_ref,
        evidence: f.evidence,
        severity: String(f.severity ?? "low").toLowerCase(),
      })),
    })
  } finally {
    await rm(outDir, { recursive: true, force: true }).catch(() => {})
  }
}
