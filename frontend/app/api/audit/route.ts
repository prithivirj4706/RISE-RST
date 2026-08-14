import { NextResponse } from "next/server"
import { Client } from "ssh2"
import { checkCommands, checkCommand } from "@/lib/command-safety"
import { analyzeAudit, type CommandResult } from "@/lib/ai-analyze"
import { PLATFORMS, type Platform } from "@/lib/audit-data"

export const runtime = "nodejs"
export const maxDuration = 60

type AuthMethod = "key" | "password"

type AuditRequest = {
  platform: Platform
  host: string
  port?: number
  username: string
  authMethod: AuthMethod
  password?: string
  privateKey?: string
  passphrase?: string
  commands: string[]
}

const CONNECT_TIMEOUT_MS = 15_000
const PER_COMMAND_TIMEOUT_MS = 12_000

function bad(message: string, status = 400) {
  return NextResponse.json({ error: message }, { status })
}

export async function POST(req: Request) {
  let body: AuditRequest
  try {
    body = (await req.json()) as AuditRequest
  } catch {
    return bad("Invalid JSON body")
  }

  const { platform, host, username, authMethod, commands } = body
  const port = Number(body.port) || 22

  if (!platform || !(platform in PLATFORMS)) return bad("Unknown platform")
  if (!host?.trim()) return bad("Host is required")
  if (!username?.trim()) return bad("Username is required")
  if (!Array.isArray(commands) || commands.length === 0) return bad("Select at least one command")
  if (commands.length > 40) return bad("Too many commands")

  if (authMethod === "password" && !body.password) return bad("Password is required")
  if (authMethod === "key" && !body.privateKey?.trim()) return bad("Private key is required")

  // Determine which commands are from the platform's trusted allowlist vs. custom.
  const allowlist = new Set(PLATFORMS[platform].allowlist)
  const toRun = commands.map((cmd) => ({ cmd: cmd.trim(), trusted: allowlist.has(cmd.trim()) }))

  const safety = checkCommands(toRun)
  if (!safety.ok) {
    return bad(`Blocked unsafe command "${safety.cmd}": ${safety.reason}`, 422)
  }

  // Connect and run.
  const conn = new Client()

  const results = await new Promise<CommandResult[] | { error: string }>((resolve) => {
    const collected: CommandResult[] = []
    let settled = false

    const finish = (value: CommandResult[] | { error: string }) => {
      if (settled) return
      settled = true
      try {
        conn.end()
      } catch {
        /* noop */
      }
      resolve(value)
    }

    conn.on("ready", async () => {
      try {
        for (const { cmd, trusted } of toRun) {
          // Re-check each command right before dispatch (defense in depth).
          const check = checkCommand(cmd, trusted)
          if (!check.safe) {
            collected.push({ command: cmd, exitCode: null, stdout: "", stderr: `blocked: ${check.reason}` })
            continue
          }
          const result = await runCommand(conn, cmd)
          collected.push(result)
        }
        finish(collected)
      } catch (err) {
        finish({ error: err instanceof Error ? err.message : "Command execution failed" })
      }
    })

    conn.on("error", (err) => {
      finish({ error: `SSH connection failed: ${err.message}` })
    })

    conn.on("timeout", () => finish({ error: "SSH connection timed out" }))

    try {
      conn.connect({
        host: host.trim(),
        port,
        username: username.trim(),
        readyTimeout: CONNECT_TIMEOUT_MS,
        ...(authMethod === "password"
          ? { password: body.password }
          : { privateKey: body.privateKey, passphrase: body.passphrase || undefined }),
      })
    } catch (err) {
      finish({ error: err instanceof Error ? err.message : "Failed to start SSH connection" })
    }
  })

  if ("error" in results) {
    return NextResponse.json({ error: results.error }, { status: 502 })
  }

  // AI analysis of the real output.
  let analysis
  try {
    analysis = await analyzeAudit(platform, results)
  } catch (err) {
    return NextResponse.json(
      {
        error: `Analysis failed: ${err instanceof Error ? err.message : "unknown error"}`,
        results,
      },
      { status: 502 },
    )
  }

  return NextResponse.json({
    target: {
      host: host.trim(),
      transport: authMethod === "key" ? "SSH (key-based)" : "SSH (password)",
      user: username.trim(),
      port,
    },
    results,
    findings: analysis.findings,
    fixList: analysis.fixList,
  })
}

function runCommand(conn: Client, command: string): Promise<CommandResult> {
  return new Promise((resolve) => {
    let stdout = ""
    let stderr = ""
    let done = false

    const timer = setTimeout(() => {
      if (!done) {
        done = true
        resolve({ command, exitCode: null, stdout, stderr: stderr + "\n[timed out]" })
      }
    }, PER_COMMAND_TIMEOUT_MS)

    conn.exec(command, { pty: false }, (err, stream) => {
      if (err) {
        clearTimeout(timer)
        if (!done) {
          done = true
          resolve({ command, exitCode: null, stdout: "", stderr: err.message })
        }
        return
      }
      stream
        .on("close", (code: number) => {
          clearTimeout(timer)
          if (!done) {
            done = true
            resolve({ command, exitCode: code ?? null, stdout, stderr })
          }
        })
        .on("data", (d: Buffer) => {
          stdout += d.toString()
        })
      stream.stderr.on("data", (d: Buffer) => {
        stderr += d.toString()
      })
    })
  })
}
