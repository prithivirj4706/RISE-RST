"use client"

import { useCallback, useMemo, useRef, useState } from "react"
import { motion, AnimatePresence } from "motion/react"
import { Play, RotateCcw, Server, ShieldAlert, FileJson, TriangleAlert } from "lucide-react"
import { PLATFORMS, DEFAULT_PLATFORM, type Platform, type PlatformData, type Finding, type FixItem } from "@/lib/audit-data"
import { PlatformSelector } from "@/components/platform-selector"
import { PipelineStages, type StageState } from "@/components/pipeline-stages"
import { TerminalLog, type LogLine } from "@/components/terminal-log"
import { SeveritySummary } from "@/components/severity-summary"
import { FindingsList } from "@/components/findings-list"
import { FixList } from "@/components/fix-list"
import { AiNarrator, type NarrationTone } from "@/components/ai-narrator"
import { ReportDownload } from "@/components/report-download"
import { AllowlistReference } from "@/components/allowlist-reference"
import { ConnectionForm, defaultConfig, type ConnectionConfig } from "@/components/connection-form"

type Phase = "ready" | "running" | "done" | "error"

type AuditResult = {
  target: { host: string; transport: string; user: string; port: number }
  results: { command: string; exitCode: number | null; stdout: string; stderr: string }[]
  findings: Finding[]
  fixList: FixItem[]
}

const initialStages: Record<string, StageState> = {
  connector: "idle",
  collector: "idle",
  "rule-engine": "idle",
  prioritizer: "idle",
}

function readyMessage(label: string) {
  return `Hi! I check ${label} machines for security problems. Enter the host and credentials, pick the read-only checks, and press Run — I connect over SSH, read settings only, and never change anything. A human decides what to fix.`
}

export function AuditConsole() {
  const [platform, setPlatform] = useState<Platform>(DEFAULT_PLATFORM)
  const base = useMemo(() => PLATFORMS[platform], [platform])

  const [config, setConfig] = useState<ConnectionConfig>(() => defaultConfig(PLATFORMS[DEFAULT_PLATFORM]))
  const [phase, setPhase] = useState<Phase>("ready")
  const [stages, setStages] = useState<Record<string, StageState>>(initialStages)
  const [log, setLog] = useState<LogLine[]>([])
  const [progress, setProgress] = useState(0)
  const [narration, setNarration] = useState(readyMessage(PLATFORMS[DEFAULT_PLATFORM].meta.label))
  const [narrationTone, setNarrationTone] = useState<NarrationTone>("idle")
  const [thinking, setThinking] = useState(false)
  const [result, setResult] = useState<AuditResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const timers = useRef<ReturnType<typeof setTimeout>[]>([])

  const clearTimers = useCallback(() => {
    timers.current.forEach(clearTimeout)
    timers.current = []
  }, [])

  const resetState = useCallback(
    (p: Platform) => {
      clearTimers()
      setPhase("ready")
      setStages(initialStages)
      setLog([])
      setProgress(0)
      setResult(null)
      setError(null)
      setNarration(readyMessage(PLATFORMS[p].meta.label))
      setNarrationTone("idle")
      setThinking(false)
    },
    [clearTimers],
  )

  const reset = useCallback(() => resetState(platform), [resetState, platform])

  const selectPlatform = useCallback(
    (p: Platform) => {
      if (p === platform) return
      setPlatform(p)
      setConfig(defaultConfig(PLATFORMS[p]))
      resetState(p)
    },
    [platform, resetState],
  )

  const push = useCallback((line: LogLine) => setLog((l) => [...l, line]), [])
  const setStage = useCallback(
    (key: string, s: StageState) => setStages((prev) => ({ ...prev, [key]: s })),
    [],
  )
  const say = useCallback((msg: string, tone: NarrationTone, isThinking = false) => {
    setNarration(msg)
    setNarrationTone(tone)
    setThinking(isThinking)
  }, [])

  const commandsToRun = useMemo(
    () => [...config.selected, ...config.custom.map((c) => c.trim()).filter(Boolean)],
    [config.selected, config.custom],
  )

  const validate = useCallback((): string | null => {
    if (!config.host.trim()) return "Enter a host or IP address."
    if (!config.username.trim()) return "Enter a username."
    if (config.authMethod === "password" && !config.password) return "Enter a password."
    if (config.authMethod === "key" && !config.privateKey.trim()) return "Paste a private key."
    if (commandsToRun.length === 0) return "Select at least one check to run."
    return null
  }, [config, commandsToRun])

  const run = useCallback(async () => {
    const invalid = validate()
    if (invalid) {
      setPhase("error")
      setError(invalid)
      say(`I can't start yet: ${invalid}`, "warn")
      return
    }

    clearTimers()
    setPhase("running")
    setStages({ ...initialStages, connector: "active" })
    setLog([])
    setError(null)
    setResult(null)
    setProgress(12)
    setThinking(false)
    say(
      `Opening a read-only SSH session to ${config.host} as ${config.username}. I can see settings, but I can't touch them.`,
      "working",
    )
    push({ text: `→ connecting to ${config.host}:${config.port || "22"} via SSH`, tone: "muted" })

    let data: AuditResult
    try {
      const res = await fetch("/api/audit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          platform,
          host: config.host,
          port: Number(config.port) || 22,
          username: config.username,
          authMethod: config.authMethod,
          password: config.password,
          privateKey: config.privateKey,
          passphrase: config.passphrase,
          commands: commandsToRun,
        }),
      })
      const json = await res.json()
      if (!res.ok) {
        throw new Error(json?.error || `Request failed (${res.status})`)
      }
      data = json as AuditResult
    } catch (err) {
      const message = err instanceof Error ? err.message : "The audit could not be completed."
      setPhase("error")
      setStages((prev) => ({ ...prev, connector: "idle" }))
      setProgress(0)
      setError(message)
      push({ text: `✗ ${message}`, tone: "fail" })
      say(`I couldn't finish the audit. ${message}`, "warn")
      return
    }

    // Real result in hand — replay it through the pipeline visuals.
    setResult(data)
    push({ text: `  session open · user=${data.target.user} · ${data.target.transport}`, tone: "info" })
    push({ text: "✓ read-only session established (no PTY, no mutating flags)", tone: "pass" })
    setStage("connector", "done")
    setStage("collector", "active")
    setProgress(40)
    say(
      `Connected. I ran ${data.results.length} read-only check command${
        data.results.length === 1 ? "" : "s"
      } and captured exactly what each printed.`,
      "working",
    )

    let t = 250
    const schedule = (fn: () => void, delay: number) => timers.current.push(setTimeout(fn, delay))

    data.results.forEach((r) => {
      schedule(() => {
        push({ text: `$ ${r.command}`, tone: "cmd" })
        const firstLine = (r.stdout || r.stderr || "").split("\n").find((l) => l.trim()) ?? ""
        if (firstLine) {
          push({ text: `  ${firstLine.slice(0, 88)}`, tone: "muted" })
        }
        push({
          text: `  [exit ${r.exitCode ?? "n/a"}]`,
          tone: r.exitCode === 0 ? "pass" : r.stderr ? "fail" : "muted",
        })
      }, (t += 160))
    })

    schedule(() => {
      push({ text: `✓ captured stdout/stderr/exit for ${data.results.length} commands`, tone: "pass" })
      setStage("collector", "done")
      setStage("rule-engine", "active")
      setProgress(65)
      say(
        "The AI analyst compared each result against CIS best practices. Green means good, red means it needs fixing, yellow means the output was inconclusive.",
        "working",
      )
    }, (t += 300))

    data.findings.forEach((f) => {
      schedule(
        () =>
          push({
            text: `[${f.status.padEnd(7)}] ${f.rule_id}  ${f.title}`,
            tone: f.status === "PASS" ? "pass" : f.status === "FAIL" ? "fail" : "unknown",
          }),
        (t += 120),
      )
    })

    schedule(() => {
      const fails = data.findings.filter((f) => f.status === "FAIL").length
      push({ text: `✓ analysis complete — ${fails} FAIL, evidence attached`, tone: "info" })
      setStage("rule-engine", "done")
      setStage("prioritizer", "active")
      setProgress(85)
      say("Thinking… sorting the problems worst-first and writing the exact fix command for each. I only rank and explain — I never change a verdict.", "warn", true)
    }, (t += 300))

    schedule(() => {
      const fails = data.findings.filter((f) => f.status === "FAIL").length
      push({ text: `✓ fix list ready — ${data.fixList.length} prioritized, grounded items`, tone: "pass" })
      setStage("prioritizer", "done")
      setProgress(100)
      setThinking(false)
      setPhase("done")
      say(
        fails === 0
          ? `Done! Every check passed on ${data.target.host}. Nothing needs fixing right now.`
          : `Done! I found ${fails} issue${fails === 1 ? "" : "s"} on ${data.target.host}. The most urgent is at the top of the plan below, and every fix traces back to real evidence. A human just reviews and runs them.`,
        "success",
      )
    }, (t += 400))
  }, [validate, clearTimers, config, platform, commandsToRun, push, setStage, say])

  // Synthesize a PlatformData-shaped object from the live result for the display components.
  const resultData: PlatformData | null = useMemo(() => {
    if (!result) return null
    return {
      ...base,
      target: {
        host: result.target.host,
        transport: result.target.transport,
        os: "reported by host",
        kernel: `port ${result.target.port}`,
        user: result.target.user,
      },
      findings: result.findings,
      fixList: result.fixList,
    }
  }, [result, base])

  const running = phase === "running"

  return (
    <div className="space-y-6">
      {/* Platform picker */}
      <div className="rounded-xl border border-border bg-card p-4 sm:p-5">
        <PlatformSelector value={platform} onChange={selectPlatform} disabled={running} />
      </div>

      {/* Connection + checks form */}
      <div className="rounded-xl border border-border bg-card p-4 sm:p-5">
        <ConnectionForm data={base} value={config} onChange={setConfig} disabled={running} />
      </div>

      {/* Control bar */}
      <div className="rounded-xl border border-border bg-card p-4 sm:p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-start gap-3">
            <div className="flex size-10 shrink-0 items-center justify-center rounded-md border border-border bg-secondary text-primary">
              <Server className="size-5" />
            </div>
            <div>
              <p className="font-mono text-sm font-semibold text-foreground">
                {config.host.trim() || "no host set"}
              </p>
              <p className="text-xs text-muted-foreground">
                {base.meta.benchmark}
              </p>
              <p className="mt-0.5 font-mono text-xs text-muted-foreground">
                {config.authMethod === "key" ? "SSH · key-based" : "SSH · password"} ·{" "}
                {config.username.trim() || "no user"} · {commandsToRun.length} checks
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {(phase === "done" || phase === "error") && (
              <button
                type="button"
                onClick={reset}
                className="inline-flex items-center gap-2 rounded-md border border-border bg-secondary px-3.5 py-2 text-sm font-medium text-foreground transition-colors hover:bg-accent"
              >
                <RotateCcw className="size-4" />
                Reset
              </button>
            )}
            <button
              type="button"
              onClick={run}
              disabled={running}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Play className="size-4" />
              {running ? "Auditing…" : phase === "done" ? "Run again" : "Run audit"}
            </button>
          </div>
        </div>

        {/* overall progress bar */}
        <AnimatePresence>
          {phase !== "ready" && phase !== "error" && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 overflow-hidden"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
                  {phase === "done" ? "audit complete" : "auditing…"}
                </span>
                <span className="font-mono text-xs tabular-nums text-muted-foreground">{progress}%</span>
              </div>
              <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-secondary">
                <motion.div
                  className="h-full rounded-full bg-primary"
                  animate={{ width: `${progress}%` }}
                  transition={{ duration: 0.5, ease: "easeOut" }}
                />
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* error banner */}
        <AnimatePresence>
          {phase === "error" && error && (
            <motion.div
              initial={{ opacity: 0, y: -6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="mt-4 flex items-start gap-2.5 rounded-md border border-fail/40 bg-fail/10 px-3.5 py-3"
            >
              <TriangleAlert className="mt-0.5 size-4 shrink-0 text-fail" />
              <div className="min-w-0">
                <p className="text-sm font-medium text-foreground">Audit could not run</p>
                <p className="mt-0.5 break-words font-mono text-xs text-muted-foreground">{error}</p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* AI narrator */}
      <AiNarrator message={narration} tone={narrationTone} thinking={thinking} />

      {/* Pipeline + terminal */}
      <div className="grid gap-4 lg:grid-cols-5">
        <div className="lg:col-span-3">
          <PipelineStages states={stages} />
        </div>
        <div className="lg:col-span-2">
          <TerminalLog lines={log} running={running} />
        </div>
      </div>

      {/* Results */}
      <AnimatePresence mode="wait">
        {phase === "done" && resultData && (
          <motion.div
            key={result?.target.host}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
            className="space-y-6"
          >
            <SeveritySummary findings={resultData.findings} />

            <ReportDownload data={resultData} />

            <div className="grid gap-6 lg:grid-cols-2">
              <section className="space-y-3">
                <div className="flex items-center gap-2">
                  <FileJson className="size-4 text-muted-foreground" />
                  <h2 className="font-mono text-sm font-semibold uppercase tracking-widest text-muted-foreground">
                    ai analyst · findings
                  </h2>
                </div>
                <FindingsList findings={resultData.findings} />
              </section>

              <section className="space-y-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="size-4 text-fail" />
                  <h2 className="font-mono text-sm font-semibold uppercase tracking-widest text-muted-foreground">
                    prioritizer · remediation plan
                  </h2>
                </div>
                <FixList items={resultData.fixList} />
              </section>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Allowlist reference — updates with the selected platform */}
      <AllowlistReference data={base} />
    </div>
  )
}
