"use client"

import { useEffect, useRef } from "react"
import { cn } from "@/lib/utils"

export type LogLine = { text: string; tone?: "muted" | "cmd" | "pass" | "fail" | "unknown" | "info" }

const toneClass: Record<NonNullable<LogLine["tone"]>, string> = {
  muted: "text-muted-foreground",
  cmd: "text-primary",
  pass: "text-pass",
  fail: "text-fail",
  unknown: "text-unknown",
  info: "text-foreground",
}

export function TerminalLog({ lines, running }: { lines: LogLine[]; running: boolean }) {
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" })
  }, [lines])

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background">
      <div className="flex items-center gap-2 border-b border-border bg-secondary/60 px-4 py-2.5">
        <span className="size-3 rounded-full bg-fail/70" aria-hidden />
        <span className="size-3 rounded-full bg-unknown/70" aria-hidden />
        <span className="size-3 rounded-full bg-pass/70" aria-hidden />
        <span className="ml-2 font-mono text-xs text-muted-foreground">audit-agent — session log</span>
      </div>
      <div className="h-64 overflow-y-auto p-4 font-mono text-xs leading-relaxed">
        {lines.length === 0 && (
          <p className="text-muted-foreground">
            {"// idle — run the agent to open a read-only session"}
          </p>
        )}
        {lines.map((line, i) => (
          <p key={i} className={cn("whitespace-pre-wrap", toneClass[line.tone ?? "info"])}>
            {line.text}
          </p>
        ))}
        {running && <span className="cursor-blink text-primary">▊</span>}
        <div ref={endRef} />
      </div>
    </div>
  )
}
