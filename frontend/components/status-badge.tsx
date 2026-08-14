import type { Status, Severity } from "@/lib/audit-data"
import { cn } from "@/lib/utils"

const statusStyles: Record<Status, string> = {
  PASS: "border-pass/40 bg-pass/10 text-pass",
  FAIL: "border-fail/40 bg-fail/10 text-fail",
  UNKNOWN: "border-unknown/40 bg-unknown/10 text-unknown",
}

export function StatusBadge({ status }: { status: Status }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-xs font-semibold tracking-wide",
        statusStyles[status],
      )}
    >
      <span className="size-1.5 rounded-full bg-current" aria-hidden />
      {status}
    </span>
  )
}

const severityStyles: Record<Severity, string> = {
  critical: "border-fail/50 bg-fail/15 text-fail",
  high: "border-unknown/50 bg-unknown/15 text-unknown",
  medium: "border-primary/40 bg-primary/10 text-primary",
  low: "border-border bg-muted text-muted-foreground",
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-widest",
        severityStyles[severity],
      )}
    >
      {severity}
    </span>
  )
}
