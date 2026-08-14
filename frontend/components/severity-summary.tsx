"use client"

import { useEffect, useState } from "react"
import { motion } from "motion/react"
import type { Finding } from "@/lib/audit-data"

/** Counts from 0 up to `target` for a lightweight "AI tallying" feel. */
function useCountUp(target: number, duration = 700, delay = 0) {
  const [n, setN] = useState(0)
  useEffect(() => {
    let raf = 0
    let start = 0
    const startTimer = setTimeout(() => {
      const tick = (t: number) => {
        if (!start) start = t
        const p = Math.min((t - start) / duration, 1)
        // easeOutCubic
        const eased = 1 - Math.pow(1 - p, 3)
        setN(Math.round(eased * target))
        if (p < 1) raf = requestAnimationFrame(tick)
      }
      raf = requestAnimationFrame(tick)
    }, delay)
    return () => {
      clearTimeout(startTimer)
      cancelAnimationFrame(raf)
    }
  }, [target, duration, delay])
  return n
}

function StatCard({
  label,
  value,
  className,
  accent,
  delay,
}: {
  label: string
  value: number
  className: string
  accent: string
  delay: number
}) {
  const n = useCountUp(value, 700, delay * 1000)
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="relative overflow-hidden rounded-lg border border-border bg-card p-4"
    >
      <span className={`absolute inset-y-0 left-0 w-1 ${accent}`} aria-hidden />
      <p className={`font-mono text-3xl font-bold tabular-nums ${className}`}>{n}</p>
      <p className="mt-1 text-xs uppercase tracking-widest text-muted-foreground">{label}</p>
    </motion.div>
  )
}

export function SeveritySummary({ findings }: { findings: Finding[] }) {
  const pass = findings.filter((f) => f.status === "PASS").length
  const unknown = findings.filter((f) => f.status === "UNKNOWN").length

  const failedBySeverity = findings.filter((f) => f.status === "FAIL")
  const critical = failedBySeverity.filter((f) => f.severity_hint === "critical").length
  const high = failedBySeverity.filter((f) => f.severity_hint === "high").length
  const medium = failedBySeverity.filter((f) => f.severity_hint === "medium").length

  const cards = [
    { label: "Critical", value: critical, className: "text-fail", accent: "bg-fail" },
    { label: "High", value: high, className: "text-unknown", accent: "bg-unknown" },
    { label: "Medium", value: medium, className: "text-primary", accent: "bg-primary" },
    { label: "Passed", value: pass, className: "text-pass", accent: "bg-pass" },
    { label: "Unknown", value: unknown, className: "text-muted-foreground", accent: "bg-muted-foreground" },
  ]

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      {cards.map((c, i) => (
        <StatCard
          key={c.label}
          label={c.label}
          value={c.value}
          className={c.className}
          accent={c.accent}
          delay={i * 0.08}
        />
      ))}
    </div>
  )
}
