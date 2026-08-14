"use client"

import { useState } from "react"
import { motion, AnimatePresence } from "motion/react"
import { ChevronRight } from "lucide-react"
import type { Finding } from "@/lib/audit-data"
import { StatusBadge } from "@/components/status-badge"
import { cn } from "@/lib/utils"

function FindingRow({ finding, index }: { finding: Finding; index: number }) {
  const [open, setOpen] = useState(false)

  return (
    <motion.li
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.04 }}
      className="border-b border-border last:border-b-0"
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-accent/40"
        aria-expanded={open}
      >
        <ChevronRight
          className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")}
        />
        <span className="font-mono text-xs text-muted-foreground w-24 shrink-0">{finding.rule_id}</span>
        <span className="flex-1 truncate text-sm text-foreground">{finding.title}</span>
        <span className="hidden text-xs text-muted-foreground sm:inline">{finding.category}</span>
        <StatusBadge status={finding.status} />
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="space-y-2 bg-secondary/40 px-4 pb-4 pl-11 pt-1">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  command run (from allowlist)
                </p>
                <pre className="mt-1 overflow-x-auto rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-primary">
                  $ {finding.command}
                </pre>
              </div>
              <div>
                <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  captured evidence
                </p>
                <pre className="mt-1 overflow-x-auto rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-foreground">
                  {finding.evidence}
                </pre>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.li>
  )
}

export function FindingsList({ findings }: { findings: Finding[] }) {
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border bg-secondary/50 px-4 py-2.5">
        <h3 className="font-mono text-sm font-semibold text-foreground">findings[]</h3>
        <span className="font-mono text-xs text-muted-foreground">
          {findings.length} rules · click a row for evidence
        </span>
      </div>
      <ul>
        {findings.map((f, i) => (
          <FindingRow key={f.rule_id} finding={f} index={i} />
        ))}
      </ul>
    </div>
  )
}
