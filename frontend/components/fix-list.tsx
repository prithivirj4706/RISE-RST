"use client"

import { useState } from "react"
import { motion } from "motion/react"
import { Copy, Check, Link2 } from "lucide-react"
import type { FixItem } from "@/lib/audit-data"
import { SeverityBadge } from "@/components/status-badge"

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard?.writeText(text)
        setCopied(true)
        setTimeout(() => setCopied(false), 1600)
      }}
      className="inline-flex items-center gap-1.5 rounded-md border border-border bg-secondary px-2.5 py-1 font-mono text-xs text-foreground transition-colors hover:bg-accent"
      aria-label="Copy remediation command"
    >
      {copied ? <Check className="size-3.5 text-pass" /> : <Copy className="size-3.5" />}
      {copied ? "copied" : "copy"}
    </button>
  )
}

function FixCard({ item, index }: { item: FixItem; index: number }) {
  return (
    <motion.li
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.07 }}
      className="rounded-lg border border-border bg-card p-4"
    >
      <div className="flex items-start gap-3">
        <div className="flex size-8 shrink-0 items-center justify-center rounded-md border border-fail/40 bg-fail/10 font-mono text-sm font-bold text-fail">
          {item.priority}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={item.severity} />
            <span className="font-mono text-xs text-muted-foreground">{item.rule_id}</span>
            <span className="text-xs text-muted-foreground">· {item.category}</span>
          </div>
          <p className="mt-2 text-sm font-medium text-foreground text-pretty">{item.finding}</p>
          <p className="mt-1 text-sm leading-relaxed text-muted-foreground text-pretty">
            {item.why_it_matters}
          </p>

          <div className="mt-3 rounded-md border border-border bg-background">
            <div className="flex items-center justify-between border-b border-border px-3 py-1.5">
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                remediation command
              </span>
              <CopyButton text={item.fix_command} />
            </div>
            <pre className="overflow-x-auto px-3 py-2.5 font-mono text-xs leading-relaxed text-primary">
              {item.fix_command}
            </pre>
          </div>

          <div className="mt-2 flex items-center gap-1.5 text-xs text-muted-foreground">
            <Link2 className="size-3.5" />
            <span className="font-mono">
              evidence_ref → {item.evidence_ref}
            </span>
          </div>
        </div>
      </div>
    </motion.li>
  )
}

export function FixList({ items }: { items: FixItem[] }) {
  return (
    <ol className="space-y-3">
      {items.map((item, i) => (
        <FixCard key={item.rule_id} item={item} index={i} />
      ))}
    </ol>
  )
}
