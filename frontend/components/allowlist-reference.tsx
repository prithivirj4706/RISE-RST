"use client"

import { AnimatePresence, motion } from "motion/react"
import type { PlatformData } from "@/lib/audit-data"

export function AllowlistReference({ data }: { data: PlatformData }) {
  return (
    <section>
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="font-mono text-sm font-semibold uppercase tracking-widest text-muted-foreground">
          command allowlist
        </h2>
        <span className="font-mono text-xs text-muted-foreground">
          {data.meta.label} · v1 · {data.allowlist.length} entries · read-only
        </span>
      </div>
      <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
        Every command the collector may run lives in one explicit, versioned list per platform. Nothing is
        constructed dynamically — not by the rule engine, not by config, and never by the LLM.
      </p>
      <div className="mt-4 overflow-hidden rounded-lg border border-border bg-card">
        <ul className="divide-y divide-border">
          <AnimatePresence mode="popLayout">
            {data.allowlist.map((cmd, i) => (
              <motion.li
                key={`${data.meta.id}-${cmd}`}
                layout
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0 }}
                transition={{ delay: i * 0.025, duration: 0.2 }}
                className="flex items-center gap-3 px-4 py-2.5"
              >
                <span className="font-mono text-xs text-muted-foreground">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <code className="overflow-x-auto font-mono text-xs text-primary">$ {cmd}</code>
              </motion.li>
            ))}
          </AnimatePresence>
        </ul>
      </div>
    </section>
  )
}
