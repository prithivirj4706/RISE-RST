"use client"

import { motion } from "motion/react"
import { Plug, Terminal, ShieldCheck, ListOrdered, Check, Loader2 } from "lucide-react"
import { cn } from "@/lib/utils"

export type StageState = "idle" | "active" | "done"

const stages = [
  {
    key: "connector",
    label: "connector",
    desc: "read-only session",
    plain: "Signs in to the server — safely, look-only.",
    icon: Plug,
  },
  {
    key: "collector",
    label: "collector",
    desc: "allowlist commands",
    plain: "Runs a fixed list of safe check commands.",
    icon: Terminal,
  },
  {
    key: "rule-engine",
    label: "rule engine",
    desc: "~10 CIS checks",
    plain: "Compares results to security best-practices.",
    icon: ShieldCheck,
  },
  {
    key: "prioritizer",
    label: "prioritizer",
    desc: "ranked fix list",
    plain: "Ranks the problems and writes the fixes.",
    icon: ListOrdered,
  },
] as const

export function PipelineStages({ states }: { states: Record<string, StageState> }) {
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {stages.map((stage, i) => {
        const state = states[stage.key] ?? "idle"
        const Icon = stage.icon
        return (
          <motion.div
            key={stage.key}
            initial={{ opacity: 0, y: 8 }}
            animate={{
              opacity: 1,
              y: 0,
              boxShadow:
                state === "active"
                  ? "0 0 0 1px var(--primary), 0 8px 30px -12px var(--primary)"
                  : "0 0 0 0 rgba(0,0,0,0)",
            }}
            transition={{ delay: i * 0.06 }}
            className={cn(
              "relative flex flex-col overflow-hidden rounded-lg border bg-card p-4 transition-colors",
              state === "active" && "border-primary/60",
              state === "done" && "border-pass/40",
              state === "idle" && "border-border",
            )}
          >
            {/* animated data-flow strip while active */}
            {state === "active" && (
              <motion.div
                className="absolute inset-x-0 top-0 h-0.5"
                style={{
                  background:
                    "linear-gradient(90deg, transparent, var(--primary), transparent)",
                  backgroundSize: "50% 100%",
                }}
                initial={{ backgroundPositionX: "-100%" }}
                animate={{ backgroundPositionX: "200%" }}
                transition={{ duration: 1.1, repeat: Number.POSITIVE_INFINITY, ease: "linear" }}
                aria-hidden
              />
            )}
            <div className="flex items-center justify-between">
              <motion.div
                animate={state === "active" ? { scale: [1, 1.06, 1] } : { scale: 1 }}
                transition={{ duration: 1.2, repeat: state === "active" ? Number.POSITIVE_INFINITY : 0 }}
                className={cn(
                  "flex size-9 items-center justify-center rounded-md border",
                  state === "done"
                    ? "border-pass/40 bg-pass/10 text-pass"
                    : state === "active"
                      ? "border-primary/40 bg-primary/10 text-primary"
                      : "border-border bg-muted text-muted-foreground",
                )}
              >
                <Icon className="size-4" />
              </motion.div>
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                {String(i + 1).padStart(2, "0")}
              </span>
            </div>
            <div className="mt-3 flex items-center gap-1.5">
              <p className="font-mono text-sm font-semibold text-foreground">{stage.label}</p>
              {state === "active" && <Loader2 className="size-3.5 animate-spin text-primary" />}
              {state === "done" && (
                <motion.span initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", stiffness: 400, damping: 15 }}>
                  <Check className="size-3.5 text-pass" />
                </motion.span>
              )}
            </div>
            <p className="mt-0.5 text-xs text-muted-foreground">{stage.desc}</p>
            {/* plain-language helper so newcomers understand each step */}
            <p className="mt-2 border-t border-border/60 pt-2 text-xs leading-relaxed text-muted-foreground/80 text-pretty">
              {stage.plain}
            </p>
          </motion.div>
        )
      })}
    </div>
  )
}
