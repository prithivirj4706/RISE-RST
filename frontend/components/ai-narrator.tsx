"use client"

import { useEffect, useRef, useState } from "react"
import { motion, AnimatePresence } from "motion/react"
import { Sparkles } from "lucide-react"

/** Typewriter that reveals `text` character-by-character. */
function useTypewriter(text: string, speed = 18) {
  const [out, setOut] = useState("")
  useEffect(() => {
    setOut("")
    if (!text) return
    let i = 0
    const id = setInterval(() => {
      i++
      setOut(text.slice(0, i))
      if (i >= text.length) clearInterval(id)
    }, speed)
    return () => clearInterval(id)
  }, [text, speed])
  return out
}

export type NarrationTone = "idle" | "working" | "warn" | "success"

const toneRing: Record<NarrationTone, string> = {
  idle: "border-border",
  working: "border-primary/60",
  warn: "border-unknown/60",
  success: "border-pass/60",
}

export function AiNarrator({
  message,
  tone = "idle",
  thinking = false,
}: {
  message: string
  tone?: NarrationTone
  thinking?: boolean
}) {
  const typed = useTypewriter(message)
  const done = typed.length >= message.length
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight })
  }, [typed])

  return (
    <div
      className={`relative overflow-hidden rounded-xl border bg-card p-4 transition-colors sm:p-5 ${toneRing[tone]}`}
    >
      <div className="flex items-start gap-3">
        {/* Animated agent avatar */}
        <div className="relative shrink-0">
          <motion.div
            className="flex size-10 items-center justify-center rounded-full border border-primary/40 bg-primary/10 text-primary"
            animate={
              thinking
                ? { scale: [1, 1.08, 1], boxShadow: ["0 0 0 0 rgba(0,0,0,0)", "0 0 0 6px rgba(0,0,0,0)"] }
                : { scale: 1 }
            }
            transition={{ duration: 1.4, repeat: thinking ? Number.POSITIVE_INFINITY : 0, ease: "easeInOut" }}
          >
            <Sparkles className="size-5" />
          </motion.div>
          {thinking && (
            <motion.span
              className="absolute inset-0 rounded-full border border-primary/50"
              initial={{ opacity: 0.6, scale: 1 }}
              animate={{ opacity: 0, scale: 1.8 }}
              transition={{ duration: 1.4, repeat: Number.POSITIVE_INFINITY, ease: "easeOut" }}
              aria-hidden
            />
          )}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <p className="text-sm font-semibold text-foreground">Audit Agent</p>
            <span className="rounded-full border border-border bg-secondary px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              {thinking ? "thinking…" : done ? "explaining" : "typing…"}
            </span>
          </div>

          <div ref={scrollRef} className="mt-1.5 max-h-24 overflow-y-auto">
            <AnimatePresence mode="wait">
              <motion.p
                key={message}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="text-sm leading-relaxed text-muted-foreground text-pretty"
              >
                {typed}
                {!done && <span className="cursor-blink text-primary">▊</span>}
              </motion.p>
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  )
}
