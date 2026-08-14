"use client"

import { motion } from "motion/react"
import { Star } from "lucide-react"
import { cn } from "@/lib/utils"
import { PLATFORM_ORDER, PLATFORMS, type Platform } from "@/lib/audit-data"

/** Simple, dependency-free brand glyphs so newcomers instantly recognise each OS. */
function PlatformGlyph({ platform, className }: { platform: Platform; className?: string }) {
  if (platform === "linux") {
    // Tux-ish penguin silhouette
    return (
      <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden>
        <path d="M12 2c-2.2 0-3.6 1.8-3.6 4.2 0 1.3.1 2.2-.6 3.2-.8 1.1-2.4 2.6-3.2 4.5-.5 1.2-.2 2 .5 2.1.3.7.1 1.5.5 2.1.5.8 1.7.9 3 .9.7.6 1.9 1 3.4 1s2.7-.4 3.4-1c1.3 0 2.5-.1 3-.9.4-.6.2-1.4.5-2.1.7-.1 1-.9.5-2.1-.8-1.9-2.4-3.4-3.2-4.5-.7-1-.6-1.9-.6-3.2C15.6 3.8 14.2 2 12 2Zm-1.6 4.1c.4 0 .7.4.7.9s-.3.9-.7.9-.7-.4-.7-.9.3-.9.7-.9Zm3.2 0c.4 0 .7.4.7.9s-.3.9-.7.9-.7-.4-.7-.9.3-.9.7-.9Zm-1.6 2.3c.7 0 1.6.4 1.6.9 0 .3-.9.8-1.6.8s-1.6-.5-1.6-.8c0-.5.9-.9 1.6-.9Z" />
      </svg>
    )
  }
  if (platform === "macos") {
    // Apple-ish mark
    return (
      <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden>
        <path d="M16.4 12.6c0-2 1.6-3 1.7-3-.9-1.4-2.4-1.5-2.9-1.6-1.2-.1-2.4.7-3 .7-.6 0-1.6-.7-2.6-.7-1.3 0-2.6.8-3.3 2-1.4 2.4-.4 6 1 8 .7 1 1.4 2 2.5 2 1 0 1.3-.6 2.5-.6 1.2 0 1.5.6 2.5.6 1 0 1.7-.9 2.4-1.9.5-.7.7-1.1 1.1-1.9-2.9-1-3.4-4.1-1.4-5.1ZM14.3 6.2c.5-.7.9-1.6.8-2.6-.8 0-1.8.6-2.4 1.3-.5.6-1 1.5-.8 2.5.9.1 1.8-.5 2.4-1.2Z" />
      </svg>
    )
  }
  // Windows four-pane
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden>
      <path d="M3 5.4 10.5 4.3v7.2H3V5.4Zm0 13.2v-6.1h7.5v7.2L3 18.6ZM11.5 4.1 21 3v8.5h-9.5V4.1Zm0 8.4H21V21l-9.5-1.3v-7.2Z" />
    </svg>
  )
}

export function PlatformSelector({
  value,
  onChange,
  disabled,
}: {
  value: Platform
  onChange: (p: Platform) => void
  disabled?: boolean
}) {
  return (
    <div>
      <div className="mb-2 flex items-center gap-2">
        <p className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
          target platform
        </p>
        <span className="rounded-full border border-primary/40 bg-primary/10 px-2 py-0.5 font-mono text-[10px] text-primary">
          Linux prioritized
        </span>
      </div>
      <div
        role="radiogroup"
        aria-label="Target platform"
        className="grid grid-cols-1 gap-3 sm:grid-cols-3"
      >
        {PLATFORM_ORDER.map((id, i) => {
          const p = PLATFORMS[id]
          const active = value === id
          return (
            <motion.button
              key={id}
              type="button"
              role="radio"
              aria-checked={active}
              disabled={disabled}
              onClick={() => onChange(id)}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              whileHover={disabled ? undefined : { y: -2 }}
              whileTap={disabled ? undefined : { scale: 0.98 }}
              className={cn(
                "relative flex items-center gap-3 rounded-lg border p-3 text-left transition-colors",
                active ? "border-primary bg-primary/10" : "border-border bg-card hover:bg-accent",
                disabled && "cursor-not-allowed opacity-60",
              )}
            >
              <span
                className={cn(
                  "flex size-9 shrink-0 items-center justify-center rounded-md border",
                  active
                    ? "border-primary/40 bg-primary/10 text-primary"
                    : "border-border bg-secondary text-muted-foreground",
                )}
              >
                <PlatformGlyph platform={id} className="size-5" />
              </span>
              <span className="min-w-0">
                <span className="flex items-center gap-1.5">
                  <span className="font-mono text-sm font-semibold text-foreground">{p.meta.label}</span>
                  {p.meta.recommended && (
                    <span className="inline-flex items-center gap-0.5 rounded-full bg-primary/15 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider text-primary">
                      <Star className="size-2.5 fill-current" />
                      priority
                    </span>
                  )}
                </span>
                <span className="mt-0.5 block truncate text-xs text-muted-foreground">{p.meta.short}</span>
              </span>
              {active && (
                <motion.span
                  layoutId="platform-active-dot"
                  className="absolute right-3 top-3 size-2 rounded-full bg-primary"
                />
              )}
            </motion.button>
          )
        })}
      </div>
    </div>
  )
}
