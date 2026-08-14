"use client"

import { useState } from "react"
import { motion } from "motion/react"
import { FileJson, FileText, Download, Check, Copy } from "lucide-react"
import { buildReportJson, buildReportMarkdown, downloadText } from "@/lib/report"
import type { PlatformData } from "@/lib/audit-data"

type Flash = "json" | "md" | "copy" | null

export function ReportDownload({ data }: { data: PlatformData }) {
  const [flash, setFlash] = useState<Flash>(null)

  const ping = (which: Flash) => {
    setFlash(which)
    setTimeout(() => setFlash((f) => (f === which ? null : f)), 1600)
  }

  const stamp = () => new Date().toISOString()
  const fileStamp = () => stamp().slice(0, 19).replace(/[:T]/g, "-")
  const base = () => `cis-audit-${data.meta.id}-${fileStamp()}`

  const onJson = () => {
    const now = stamp()
    downloadText(`${base()}.json`, buildReportJson(data, now), "application/json")
    ping("json")
  }

  const onMd = () => {
    const now = stamp()
    downloadText(`${base()}.md`, buildReportMarkdown(data, now), "text/markdown")
    ping("md")
  }

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(buildReportJson(data, stamp()))
      ping("copy")
    } catch {
      // clipboard blocked — no-op
    }
  }

  return (
    <motion.section
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: 0.1 }}
      className="rounded-xl border border-border bg-card p-4 sm:p-5"
    >
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div className="flex items-start gap-3">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-md border border-border bg-secondary text-primary">
            <Download className="size-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-foreground">Download the report</h2>
            <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
              Take the results with you. <span className="text-foreground">JSON</span> is for pipelines and tooling;{" "}
              <span className="text-foreground">Markdown</span> is a readable report to share with your team.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={onJson}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-3.5 py-2 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90"
          >
            {flash === "json" ? <Check className="size-4" /> : <FileJson className="size-4" />}
            {flash === "json" ? "Saved" : "report.json"}
          </button>
          <button
            type="button"
            onClick={onMd}
            className="inline-flex items-center gap-2 rounded-md border border-border bg-secondary px-3.5 py-2 text-sm font-medium text-foreground transition-colors hover:bg-accent"
          >
            {flash === "md" ? <Check className="size-4 text-primary" /> : <FileText className="size-4" />}
            {flash === "md" ? "Saved" : "report.md"}
          </button>
          <button
            type="button"
            onClick={onCopy}
            aria-label="Copy JSON report to clipboard"
            className="inline-flex items-center gap-2 rounded-md border border-border bg-secondary px-3.5 py-2 text-sm font-medium text-foreground transition-colors hover:bg-accent"
          >
            {flash === "copy" ? <Check className="size-4 text-primary" /> : <Copy className="size-4" />}
            {flash === "copy" ? "Copied" : "Copy JSON"}
          </button>
        </div>
      </div>
    </motion.section>
  )
}
