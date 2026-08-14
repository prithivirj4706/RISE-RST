import "server-only"
import { generateObject } from "ai"
import { z } from "zod"
import type { Finding, FixItem, Platform } from "@/lib/audit-data"

const MODEL = "openai/gpt-5.5"

export type CommandResult = {
  command: string
  exitCode: number | null
  stdout: string
  stderr: string
}

const findingSchema = z.object({
  rule_id: z.string().describe("Stable identifier, prefer a CIS reference like CIS-5.2.10 when applicable"),
  title: z.string(),
  category: z.string(),
  command: z.string().describe("The exact command from the provided output that this finding is based on"),
  status: z.enum(["PASS", "FAIL", "UNKNOWN"]),
  evidence: z.string().describe("A short verbatim excerpt of the real command output that justifies the verdict"),
  severity_hint: z.enum(["critical", "high", "medium", "low"]),
})

const fixItemSchema = z.object({
  priority: z.number().int().describe("1 = most urgent; unique and contiguous starting at 1"),
  rule_id: z.string().describe("Must match a rule_id from findings with status FAIL"),
  category: z.string(),
  finding: z.string(),
  why_it_matters: z.string(),
  fix_command: z.string().describe("A concrete command a human can run to remediate"),
  evidence_ref: z.string().describe("The evidence excerpt from the corresponding finding"),
  severity: z.enum(["critical", "high", "medium", "low"]),
})

const analysisSchema = z.object({
  findings: z.array(findingSchema),
  fixList: z.array(fixItemSchema),
})

const SYSTEM = `You are a CIS-Benchmark security auditor. You are given the RAW output of read-only shell commands captured from a live host. Your job is to:
1. Produce one finding per meaningful check, grounded ONLY in the provided output. Never invent evidence. If output is empty/ambiguous/errored, mark status UNKNOWN.
2. Assign PASS/FAIL/UNKNOWN strictly from the evidence.
3. Build a remediation plan (fixList) covering ONLY the FAIL findings, ordered worst-first (critical > high > medium > low), each with a concrete fix command.
Rules: temperature is 0. Do not soften or invent verdicts. Every finding.evidence must be a verbatim excerpt of the given output. Every fixList item must reference an existing FAIL finding's rule_id.`

export async function analyzeAudit(
  platform: Platform,
  results: CommandResult[],
): Promise<{ findings: Finding[]; fixList: FixItem[] }> {
  const transcript = results
    .map(
      (r) =>
        `$ ${r.command}\n[exit ${r.exitCode ?? "n/a"}]\n${(r.stdout || "").trim() || "(no stdout)"}${
          r.stderr?.trim() ? `\n[stderr] ${r.stderr.trim()}` : ""
        }`,
    )
    .join("\n\n---\n\n")

  const { object } = await generateObject({
    model: MODEL,
    schema: analysisSchema,
    temperature: 0,
    system: SYSTEM,
    prompt: `Platform: ${platform}\n\nCaptured command output:\n\n${transcript}`,
  })

  // Defensive normalization: contiguous priorities, FAIL-only fix list.
  const failIds = new Set(object.findings.filter((f) => f.status === "FAIL").map((f) => f.rule_id))
  const fixList = object.fixList
    .filter((f) => failIds.has(f.rule_id))
    .sort((a, b) => a.priority - b.priority)
    .map((f, i) => ({ ...f, priority: i + 1 }))

  return { findings: object.findings, fixList }
}
