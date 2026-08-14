import { Lock, ScanLine, GitCommitVertical, Terminal } from "lucide-react"
import { AuditConsole } from "@/components/audit-console"
import { PLATFORMS, DEFAULT_PLATFORM } from "@/lib/audit-data"

export default function Page() {
  const commandAllowlist = PLATFORMS[DEFAULT_PLATFORM].allowlist

  return (
    <main className="relative min-h-screen">
      {/* console grid backdrop */}
      <div className="pointer-events-none absolute inset-0 console-grid" aria-hidden />

      <div className="relative mx-auto max-w-6xl px-4 py-10 sm:px-6 sm:py-14">
        {/* Header */}
        <header className="mb-12">
          <div className="inline-flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 font-mono text-xs text-muted-foreground">
            <Terminal className="size-3.5 text-primary" />
            commands → rules → evidence → fix list
          </div>
          <h1 className="mt-5 max-w-3xl text-balance text-3xl font-bold leading-tight tracking-tight text-foreground sm:text-5xl">
            CIS Audit Agent
          </h1>
          <p className="mt-4 max-w-2xl text-pretty text-base leading-relaxed text-muted-foreground sm:text-lg">
            Open a strictly read-only session to a host, run a fixed allowlist of CIS-Benchmark-style
            checks, and get a prioritized, copy-paste-ready remediation plan. Verdicts come from
            deterministic parsers, never from a model — every fix traces back to one rule, one
            command, and that command&rsquo;s real captured output.
          </p>

          <dl className="mt-8 grid grid-cols-1 gap-3 sm:grid-cols-3">
            <SafetyCard
              icon={Lock}
              title="Read-only, always"
              body="The agent observes; a deterministic rule engine decides; a human executes the fix. Zero mutating commands run — a mutating command cannot even be defined."
            />
            <SafetyCard
              icon={ScanLine}
              title="Grounded findings"
              body="Every fix-list item carries its rule_id, exact command, captured evidence, and verdict — no generic advice."
            />
            <SafetyCard
              icon={GitCommitVertical}
              title="No drift"
              body="Two runs on an unchanged host give identical verdicts and ordering. Only the timestamp differs."
            />
          </dl>
        </header>

        {/* Console */}
        <AuditConsole />

        {/* Allowlist reference */}
        <section className="mt-12">
          <div className="flex items-center gap-2">
            <h2 className="font-mono text-sm font-semibold uppercase tracking-widest text-muted-foreground">
              command allowlist
            </h2>
            <span className="font-mono text-xs text-muted-foreground">
              v1 · {commandAllowlist.length} entries · read-only
            </span>
          </div>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
            Every command the collector may run lives in one explicit, versioned list. Nothing is
            constructed dynamically — not by the rule engine, not by config, and never by the LLM.
          </p>
          <div className="mt-4 overflow-hidden rounded-lg border border-border bg-card">
            <ul className="divide-y divide-border">
              {commandAllowlist.map((cmd, i) => (
                <li key={cmd} className="flex items-center gap-3 px-4 py-2.5">
                  <span className="font-mono text-xs text-muted-foreground">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <code className="overflow-x-auto font-mono text-xs text-primary">$ {cmd}</code>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <footer className="mt-12 border-t border-border pt-6">
          <p className="font-mono text-xs text-muted-foreground">
            {"// live SSH session · read-only allowlist enforced server-side · AI ranks & explains, never changes verdicts"}
          </p>
        </footer>
      </div>
    </main>
  )
}

function SafetyCard({
  icon: Icon,
  title,
  body,
}: {
  icon: React.ComponentType<{ className?: string }>
  title: string
  body: string
}) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="flex size-8 items-center justify-center rounded-md border border-border bg-secondary text-primary">
        <Icon className="size-4" />
      </div>
      <p className="mt-3 text-sm font-semibold text-foreground">{title}</p>
      <p className="mt-1 text-sm leading-relaxed text-muted-foreground text-pretty">{body}</p>
    </div>
  )
}
