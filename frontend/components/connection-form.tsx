"use client"

import { Container, HardDrive, KeyRound, Server, ShieldCheck, Terminal } from "lucide-react"
import type { PlatformData } from "@/lib/audit-data"

/**
 * Target configuration.
 *
 * Two capabilities were deliberately removed from this form, because the API
 * route no longer accepts either and would reject them:
 *
 *   - **Password authentication.** The engine's SSH connector sets
 *     `PasswordAuthentication=no` and `BatchMode=yes`, so it cannot prompt for
 *     or hold a password. Only a key *path* is sent; key material never enters
 *     the browser or the request body.
 *   - **Custom command entry.** Commands come from the engine's fixed,
 *     import-time-validated allowlist. Letting a user type a command to run on
 *     a remote host is a remote-code-execution hole, not a feature. The
 *     allowlist is shown read-only so an operator can audit exactly what will
 *     run — see the "command allowlist" panel.
 */

export type Transport = "local" | "ssh" | "docker"

export type ConnectionConfig = {
  transport: Transport
  host: string
  port: string
  username: string
  /** Path to a private key on the server. Never key material. */
  keyPath: string
  container: string
  insecureHostKey: boolean
}

export function defaultConfig(_data: PlatformData): ConnectionConfig {
  return {
    transport: "local",
    host: "",
    port: "22",
    username: "",
    keyPath: "",
    container: "",
    insecureHostKey: false,
  }
}

const inputClass =
  "w-full rounded-md border border-border bg-secondary px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted-foreground/60 outline-none transition-colors duration-200 focus:border-primary focus-visible:ring-2 focus-visible:ring-ring/40"

const TRANSPORTS: { id: Transport; label: string; hint: string; Icon: typeof Server }[] = [
  { id: "local", label: "Local", hint: "audit this machine", Icon: HardDrive },
  { id: "ssh", label: "SSH", hint: "remote host, key auth", Icon: Server },
  { id: "docker", label: "Docker", hint: "local container", Icon: Container },
]

function Field({
  label,
  hint,
  children,
}: {
  label: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <label className="block space-y-1.5">
      <span className="flex items-baseline justify-between gap-3">
        <span className="font-mono text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          {label}
        </span>
        {hint ? <span className="text-[11px] text-muted-foreground/70">{hint}</span> : null}
      </span>
      {children}
    </label>
  )
}

export function ConnectionForm({
  value,
  onChange,
  disabled,
}: {
  data: PlatformData
  value: ConnectionConfig
  onChange: (next: ConnectionConfig) => void
  disabled?: boolean
}) {
  const set = <K extends keyof ConnectionConfig>(key: K, v: ConnectionConfig[K]) =>
    onChange({ ...value, [key]: v })

  return (
    <div className="space-y-6">
      <fieldset disabled={disabled} className="space-y-4 disabled:opacity-60">
        <legend className="mb-3 flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-widest text-muted-foreground">
          <Terminal className="size-3.5 text-primary" />
          target
        </legend>

        {/* transport */}
        <div className="grid grid-cols-3 gap-2">
          {TRANSPORTS.map(({ id, label, hint, Icon }) => {
            const active = value.transport === id
            return (
              <button
                key={id}
                type="button"
                onClick={() => set("transport", id)}
                aria-pressed={active}
                className={[
                  "group flex cursor-pointer flex-col items-start gap-1 rounded-md border px-3 py-2.5 text-left transition-all duration-200",
                  active
                    ? "border-primary bg-primary/10 text-foreground"
                    : "border-border bg-secondary text-muted-foreground hover:border-muted-foreground/40 hover:text-foreground",
                ].join(" ")}
              >
                <span className="flex items-center gap-1.5 font-mono text-xs font-semibold">
                  <Icon className={active ? "size-3.5 text-primary" : "size-3.5"} />
                  {label}
                </span>
                <span className="text-[11px] leading-tight text-muted-foreground/80">{hint}</span>
              </button>
            )
          })}
        </div>

        {value.transport === "ssh" ? (
          <div className="space-y-4">
            <div className="grid grid-cols-[1fr_88px] gap-3">
              <Field label="host">
                <input
                  className={inputClass}
                  value={value.host}
                  onChange={(e) => set("host", e.target.value)}
                  placeholder="10.0.0.5"
                  autoComplete="off"
                  spellCheck={false}
                />
              </Field>
              <Field label="port">
                <input
                  className={inputClass}
                  value={value.port}
                  onChange={(e) => set("port", e.target.value)}
                  placeholder="22"
                  inputMode="numeric"
                />
              </Field>
            </div>
            <Field label="username">
              <input
                className={inputClass}
                value={value.username}
                onChange={(e) => set("username", e.target.value)}
                placeholder="audit"
                autoComplete="off"
                spellCheck={false}
              />
            </Field>
            <Field label="private key path" hint="path only — never the key">
              <input
                className={inputClass}
                value={value.keyPath}
                onChange={(e) => set("keyPath", e.target.value)}
                placeholder="~/.ssh/audit_ed25519"
                autoComplete="off"
                spellCheck={false}
              />
            </Field>

            <div className="flex items-start gap-2.5 rounded-md border border-primary/25 bg-primary/[0.06] px-3 py-2.5">
              <KeyRound className="mt-0.5 size-3.5 shrink-0 text-primary" />
              <p className="text-[12px] leading-relaxed text-muted-foreground">
                Key-based authentication only. The connector runs with{" "}
                <code className="font-mono text-foreground">PasswordAuthentication=no</code> and{" "}
                <code className="font-mono text-foreground">BatchMode=yes</code>, so it can neither
                prompt for nor hold a password.
              </p>
            </div>

            <label className="flex cursor-pointer items-start gap-2.5 rounded-md border border-border bg-secondary/60 px-3 py-2.5 transition-colors duration-200 hover:border-muted-foreground/40">
              <input
                type="checkbox"
                checked={value.insecureHostKey}
                onChange={(e) => set("insecureHostKey", e.target.checked)}
                className="mt-0.5 size-3.5 cursor-pointer accent-destructive"
              />
              <span className="text-[12px] leading-relaxed text-muted-foreground">
                <span className="font-medium text-foreground">
                  Disable SSH host-key verification
                </span>{" "}
                — throwaway targets only. The session will not be authenticated against a known
                host key. This is recorded loudly in the report.
              </span>
            </label>
          </div>
        ) : null}

        {value.transport === "docker" ? (
          <Field label="container" hint="docker exec — no shell on the target">
            <input
              className={inputClass}
              value={value.container}
              onChange={(e) => set("container", e.target.value)}
              placeholder="sa-vuln"
              autoComplete="off"
              spellCheck={false}
            />
          </Field>
        ) : null}

        {value.transport === "local" ? (
          <div className="flex items-start gap-2.5 rounded-md border border-border bg-secondary/60 px-3 py-2.5">
            <HardDrive className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />
            <p className="text-[12px] leading-relaxed text-muted-foreground">
              Audits the machine this app is running on. No credentials required.
            </p>
          </div>
        ) : null}
      </fieldset>

      {/* Why there is no command picker any more. */}
      <div className="flex items-start gap-2.5 rounded-md border border-border bg-secondary/40 px-3 py-2.5">
        <ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-primary" />
        <p className="text-[12px] leading-relaxed text-muted-foreground">
          <span className="font-medium text-foreground">Commands are not configurable.</span> Every
          command comes from the engine&rsquo;s fixed allowlist, validated read-only at import time
          — a mutating command cannot even be defined. The client cannot influence what runs on the
          target.
        </p>
      </div>
    </div>
  )
}
