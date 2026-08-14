"use client"

import { KeyRound, Lock, Plus, Terminal, X } from "lucide-react"
import type { PlatformData } from "@/lib/audit-data"

export type AuthMethod = "key" | "password"

export type ConnectionConfig = {
  host: string
  port: string
  username: string
  authMethod: AuthMethod
  password: string
  privateKey: string
  passphrase: string
  /** Allowlist entries the user has enabled. */
  selected: string[]
  /** Extra read-only commands typed by the user. */
  custom: string[]
}

export function defaultConfig(data: PlatformData): ConnectionConfig {
  return {
    host: "",
    port: "22",
    username: "",
    authMethod: "key",
    password: "",
    privateKey: "",
    passphrase: "",
    selected: [...data.allowlist],
    custom: [],
  }
}

const inputClass =
  "w-full rounded-md border border-border bg-secondary px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted-foreground/60 outline-none transition-colors focus:border-primary"

export function ConnectionForm({
  data,
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

  const toggleCmd = (cmd: string) => {
    const has = value.selected.includes(cmd)
    set("selected", has ? value.selected.filter((c) => c !== cmd) : [...value.selected, cmd])
  }

  const updateCustom = (i: number, v: string) => {
    const next = [...value.custom]
    next[i] = v
    set("custom", next)
  }

  return (
    <div className="space-y-6">
      {/* Connection */}
      <fieldset disabled={disabled} className="space-y-4 disabled:opacity-60">
        <legend className="mb-3 flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-widest text-muted-foreground">
          <Terminal className="size-3.5 text-primary" />
          connection
        </legend>

        <div className="grid gap-4 sm:grid-cols-3">
          <label className="sm:col-span-2">
            <span className="mb-1.5 block text-xs font-medium text-muted-foreground">Host / IP</span>
            <input
              className={inputClass}
              placeholder="10.0.0.12 or host.example.com"
              value={value.host}
              onChange={(e) => set("host", e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <label>
            <span className="mb-1.5 block text-xs font-medium text-muted-foreground">Port</span>
            <input
              className={inputClass}
              placeholder="22"
              inputMode="numeric"
              value={value.port}
              onChange={(e) => set("port", e.target.value.replace(/[^0-9]/g, ""))}
            />
          </label>
        </div>

        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-muted-foreground">Username</span>
          <input
            className={inputClass}
            placeholder="auditor"
            value={value.username}
            onChange={(e) => set("username", e.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
        </label>

        {/* Auth method toggle */}
        <div>
          <span className="mb-1.5 block text-xs font-medium text-muted-foreground">Authentication</span>
          <div className="inline-flex rounded-md border border-border bg-secondary p-1">
            <AuthTab
              active={value.authMethod === "key"}
              onClick={() => set("authMethod", "key")}
              icon={KeyRound}
              label="Private key"
            />
            <AuthTab
              active={value.authMethod === "password"}
              onClick={() => set("authMethod", "password")}
              icon={Lock}
              label="Password"
            />
          </div>
        </div>

        {value.authMethod === "key" ? (
          <div className="grid gap-4">
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-muted-foreground">
                Private key (PEM / OpenSSH)
              </span>
              <textarea
                className={`${inputClass} h-28 resize-y leading-relaxed`}
                placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
                value={value.privateKey}
                onChange={(e) => set("privateKey", e.target.value)}
                spellCheck={false}
              />
            </label>
            <label className="block sm:max-w-xs">
              <span className="mb-1.5 block text-xs font-medium text-muted-foreground">
                Passphrase <span className="text-muted-foreground/60">(optional)</span>
              </span>
              <input
                type="password"
                className={inputClass}
                placeholder="••••••••"
                value={value.passphrase}
                onChange={(e) => set("passphrase", e.target.value)}
                autoComplete="off"
              />
            </label>
          </div>
        ) : (
          <label className="block sm:max-w-xs">
            <span className="mb-1.5 block text-xs font-medium text-muted-foreground">Password</span>
            <input
              type="password"
              className={inputClass}
              placeholder="••••••••"
              value={value.password}
              onChange={(e) => set("password", e.target.value)}
              autoComplete="off"
            />
          </label>
        )}
      </fieldset>

      {/* Commands */}
      <fieldset disabled={disabled} className="space-y-3 disabled:opacity-60">
        <legend className="mb-1 flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-widest text-muted-foreground">
          <Terminal className="size-3.5 text-primary" />
          checks to run
          <span className="text-muted-foreground/60">
            ({value.selected.length + value.custom.filter((c) => c.trim()).length} selected)
          </span>
        </legend>

        <ul className="grid gap-1.5 sm:grid-cols-2">
          {data.allowlist.map((cmd) => {
            const checked = value.selected.includes(cmd)
            return (
              <li key={cmd}>
                <label
                  className={`flex cursor-pointer items-center gap-2.5 rounded-md border px-3 py-2 transition-colors ${
                    checked ? "border-primary/50 bg-primary/5" : "border-border bg-secondary hover:border-border/80"
                  }`}
                >
                  <input
                    type="checkbox"
                    className="size-3.5 shrink-0 accent-primary"
                    checked={checked}
                    onChange={() => toggleCmd(cmd)}
                  />
                  <code className="truncate font-mono text-xs text-foreground" title={cmd}>
                    {cmd}
                  </code>
                </label>
              </li>
            )
          })}
        </ul>

        {/* Custom read-only commands */}
        <div className="rounded-md border border-dashed border-border p-3">
          <p className="mb-2 text-xs font-medium text-muted-foreground">
            Custom read-only commands{" "}
            <span className="text-muted-foreground/60">— rejected server-side if they mutate state</span>
          </p>
          <div className="space-y-2">
            {value.custom.map((c, i) => (
              <div key={i} className="flex items-center gap-2">
                <span className="font-mono text-xs text-muted-foreground">$</span>
                <input
                  className={inputClass}
                  placeholder="e.g. cat /etc/os-release"
                  value={c}
                  onChange={(e) => updateCustom(i, e.target.value)}
                  spellCheck={false}
                />
                <button
                  type="button"
                  onClick={() => set("custom", value.custom.filter((_, j) => j !== i))}
                  className="shrink-0 rounded-md border border-border bg-secondary p-2 text-muted-foreground transition-colors hover:text-foreground"
                  aria-label="Remove command"
                >
                  <X className="size-3.5" />
                </button>
              </div>
            ))}
            <button
              type="button"
              onClick={() => set("custom", [...value.custom, ""])}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-secondary px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:bg-accent"
            >
              <Plus className="size-3.5" />
              Add command
            </button>
          </div>
        </div>
      </fieldset>
    </div>
  )
}

function AuthTab({
  active,
  onClick,
  icon: Icon,
  label,
}: {
  active: boolean
  onClick: () => void
  icon: React.ComponentType<{ className?: string }>
  label: string
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded px-3 py-1.5 text-sm font-medium transition-colors ${
        active ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"
      }`}
    >
      <Icon className="size-3.5" />
      {label}
    </button>
  )
}
