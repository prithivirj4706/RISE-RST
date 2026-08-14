/**
 * Server-side, read-only command guard.
 *
 * The audit agent must NEVER run a mutating command. This module is the single
 * source of truth for that guarantee. It runs on the server only, before any
 * command is dispatched over SSH. The UI allowlist is a convenience; this is the
 * enforcement.
 */

/** Binaries/keywords that can modify state — rejected outright. */
const DENIED_TOKENS = [
  // file / fs mutation
  "rm",
  "rmdir",
  "mv",
  "cp",
  "dd",
  "mkfs",
  "mkdir",
  "touch",
  "truncate",
  "tee",
  "chmod",
  "chown",
  "chgrp",
  "chattr",
  "ln",
  "install",
  "shred",
  // editors / writers
  "vi",
  "vim",
  "nano",
  "emacs",
  "sed", // sed -i can write; block entirely to stay safe
  // package / service state
  "apt",
  "apt-get",
  "dpkg",
  "yum",
  "dnf",
  "rpm",
  "snap",
  "brew",
  "pip",
  "npm",
  "gem",
  "systemctl", // start/stop/enable mutate; is-enabled/status handled via allowlist only
  "service",
  "launchctl",
  "reboot",
  "shutdown",
  "halt",
  "poweroff",
  "init",
  "kill",
  "killall",
  "pkill",
  // users / auth
  "useradd",
  "userdel",
  "usermod",
  "groupadd",
  "groupdel",
  "passwd",
  "chpasswd",
  "visudo",
  // firewall / network state
  "iptables",
  "nft",
  "ip",
  "route",
  "mount",
  "umount",
  "modprobe",
  "insmod",
  "rmmod",
  "sysctl",
  "crontab",
  // windows mutators
  "Set-",
  "New-",
  "Remove-",
  "Disable-",
  "Enable-",
  "Restart-",
  "Stop-",
  "Start-",
  "Clear-",
  "reg",
  "regedit",
  "diskpart",
]

/** Shell operators that could redirect, chain a write, or escalate. */
const DENIED_OPERATORS = [
  ">", // redirect / overwrite
  ">>",
  "|", // piping is allowed inside vetted allowlist entries only, not custom input
  "&", // backgrounding / &&
  ";", // command chaining
  "`", // command substitution
  "$(", // command substitution
  "\n",
  "\r",
]

/** systemctl / launchctl sub-commands that are read-only and therefore allowed. */
const READONLY_SUBCOMMANDS: Record<string, string[]> = {
  systemctl: ["is-enabled", "is-active", "status", "list-units", "list-unit-files", "show"],
  launchctl: ["list", "print"],
}

export type SafetyResult = { safe: true } | { safe: false; reason: string }

/**
 * Validate a single command string. `trusted` entries come from the fixed
 * platform allowlist and are allowed to use pipes / vetted mutator-named
 * sub-commands (e.g. `systemctl is-enabled`). Custom user commands are held to
 * the stricter rule set.
 */
export function checkCommand(raw: string, trusted = false): SafetyResult {
  const command = raw.trim()

  if (!command) return { safe: false, reason: "Empty command" }
  if (command.length > 400) return { safe: false, reason: "Command too long" }

  // Operator checks (skip pipe restriction for trusted allowlist entries).
  for (const op of DENIED_OPERATORS) {
    if (op === "|" && trusted) continue
    if (command.includes(op)) {
      return { safe: false, reason: `Disallowed shell operator: ${op.trim() || "newline"}` }
    }
  }

  // sudo is allowed only as a read prefix; the underlying binary is still checked.
  const withoutSudo = command.replace(/^sudo\s+/, "")
  const tokens = withoutSudo.split(/\s+/)
  const head = tokens[0] ?? ""

  // Allow vetted read-only sub-commands of otherwise-mutating tools.
  const sub = tokens[1]
  if (READONLY_SUBCOMMANDS[head]) {
    if (sub && READONLY_SUBCOMMANDS[head].includes(sub)) return { safe: true }
    return { safe: false, reason: `${head} sub-command "${sub ?? ""}" is not read-only` }
  }

  for (const bad of DENIED_TOKENS) {
    // Windows verbs use a prefix match (e.g. "Set-"); unix binaries match the head token.
    if (bad.endsWith("-")) {
      if (command.includes(bad)) return { safe: false, reason: `Mutating command not allowed: ${bad}` }
    } else if (head === bad) {
      return { safe: false, reason: `Mutating command not allowed: ${bad}` }
    }
  }

  return { safe: true }
}

/** Validate a batch. Returns the first failure, if any. */
export function checkCommands(
  commands: { cmd: string; trusted: boolean }[],
): { ok: true } | { ok: false; cmd: string; reason: string } {
  for (const { cmd, trusted } of commands) {
    const res = checkCommand(cmd, trusted)
    if (!res.safe) return { ok: false, cmd, reason: res.reason }
  }
  return { ok: true }
}
