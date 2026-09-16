/**
 * Native danger-command guard for the DeepSeek Harness: monotonic deny policy
 * over catastrophic shell commands on the `bash`/`pwsh` tools, plus a JSONL
 * audit trail appended to the local hook-kit audit log. The rule set, matching
 * semantics, and deny text port `shell_guard.py` from the server hook-kit
 * (`scripts/hook-kit/shell_guard.py`) verbatim, so every harness platform
 * blocks the same disaster class. Deny feedback is model-visible (the deny
 * decision materializes as an error tool result) and audit writes are
 * fail-soft: an audit I/O failure never affects the guard decision or the
 * tool call it denies.
 *
 * GuardFall hardening parity (2026-08-15): the `bash` tool goes through the
 * hardened judge (`judgeCommandHardened`) — line-continuation normalization,
 * `$(...)`/backtick substitution recursion, `$IFS` obfuscation detection, and
 * a POSIX tokenize-then-recheck pass — mirroring `judge_shell_hardened`; the
 * `pwsh` tool uses the raw judge only (backslash paths would be mangled by
 * POSIX tokenization). The three escape hatches (`HOOK_KIT_GUARD_OFF`,
 * `HOOK_KIT_GUARD_ALLOW_RULES`, `HOOK_KIT_GUARD_DRY_RUN`) are honored and
 * audited as `guard_bypass` / `guard_rule_bypass` / `harness_deny_dryrun`.
 *
 * Two extension points cooperate:
 * - `tools/pre-execute` (waterfall) denies early with the Chinese reason;
 * - `ctx.tools.guard()` re-checks monotonically after the whole waterfall, so
 *   a listener that short-circuited the waterfall with an allow decision
 *   cannot resurrect a call this final invariant forbids.
 *
 * @module @deepseek-ai/dsh-danger-command-guard
 */

import { appendFileSync, mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'danger-command-guard'

/** The tool registry service this plugin guards (`tools/pre-execute`, `tools.guard()`). */
export const inject = ['tools']

/**
 * Plugin config, validated by the same-named schemastery schema plus the
 * load-time checks in `apply` (misconfiguration fails loud: a non-integer or
 * below-1 `commandPreviewChars`, or a blank `auditPath`, throws at plugin
 * load).
 */
export interface Config {
  /**
   * JSONL audit log path. Unset resolves to `$HOOK_KIT_AUDIT_LOG`, else
   * `~/.config/hook-kit/audit.jsonl` (the server hook-kit's own log).
   */
  auditPath?: string
  /** The `actor` value stamped on every audit entry (default `dsh`). */
  actor?: string
  /** Maximum command characters quoted in an audit entry (default 200). */
  commandPreviewChars?: number
}

export const Config: z<Config> = z.object({
  auditPath: z.string(),
  actor: z.string().default('dsh'),
  commandPreviewChars: z.number().default(200),
})

/** One matched rule: its stable id plus the model-facing Chinese deny text. */
export interface DenyVerdict {
  /**
   * Stable rule id stamped on the audit entry (`rm-root`, `prune-af`,
   * `push-force`, `push-plus`, `reset-hard`, `ps-remove`, `cmd-rd`,
   * `ifs-obfuscation`, or `subst-<rule>`).
   */
  rule: string
  /** Model-visible deny reason (Chinese, verbatim from `shell_guard.py`). */
  reason: string
}

/** One ordered shell rule: first matcher wins; a rule's veto regex exempts the command. */
interface ShellRule {
  rule: string
  matcher: RegExp
  veto?: RegExp
  reason: string
}

/**
 * Root/home-directory target, ported verbatim from `shell_guard.py`'s
 * `ROOT_TARGET`: `/`, `~`, `/c/` (MSYS), `$HOME`/`${HOME}`,
 * `$env:USERPROFILE|HOMEDRIVE|HOMEPATH`, or a bare `C:\` — each followed by a
 * terminator. The terminator prevents sub-path false positives
 * (`/tmp/...`, `C:\project`, `$HOME/project`).
 */
const ROOT_TARGET = /\s\/(?:\s|$|"|')|\s~(?:\s|$|"|')|\s\/c\/(?:\s|$|"|'|\*)|\s\$(?:HOME|HOMEPATH)\b(?:\s|$|"|'|\*|\/\*)|\s\$\{HOME\}(?:\s|$|"|'|\*|\/\*)|\s\$env:(?:USERPROFILE|HOMEDRIVE|HOMEPATH)\b(?:\s|$|"|'|\*|\/\*)|\sC:\\\s|\sC:\\$|\sC:\\"/

/**
 * The five inline shell rules, in `shell_guard.py`'s `SHELL_RULES` order.
 * Each matcher is the Python pattern transliterated to a JavaScript literal
 * with the same `i` (IGNORECASE) semantics; `[^\n]` keeps the match on one
 * command line. The `rm-root` matcher already folds the `--recursive`
 * long-flag variants and the `//` / `/c/` / `$HOME` / `${HOME}` targets in.
 */
const SHELL_RULES: readonly ShellRule[] = [
  {
    rule: 'rm-root',
    // oxlint-disable-next-line @stylistic/max-len -- the regex ports shell_guard.py's single-line Python pattern verbatim.
    matcher: /\brm\b[^\n]*(?:-rf?\b|-fr\b|--force\b[^\n]*-r\b|-r\b[^\n]*--force\b|--recursive\b[^\n]*--force\b|--force\b[^\n]*--recursive\b|--recursive\b[^\n]*-f\b|-f\b[^\n]*--recursive\b)[^\n]*(?:"\/"|'\/'|"\/\/"|'\/\/'|\s\/(?:\s|\/|\*|$|"|')|\s~\/?(?:\s|$|"|')|\s~(?:\s|$|"|'|\*)|\s\/c\/(?:\s|\/|\*|$|"|')|\s\$(?:HOME|HOMEPATH)\b(?:\s|$|"|'|\*|\/\*)|\s\$\{HOME\}(?:\s|$|"|'|\*|\/\*))/i,
    reason: '危险命令已拦截：rm -rf 删除根目录/家目录不可恢复（安全红线）。',
  },
  {
    rule: 'prune-af',
    // oxlint-disable-next-line @stylistic/max-len -- the regex ports shell_guard.py's single-line Python pattern verbatim.
    matcher: /\bdocker\b[^\n]*\b(?:system|container|image|volume)\s+prune\b[^\n]*(?:-af\b|--all\b[^\n]*--force\b|--force\b[^\n]*--all\b|-a\s+-f\b|-f\s+-a\b)/i,
    reason: '危险命令已拦截：docker prune -af 有事故前科（2026-05-28），仅允许 docker system prune -f。',
  },
  {
    rule: 'push-force',
    matcher: /\bgit\b[^\n]*\bpush\b[^\n]*(?:--force\b|\s-f\b)/i,
    veto: /--force-with-lease/i,
    reason: '危险操作已拦截：git push --force 属破坏性操作（--force-with-lease 放行）。',
  },
  {
    rule: 'push-plus',
    matcher: /\bgit\b[^\n]*\bpush\b[^\n]*[ \t]\+[A-Za-z0-9._/-]+/i,
    reason: '危险操作已拦截：git push +refspec 强制覆盖远端分支（等价 --force，如需请用 --force-with-lease）。',
  },
  {
    rule: 'reset-hard',
    matcher: /\bgit\b[^\n]*\breset\b[^\n]*--hard\b/i,
    reason: '危险操作已拦截：git reset --hard 属破坏性操作。',
  },
]

const PS_REMOVE_REASON = '危险命令已拦截：Remove-Item -Recurse -Force 删除根目录/家目录不可恢复。'
const CMD_RD_REASON = '危险命令已拦截：rd/rmdir /s /q 删除根目录/家目录不可恢复。'

const REMOVE_ITEM = /\bRemove-Item\b/i
// Deliberate `(?:^|\s)` instead of `\b`: `-` is a non-word character, so
// whitespace→`-` has no word boundary (ported from shell_guard.py's note).
const RECURSE_FLAG = /(?:^|\s)-Recurse\b/i
const FORCE_FLAG = /(?:^|\s)-Force\b/i
const RD_COMMAND = /\b(?:rd|rmdir)\b/i
const S_FLAG = /(?:^|\s)\/s\b/i
const Q_FLAG = /(?:^|\s)\/q\b/i

/**
 * PowerShell `Remove-Item` carrying both `-Recurse` and `-Force` (any flag
 * order) against a root/home target. Ported from `shell_guard.py`'s
 * `_powershell_remove_root`.
 * @param command - the full command line.
 * @returns whether the command is the ps-remove disaster class.
 */
function powershellRemoveRoot(command: string): boolean {
  return REMOVE_ITEM.test(command)
    && RECURSE_FLAG.test(command)
    && FORCE_FLAG.test(command)
    && ROOT_TARGET.test(command)
}

/**
 * `rd`/`rmdir` with `/s /q` against a root/home target. Ported from
 * `shell_guard.py`'s `_cmd_rd_root`.
 * @param command - the full command line.
 * @returns whether the command is the cmd-rd disaster class.
 */
function cmdRdRoot(command: string): boolean {
  return RD_COMMAND.test(command)
    && S_FLAG.test(command)
    && Q_FLAG.test(command)
    && ROOT_TARGET.test(command)
}

/**
 * Judge one shell command against the ported rule set: ordered inline rules
 * (with veto exemption), then the PowerShell and cmd equivalents. This is the
 * raw channel, equivalent to `shell_guard.py`'s `judge_shell`.
 * @param command - the full command line to judge.
 * @returns the denying verdict, or `undefined` to allow the command.
 */
export function judgeCommand(command: string): DenyVerdict | undefined {
  if (typeof command !== 'string' || command.length === 0) return undefined
  for (const { rule, matcher, veto, reason } of SHELL_RULES) {
    if (veto !== undefined && veto.test(command)) continue
    if (matcher.test(command)) return { rule, reason }
  }
  if (powershellRemoveRoot(command)) return { rule: 'ps-remove', reason: PS_REMOVE_REASON }
  if (cmdRdRoot(command)) return { rule: 'cmd-rd', reason: CMD_RD_REASON }
  return undefined
}

// ---- GuardFall hardening (ported verbatim from shell_guard.py) ----

/** Substitution recursion depth cap (mirrors `SUBSTITUTION_DEPTH_LIMIT`). */
const SUBSTITUTION_DEPTH_LIMIT = 4
/** Maximum `$(...)` / backtick body length scanned (mirrors `SUBSTITUTION_BODY_LIMIT`). */
const SUBSTITUTION_BODY_LIMIT = 4000

/** `$IFS` reference (bare or braced). */
const IFS_REFERENCE = /\$\{?IFS\}?/
/** Destructive binaries that make a `$IFS` reference suspicious (Class B). */
const IFS_OBFUSCATION_BINARIES = /\b(?:rm|docker|git)\b/i
const IFS_OBFUSCATION_REASON = '危险命令已拦截：$IFS 混淆展开（rm/docker/git 组合绕过检测）。'

/**
 * Collapse a bash line continuation (backslash + newline) and fold the
 * remaining `\r`/`\n` to spaces, mirroring `shell_guard.py`'s
 * `normalize_command` — prevents `rm -rf \<newline>/` cross-line bypass.
 * @param command - the raw command line.
 * @returns the single-line normalized command.
 */
function normalizeCommand(command: string): string {
  return command.replace(/\\\r?\n/g, ' ').replace(/\r/g, ' ').replace(/\n/g, ' ')
}

/**
 * Collect the inner text of every `$(...)` and `` `...` `` substitution, using
 * a balanced-parenthesis scan so `$((arithmetic))` does not mis-split.
 * Mirrors `shell_guard.py`'s `iter_substitutions`; returns early on an
 * unclosed construct.
 * @param command - the command to scan.
 * @param limit - the per-body length cap.
 * @returns the collected substitution bodies.
 */
function collectSubstitutions(command: string, limit: number): string[] {
  const results: string[] = []
  let index = 0
  const length = command.length
  while (index < length) {
    const char = command[index]
    if (char === '$' && command[index + 1] === '(') {
      let depth = 0
      let cursor = index + 1
      let closed = false
      while (cursor < length) {
        const c = command[cursor]
        if (c === '(') depth += 1
        else if (c === ')') {
          depth -= 1
          if (depth === 0) {
            const body = command.slice(index + 2, cursor)
            if (body.length > 0 && body.length <= limit) results.push(body)
            index = cursor
            closed = true
            break
          }
        }
        cursor += 1
      }
      if (!closed) return results
    } else if (char === '`') {
      const end = command.indexOf('`', index + 1)
      if (end === -1) return results
      const body = command.slice(index + 1, end)
      if (body.length > 0 && body.length <= limit) results.push(body)
      index = end
    }
    index += 1
  }
  return results
}

/**
 * A minimal POSIX shell tokenizer (single/double quotes + backslash escapes),
 * used only to "merge" quoted spans — `r''m -rf /` tokenizes to `rm -rf /`.
 * Returns `undefined` on an unclosed quote (caller then skips the recheck),
 * mirroring `shlex.split(posix=True)` failing on unbalanced input.
 * @param command - the command to tokenize.
 * @returns the tokens, or `undefined` on unbalanced quotes.
 */
function tokenizePosix(command: string): string[] | undefined {
  const tokens: string[] = []
  let current = ''
  let inToken = false
  let index = 0
  const length = command.length

  const flush = (): void => {
    if (inToken) {
      tokens.push(current)
      current = ''
      inToken = false
    }
  }

  while (index < length) {
    const char = command[index]
    if (char === ' ' || char === '\t' || char === '\n' || char === '\r') {
      flush()
      index += 1
      continue
    }
    if (char === "'") {
      const end = command.indexOf("'", index + 1)
      if (end === -1) return undefined
      current += command.slice(index + 1, end)
      inToken = true
      index = end + 1
      continue
    }
    if (char === '"') {
      let cursor = index + 1
      let closed = false
      while (cursor < length) {
        const c = command[cursor]
        if (c === '\\' && cursor + 1 < length) {
          current += command[cursor + 1]
          inToken = true
          cursor += 2
          continue
        }
        if (c === '"') {
          closed = true
          break
        }
        current += c
        inToken = true
        cursor += 1
      }
      if (!closed) return undefined
      index = cursor + 1
      continue
    }
    if (char === '\\' && index + 1 < length) {
      current += command[index + 1]
      inToken = true
      index += 2
      continue
    }
    current += char
    inToken = true
    index += 1
  }
  flush()
  return tokens
}

/**
 * POSIX-tokenize then rejoin: the Class A (quote-merge) variant. Returns
 * `undefined` when tokenization fails (unbalanced quotes), so the caller
 * falls back to the raw channel.
 * @param command - the command to canonicalize.
 * @returns the rejoined token stream, or `undefined`.
 */
function tokenizedVariant(command: string): string | undefined {
  const tokens = tokenizePosix(command)
  return tokens === undefined ? undefined : tokens.join(' ')
}

/**
 * Hardened judge for POSIX shells (`bash`), mirroring `shell_guard.py`'s
 * `judge_shell_hardened`: normalize → substitution recursion (Class C) →
 * `$IFS` check (Class B) → raw judge → tokenize-then-recheck (Class A).
 * @param command - the raw command line.
 * @param depth - substitution recursion depth.
 * @returns the denying verdict, or `undefined` to allow the command.
 */
export function judgeCommandHardened(command: string, depth = 0): DenyVerdict | undefined {
  if (typeof command !== 'string' || command.length === 0) return undefined
  const normalized = normalizeCommand(command)

  // GuardFall Class C: a benign outer command wrapping a destructive inner
  // substitution (`echo "$(rm -rf /)"`).
  if (depth < SUBSTITUTION_DEPTH_LIMIT) {
    for (const body of collectSubstitutions(normalized, SUBSTITUTION_BODY_LIMIT)) {
      const inner = judgeCommandHardened(body, depth + 1)
      if (inner !== undefined) return { rule: `subst-${inner.rule}`, reason: inner.reason }
    }
  }

  // GuardFall Class B: `$IFS` expansion combined with a destructive binary.
  if (IFS_REFERENCE.test(normalized) && IFS_OBFUSCATION_BINARIES.test(normalized)) {
    return { rule: 'ifs-obfuscation', reason: IFS_OBFUSCATION_REASON }
  }

  const raw = judgeCommand(normalized)
  if (raw !== undefined) return raw

  // GuardFall Class A: quote merging (`r''m -rf /`); recheck only when the
  // token stream differs from the normalized input.
  const tokenized = tokenizedVariant(normalized)
  if (tokenized !== undefined && tokenized !== normalized) {
    const retok = judgeCommand(tokenized)
    if (retok !== undefined) return retok
  }
  return undefined
}

/** The tool names this guard inspects (the shipped `bash`/`pwsh` tool names). */
const GUARDED_TOOLS = new Set(['bash', 'pwsh'])
/** Tool names that go through the hardened (POSIX) judge; `pwsh` stays raw. */
const POSIX_TOOLS = new Set(['bash'])

/** Read the `command` argument of a shell tool call, or `undefined` for a non-string. */
function extractCommand(argumentsValue: unknown): string | undefined {
  if (typeof argumentsValue !== 'object' || argumentsValue === null) return undefined
  const command = (argumentsValue as Record<string, unknown>).command
  return typeof command === 'string' ? command : undefined
}

/** Audit event names, matching `shell_guard.py`'s `audit.record` events. */
type GuardEvent = 'harness_deny' | 'guard_bypass' | 'guard_rule_bypass' | 'harness_deny_dryrun'

/** One audit log entry, in the server hook-kit `audit.py` format. */
interface AuditEntry {
  ts: string
  event: GuardEvent
  actor: string
  rule: string
  tool: string
  command: string
  cwd: string
  session_id?: string
}

/**
 * Local wall-clock timestamp in the hook-kit `audit.py` format
 * (`YYYY-MM-DDTHH:MM:SS`), matching Python's `time.strftime`.
 * @param date - the instant to format (defaults to now).
 * @returns the zero-padded local timestamp string.
 */
function localTimestamp(date: Date = new Date()): string {
  const pad = (value: number): string => String(value).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`
    + `T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

/** One JSONL line for an audit entry. */
function renderAuditLine(entry: AuditEntry): string {
  return `${JSON.stringify(entry)}\n`
}

/** Create the parent directory and append one audit line (plain synchronous I/O). */
function writeAuditLine(path: string, line: string): void {
  mkdirSync(dirname(path), { recursive: true })
  appendFileSync(path, line, 'utf8')
}

/**
 * Append one audit entry, swallowing every I/O error: audit is a side
 * channel, and its failure must never affect the guard decision or the tool
 * call it denies (fail-soft, the same contract as the server hook-kit's
 * `audit.py`). `writeAuditLine` performs only filesystem operations, so
 * `OSError` is the only failure class that can reach the catch.
 * @param path - the JSONL log path.
 * @param entry - the entry to append.
 */
function recordAudit(path: string, entry: AuditEntry): void {
  try {
    writeAuditLine(path, renderAuditLine(entry))
  } catch {
    // Swallows mkdir/append OSError: audit I/O must never fail the guard.
  }
}

/**
 * Resolve the audit log path: an explicit config value wins; otherwise the
 * `HOOK_KIT_AUDIT_LOG` override; otherwise the hook-kit default under the
 * user home. A blank configured value fails loud.
 * @param configured - the `auditPath` config value, if provided.
 * @returns the resolved absolute-ish log path.
 */
function resolveAuditPath(configured: string | undefined): string {
  if (configured !== undefined) {
    if (configured.trim() === '') {
      throw new Error('danger-command-guard: `auditPath` must not be blank')
    }
    return configured
  }
  const fromEnvironment = process.env.HOOK_KIT_AUDIT_LOG
  if (fromEnvironment !== undefined) return fromEnvironment
  return join(homedir(), '.config', 'hook-kit', 'audit.jsonl')
}

/**
 * Validate `commandPreviewChars` per the fail-loud contract.
 * @param value - the config value after schemastery defaults.
 * @returns the validated value.
 */
function validateCommandPreviewChars(value: number): number {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`danger-command-guard: invalid commandPreviewChars ${value} — must be an integer >= 1`)
  }
  return value
}

/** The three escape-hatch env vars, resolved per judgement (runtime toggleable). */
interface EscapeState {
  off: boolean
  allowRules: Set<string>
  dryRun: boolean
}

/** `1`/`true`/`yes` (case-insensitive) counts as enabled. */
function isTruthy(value: string | undefined): boolean {
  return value !== undefined && ['1', 'true', 'yes'].includes(value.trim().toLowerCase())
}

/** Read the escape-hatch env vars, mirroring `shell_guard.py`'s `_escape_state`. */
function escapeState(): EscapeState {
  return {
    off: isTruthy(process.env.HOOK_KIT_GUARD_OFF),
    allowRules: new Set(
      (process.env.HOOK_KIT_GUARD_ALLOW_RULES ?? '')
        .split(',').map(rule => rule.trim()).filter(rule => rule.length > 0),
    ),
    dryRun: isTruthy(process.env.HOOK_KIT_GUARD_DRY_RUN),
  }
}

/**
 * Resolve the audit event for a rule hit under the current escape state.
 * Mirrors `shell_guard.py`'s `judge()` escape dispatch (off → `guard_bypass`,
 * allow-list → `guard_rule_bypass`, dry-run → `harness_deny_dryrun`).
 */
function resolveGuardEvent(rule: string, state: EscapeState): GuardEvent {
  if (state.off) return 'guard_bypass'
  if (state.allowRules.has(rule)) return 'guard_rule_bypass'
  if (state.dryRun) return 'harness_deny_dryrun'
  return 'harness_deny'
}

/** Model-visible escape-hatch hint appended to every deny reason. */
function denyHint(rule: string): string {
  return ` 逃生口：HOOK_KIT_GUARD_ALLOW_RULES=${rule} 按规则放行，或 HOOK_KIT_GUARD_OFF=1 会话关闭；均写审计 ~/.config/hook-kit/audit.jsonl（DRY_RUN=1 只审计不拦）。`
}

/**
 * Install the guard's listeners: the early `tools/pre-execute` deny plus the
 * monotonic `tools.guard()` backstop. Both registrations are owned by this
 * plugin's context and unwind when its fiber disposes.
 * @param ctx - plugin context; listeners are scoped to it and disposed with it.
 * @param config - validated {@link Config}; path and preview length are re-checked fail-loud here.
 */
export function apply(ctx: Context, config: Config): void {
  const auditPath = resolveAuditPath(config.auditPath)
  const actor = config.actor as string
  const commandPreviewChars = validateCommandPreviewChars(config.commandPreviewChars as number)

  /**
   * Evaluate one execution: its command plus the denying verdict, if any.
   * `bash` goes through the hardened (POSIX) judge, `pwsh` through the raw one.
   */
  function judge(exec: Readonly<ToolExecution>): { command: string; verdict: DenyVerdict } | undefined {
    if (!GUARDED_TOOLS.has(exec.name)) return undefined
    const command = extractCommand(exec.arguments)
    if (command === undefined) return undefined
    const verdict = POSIX_TOOLS.has(exec.name) ? judgeCommandHardened(command) : judgeCommand(command)
    return verdict === undefined ? undefined : { command, verdict }
  }

  /** Audit a hit and return the deny reason (empty string when bypassed). */
  function audit(exec: ToolExecution, command: string, verdict: DenyVerdict, event: GuardEvent): string {
    recordAudit(auditPath, {
      ts: localTimestamp(),
      event,
      actor,
      rule: verdict.rule,
      tool: exec.name,
      command: command.slice(0, commandPreviewChars),
      cwd: process.cwd(),
      ...exec.agent !== undefined ? { session_id: exec.agent.id } : {},
    })
    return event === 'harness_deny' ? verdict.reason + denyHint(verdict.rule) : ''
  }

  // The extensible waterfall gate: deny early with the model-visible reason.
  // Escape hatches are resolved here too, but bypassed hits are only audited
  // by the monotonic backstop below (so a bypass is recorded exactly once).
  ctx.on('tools/pre-execute', async (exec, next): Promise<PreToolDecision> => {
    const judged = judge(exec)
    if (judged === undefined) return next()
    const event = resolveGuardEvent(judged.verdict.rule, escapeState())
    if (event !== 'harness_deny') return next()
    return { kind: 'deny', reason: audit(exec, judged.command, judged.verdict, event) }
  })

  // The monotonic final guard: runs after the whole pre-execute waterfall,
  // so an upstream listener that short-circuited with an allow decision
  // cannot resurrect a call this invariant forbids. This is also the single
  // audit point for escape-hatch bypasses.
  ctx.tools.guard((exec) => {
    const judged = judge(exec)
    if (judged === undefined) return undefined
    const event = resolveGuardEvent(judged.verdict.rule, escapeState())
    return audit(exec, judged.command, judged.verdict, event) || undefined
  })
}
