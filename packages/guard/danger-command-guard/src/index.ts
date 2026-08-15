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
  /** Stable rule id stamped on the audit entry (`rm-root`, `prune-af`, `push-force`, `reset-hard`, `ps-remove`, `cmd-rd`). */
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
 * `ROOT_TARGET`: `/`, `~` (with optional trailing slash) followed by a
 * terminator, or a bare `C:\` at end / before whitespace or a quote. The
 * terminator prevents sub-path false positives (`/tmp/...`, `C:\project`).
 */
const ROOT_TARGET = /\s\/(?:\s|$|"|')|\s~(?:\s|$|"|')|\sC:\\\s|\sC:\\$|\sC:\\"/

/**
 * The four inline shell rules, in `shell_guard.py`'s `SHELL_RULES` order.
 * Each matcher is the Python pattern transliterated to a JavaScript literal
 * with the same `i` (IGNORECASE) semantics; `[^\n]` keeps the match on one
 * command line.
 */
const SHELL_RULES: readonly ShellRule[] = [
  {
    rule: 'rm-root',
    // oxlint-disable-next-line @stylistic/max-len -- the regex ports shell_guard.py's single-line Python pattern verbatim.
    matcher: /\brm\b[^\n]*(?:-rf?\b|-fr\b|--force\b[^\n]*-r\b|-r\b[^\n]*--force\b)[^\n]*(?:"\/"|'\/'|\s\/(?:\s|\/|\*|$|"|')|\s~\/?(?:\s|$|"|')|\s~(?:\s|$|"|'|\*))/i,
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
 * (with veto exemption), then the PowerShell and cmd equivalents.
 * @param command - the full command line to judge.
 * @returns the denying verdict, or `undefined` to allow the command.
 */
export function judgeCommand(command: string): DenyVerdict | undefined {
  for (const { rule, matcher, veto, reason } of SHELL_RULES) {
    if (veto !== undefined && veto.test(command)) continue
    if (matcher.test(command)) return { rule, reason }
  }
  if (powershellRemoveRoot(command)) return { rule: 'ps-remove', reason: PS_REMOVE_REASON }
  if (cmdRdRoot(command)) return { rule: 'cmd-rd', reason: CMD_RD_REASON }
  return undefined
}

/** The tool names this guard inspects (the shipped `bash`/`pwsh` tool names). */
const GUARDED_TOOLS = new Set(['bash', 'pwsh'])

/** Read the `command` argument of a shell tool call, or `undefined` for a non-string. */
function extractCommand(argumentsValue: unknown): string | undefined {
  if (typeof argumentsValue !== 'object' || argumentsValue === null) return undefined
  const command = (argumentsValue as Record<string, unknown>).command
  return typeof command === 'string' ? command : undefined
}

/** One audit log entry, in the server hook-kit `audit.py` format. */
interface AuditEntry {
  ts: string
  event: 'harness_deny'
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

  /** Evaluate one execution: its command plus the denying verdict, if any. */
  function judge(exec: Readonly<ToolExecution>): { command: string; verdict: DenyVerdict } | undefined {
    if (!GUARDED_TOOLS.has(exec.name)) return undefined
    const command = extractCommand(exec.arguments)
    if (command === undefined) return undefined
    const verdict = judgeCommand(command)
    return verdict === undefined ? undefined : { command, verdict }
  }

  /** Audit a denial and return the model-visible deny reason. */
  function deny(exec: ToolExecution, command: string, verdict: DenyVerdict): string {
    recordAudit(auditPath, {
      ts: localTimestamp(),
      event: 'harness_deny',
      actor,
      rule: verdict.rule,
      tool: exec.name,
      command: command.slice(0, commandPreviewChars),
      cwd: process.cwd(),
      ...exec.agent !== undefined ? { session_id: exec.agent.id } : {},
    })
    return verdict.reason
  }

  // The extensible waterfall gate: deny early with the model-visible reason.
  // Non-guarded tools and pass judgments delegate to the rest of the chain.
  ctx.on('tools/pre-execute', async (exec, next): Promise<PreToolDecision> => {
    const judged = judge(exec)
    if (judged !== undefined) return { kind: 'deny', reason: deny(exec, judged.command, judged.verdict) }
    return next()
  })

  // The monotonic final guard: runs after the whole pre-execute waterfall,
  // so an upstream listener that short-circuited with an allow decision
  // cannot resurrect a call this invariant forbids.
  ctx.tools.guard((exec) => {
    const judged = judge(exec)
    if (judged === undefined) return undefined
    return deny(exec, judged.command, judged.verdict)
  })
}
