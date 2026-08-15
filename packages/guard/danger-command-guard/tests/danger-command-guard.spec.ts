/**
 * Unit + real-composition coverage for @deepseek-ai/dsh-danger-command-guard.
 * The judgeCommand deny/pass matrices port the parametrize lists from
 * scripts/hook-kit/tests/test_shell_guard.py verbatim, so the native guard
 * and the Python shell guard stay semantically identical. A real agent loop
 * drives the model-visible deny result, audit writes go to temp files, and
 * disposal/HMR-safety plus the monotonic-guard backstop are proven through
 * the real tool registry.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import type { Agent } from '@deepseek-ai/dsh-agent'
import AgentLoop from '@deepseek-ai/dsh-agent-loop'
import { mountAgentLoopTestDependencies } from '@deepseek-ai/dsh-agent-loop-testkit'
import { CallId, createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId, type SessionEvent } from '@deepseek-ai/dsh-session'
import { defineContentToolFixture } from '@deepseek-ai/dsh-tools'
import * as DangerCommandGuard from '@deepseek-ai/dsh-danger-command-guard'
import { judgeCommand } from '@deepseek-ai/dsh-danger-command-guard'
import type { Config } from '@deepseek-ai/dsh-danger-command-guard'
import { MockAdapter, textResponse, toolCallResponse } from '../../../core/agent-loop/tests/mock-adapter.ts'

const testToolSignal = new AbortController().signal

/** Temp directories created by this suite, removed after every test. */
const tempDirs: string[] = []

afterEach(() => {
  vi.unstubAllEnvs()
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true })
  }
})

/** One throwaway temp directory, cleaned after the test. */
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-danger-command-guard-'))
  tempDirs.push(dir)
  return dir
}

// ---- judgeCommand matrices (ported verbatim from test_shell_guard.py) ----

describe('judgeCommand rule matrices (ported from test_shell_guard.py)', () => {
  describe('rm-root', () => {
    it.each([
      'rm -rf /',
      'rm -rf ~',
      'rm -rf ~/',
      'rm -r /',
      'rm -rf /*',
      'rm -rf "/"',
      "rm -rf '/'",
      'rm --force -r /tmp2 && rm -r --force /',
      'sudo rm -rf /',
      'rm -fr /',
      'rm -rf / --no-preserve-root',
    ])('denies %j', (command) => {
      expect(judgeCommand(command)).toMatchObject({ rule: 'rm-root' })
    })

    it.each([
      'rm -rf /tmp/build',
      'rm -rf ./node_modules',
      'rm -rf ~/project/dist',
      'rm -r build/',
      'rm -rf /home/user/cache',
    ])('passes sub-path %j', (command) => {
      expect(judgeCommand(command)).toBeUndefined()
    })
  })

  describe('prune-af', () => {
    it.each([
      'docker system prune -af',
      'docker system prune --all --force',
      'docker system prune -a -f',
      'docker system prune -f -a',
      'docker container prune -af',
      'docker image prune --force --all',
      'docker volume prune -af',
    ])('denies %j', (command) => {
      expect(judgeCommand(command)).toMatchObject({ rule: 'prune-af' })
    })

    it.each([
      'docker system prune -f',
      'docker system prune --volumes',
      'docker image prune -f',
      'docker system df',
      'docker volume ls',
    ])('passes %j', (command) => {
      expect(judgeCommand(command)).toBeUndefined()
    })
  })

  describe('push-force / reset-hard', () => {
    it.each([
      'git push --force origin main',
      'git push -f',
      'git push origin main --force',
      'git push origin main -f',
    ])('denies %j', (command) => {
      expect(judgeCommand(command)).toMatchObject({ rule: 'push-force' })
    })

    it.each([
      'git push --force-with-lease origin main',
      'git push --force-with-lease',
      'git push origin main',
      'git push -u origin main',
    ])('passes %j', (command) => {
      expect(judgeCommand(command)).toBeUndefined()
    })

    it.each([
      'git reset --hard HEAD~1',
      'git reset --hard',
    ])('denies %j', (command) => {
      expect(judgeCommand(command)).toMatchObject({ rule: 'reset-hard' })
    })

    it.each([
      'git reset --soft HEAD~1',
      'git reset HEAD~1',
      'git reset --mixed',
    ])('passes %j', (command) => {
      expect(judgeCommand(command)).toBeUndefined()
    })
  })

  describe('PowerShell / cmd equivalents', () => {
    it.each([
      'Remove-Item C:\\ -Recurse -Force',
      'Remove-Item -Recurse -Force C:\\',
      'Remove-Item ~ -Recurse -Force',
      'Remove-Item -Recurse -Force ~',
    ])('denies %j', (command) => {
      expect(judgeCommand(command)).toMatchObject({ rule: 'ps-remove' })
    })

    it.each([
      'Remove-Item C:\\project\\build -Recurse -Force',
      'Remove-Item -Recurse build',
      'Remove-Item C:\\build -Force',
    ])('passes %j', (command) => {
      expect(judgeCommand(command)).toBeUndefined()
    })

    it.each([
      'rd /s /q C:\\',
      'rd C:\\ /s /q',
      'rmdir /s /q ~',
    ])('denies %j', (command) => {
      expect(judgeCommand(command)).toMatchObject({ rule: 'cmd-rd' })
    })

    it.each([
      'rd /s /q C:\\project\\build',
      'rd build',
      'rmdir /s build',
    ])('passes %j', (command) => {
      expect(judgeCommand(command)).toBeUndefined()
    })
  })

  it('carries a model-facing Chinese reason on every denial', () => {
    for (const command of [
      'rm -rf /',
      'docker system prune -af',
      'git push --force origin main',
      'git reset --hard',
      'Remove-Item C:\\ -Recurse -Force',
      'rd /s /q C:\\',
    ]) {
      const verdict = judgeCommand(command)
      expect(verdict).toBeDefined()
      expect(verdict!.reason).toContain('危险')
    }
  })
})

// ---- real tool registry: deny materializes as an error result ----

/** A probe tool whose body counts invocations and returns fixed text. */
function probeTool(name: string, bodyCalls: { count: number }) {
  return defineContentToolFixture({
    name,
    description: `probe for ${name}`,
    parameters: {},
    execute() {
      bodyCalls.count += 1
      return [{ type: 'text' as const, text: `ran:${name}` }]
    },
  })
}

/** Boot the registry + the guard. */
async function registryHarness(config: Config = {}): Promise<Context> {
  const ctx = new Context()
  await mountAgentLoopTestDependencies(ctx)
  await ctx.plugin(DangerCommandGuard, config)
  return ctx
}

/** Joined text content of every tool/result event in the agent's session log. */
function resultTexts(agent: Agent): string[] {
  return [...agent.session.events]
    .filter((event): event is SessionEvent<'tool/result'> => event.type === 'tool/result')
    .map((event) => {
      const block = event.data.message.content[0]
      return block === undefined ? '' : block.content
        .map(contentBlock => contentBlock.type === 'text' ? contentBlock.text : '')
        .join('|')
    })
}

/** Run a dangerous command through the registry and expect the deny reason. */
async function expectDenied(
  ctx: Context,
  bodyCalls: { count: number },
  name: string,
  command: string,
  reason: string,
): Promise<void> {
  ctx.tools.register(probeTool(name, bodyCalls))
  const result = await ctx.tools.execute({
    callId: CallId(`deny-${name}`), name, arguments: { command }, signal: testToolSignal,
  })
  expect(result.isError).toBe(true)
  expect(result.content).toEqual([{ type: 'text', text: `Error: ${reason}` }])
  expect(bodyCalls.count).toBe(0)
}

describe('tools/pre-execute deny through the real registry', () => {
  it('denies a dangerous bash command and never runs the tool body', async () => {
    const ctx = await registryHarness({ auditPath: join(tempDir(), 'audit.jsonl') })
    const bodyCalls = { count: 0 }
    await expectDenied(ctx, bodyCalls, 'bash', 'rm -rf /',
      '危险命令已拦截：rm -rf 删除根目录/家目录不可恢复（安全红线）。')
  })

  it('denies the PowerShell equivalent on the pwsh tool', async () => {
    const ctx = await registryHarness({ auditPath: join(tempDir(), 'audit.jsonl') })
    const bodyCalls = { count: 0 }
    await expectDenied(ctx, bodyCalls, 'pwsh', 'Remove-Item -Recurse -Force C:\\',
      '危险命令已拦截：Remove-Item -Recurse -Force 删除根目录/家目录不可恢复。')
  })

  it('allows safe commands and non-guarded tools', async () => {
    const ctx = await registryHarness({ auditPath: join(tempDir(), 'audit.jsonl') })
    const bodyCalls = { count: 0 }
    ctx.tools.register(probeTool('bash', bodyCalls))
    ctx.tools.register(probeTool('read', bodyCalls))
    const safe = await ctx.tools.execute({
      callId: CallId('safe'), name: 'bash', arguments: { command: 'ls -la' }, signal: testToolSignal,
    })
    expect(safe.isError).toBe(false)
    // A non-guarded tool carrying a dangerous-looking string is not judged.
    const other = await ctx.tools.execute({
      callId: CallId('other'), name: 'read', arguments: { command: 'rm -rf /' }, signal: testToolSignal,
    })
    expect(other.isError).toBe(false)
    expect(bodyCalls.count).toBe(2)
  })

  it('abstains for missing and non-string command arguments', async () => {
    const ctx = await registryHarness({ auditPath: join(tempDir(), 'audit.jsonl') })
    const bodyCalls = { count: 0 }
    ctx.tools.register(probeTool('bash', bodyCalls))
    for (const [callId, argumentsValue] of [
      ['missing', {}],
      ['non-string-command', { command: 42 }],
    ] as const) {
      const result = await ctx.tools.execute({
        callId: CallId(callId), name: 'bash', arguments: argumentsValue, signal: testToolSignal,
      })
      expect(result.isError, callId).toBe(false)
    }
    expect(bodyCalls.count).toBe(2)
  })

  it('abstains for arguments the registry itself rejects (null and non-object)', async () => {
    const ctx = await registryHarness({ auditPath: join(tempDir(), 'audit.jsonl') })
    const bodyCalls = { count: 0 }
    ctx.tools.register(probeTool('bash', bodyCalls))
    for (const [callId, argumentsValue] of [
      ['null-args', null],
      ['non-object', 'not-an-object'],
    ] as const) {
      const result = await ctx.tools.execute({
        callId: CallId(callId), name: 'bash', arguments: argumentsValue, signal: testToolSignal,
      })
      // The guard abstained (no shell command to judge); the error comes from
      // the registry's argument materialization, so it must not carry a deny
      // reason.
      expect(result.isError, callId).toBe(true)
      expect(JSON.stringify(result.content), callId).not.toContain('危险')
    }
    expect(bodyCalls.count).toBe(0)
  })
})

// ---- the monotonic guard survives a short-circuited waterfall ----

describe('tools.guard() monotonic backstop', () => {
  it('denies even when an upstream prepended listener force-allows', async () => {
    const ctx = await registryHarness({ auditPath: join(tempDir(), 'audit.jsonl') })
    const bodyCalls = { count: 0 }
    ctx.tools.register(probeTool('bash', bodyCalls))
    const removeAllowListener = ctx.on('tools/pre-execute',
      () => Promise.resolve({ kind: 'allow' }), { prepend: true })
    const result = await ctx.tools.execute({
      callId: CallId('backstop'), name: 'bash', arguments: { command: 'rm -rf /' }, signal: testToolSignal,
    })
    expect(result.isError).toBe(true)
    expect(bodyCalls.count).toBe(0)
    removeAllowListener()
  })
})

// ---- audit trail ----

/** Read every JSON line of an audit file. */
function auditLines(path: string): Record<string, unknown>[] {
  return readFileSync(path, 'utf8').trim().split('\n').map(line => JSON.parse(line) as Record<string, unknown>)
}

describe('audit trail', () => {
  it('appends one harness_deny JSONL entry with the hook-kit field format', async () => {
    const auditPath = join(tempDir(), 'audit.jsonl')
    const ctx = await registryHarness({ auditPath })
    const bodyCalls = { count: 0 }
    await expectDenied(ctx, bodyCalls, 'bash', 'git push --force origin main',
      '危险操作已拦截：git push --force 属破坏性操作（--force-with-lease 放行）。')

    const lines = auditLines(auditPath)
    expect(lines).toHaveLength(1)
    const entry = lines[0]!
    expect(entry.event).toBe('harness_deny')
    expect(entry.actor).toBe('dsh')
    expect(entry.rule).toBe('push-force')
    expect(entry.tool).toBe('bash')
    expect(entry.command).toBe('git push --force origin main')
    expect(entry.cwd).toBe(process.cwd())
    expect(entry).not.toHaveProperty('session_id')
    expect(entry.ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/)
  })

  it('truncates the command at commandPreviewChars and honors a custom actor', async () => {
    const auditPath = join(tempDir(), 'audit.jsonl')
    const ctx = await registryHarness({ auditPath, actor: 'test-actor', commandPreviewChars: 10 })
    const bodyCalls = { count: 0 }
    await expectDenied(ctx, bodyCalls, 'bash', 'rm -rf / --very-long-suffix-that-exceeds-the-limit',
      '危险命令已拦截：rm -rf 删除根目录/家目录不可恢复（安全红线）。')

    const entry = auditLines(auditPath)[0]!
    expect(entry.actor).toBe('test-actor')
    expect(entry.command).toHaveLength(10)
  })

  it('stamps the agent session id on loop-driven denials', async () => {
    const auditPath = join(tempDir(), 'audit.jsonl')
    const ctx = new Context()
    await mountAgentLoopTestDependencies(ctx)
    await ctx.plugin(AgentLoop, { agents: [] })
    await ctx.plugin(DangerCommandGuard, { auditPath })
    const bodyCalls = { count: 0 }
    ctx.tools.register(probeTool('bash', bodyCalls))
    ctx.llm.registerAdapter(['mock'], new MockAdapter([
      toolCallResponse('c1', 'bash', { command: 'docker system prune -af' }),
      textResponse('done'),
    ]))
    const agent = ctx.agentLoop.create(SessionId('a1'), { provider: 'mock', model: 'mock' })
    agent.followup(createUserMessage({ content: [{ type: 'text', text: 'go' }], source: { kind: 'user' } }))
    await new Promise<void>((resolve) => {
      const dispose = ctx.on('agent/status', ({ agent: current, status }) => {
        if (current === agent && status === 'idle') { dispose(); resolve() }
      })
    })

    expect(resultTexts(agent)).toContain('Error: 危险命令已拦截：docker prune -af 有事故前科（2026-05-28），仅允许 docker system prune -f。')
    expect(bodyCalls.count).toBe(0)
    const entry = auditLines(auditPath)[0]!
    expect(entry.rule).toBe('prune-af')
    expect(entry.session_id).toBe('a1')
  })

  it('stays fail-soft when the audit path is unwritable (deny unaffected)', async () => {
    const blocker = join(tempDir(), 'blocker')
    writeFileSync(blocker, 'a file, not a directory')
    const ctx = await registryHarness({ auditPath: join(blocker, 'sub', 'audit.jsonl') })
    const bodyCalls = { count: 0 }
    await expectDenied(ctx, bodyCalls, 'bash', 'rm -rf /',
      '危险命令已拦截：rm -rf 删除根目录/家目录不可恢复（安全红线）。')
  })

  it('falls back to the hook-kit home default when neither config nor env names a path', async () => {
    const fakeHome = tempDir()
    vi.stubEnv('USERPROFILE', fakeHome)
    const ctx = await registryHarness()
    const bodyCalls = { count: 0 }
    await expectDenied(ctx, bodyCalls, 'bash', 'rm -rf /',
      '危险命令已拦截：rm -rf 删除根目录/家目录不可恢复（安全红线）。')

    const entry = auditLines(join(fakeHome, '.config', 'hook-kit', 'audit.jsonl'))[0]!
    expect(entry.event).toBe('harness_deny')
  })

  it('honors the HOOK_KIT_AUDIT_LOG environment override', async () => {
    const auditPath = join(tempDir(), 'env-audit.jsonl')
    vi.stubEnv('HOOK_KIT_AUDIT_LOG', auditPath)
    const ctx = await registryHarness()
    const bodyCalls = { count: 0 }
    await expectDenied(ctx, bodyCalls, 'bash', 'rm -rf /',
      '危险命令已拦截：rm -rf 删除根目录/家目录不可恢复（安全红线）。')

    expect(auditLines(auditPath)).toHaveLength(1)
  })
})

// ---- config validation ----

describe('fail-loud config validation', () => {
  it.each([
    [{ commandPreviewChars: 0 }, /commandPreviewChars/],
    [{ commandPreviewChars: 1.5 }, /commandPreviewChars/],
    [{ auditPath: '   ' }, /auditPath/],
  ])('rejects invalid config %o', async (config, message) => {
    const ctx = new Context()
    await mountAgentLoopTestDependencies(ctx)
    await expect(ctx.plugin(DangerCommandGuard, config as Config)).rejects.toThrow(message)
  })
})

// ---- disposal (HMR safety) ----

describe('disposal (HMR safety)', () => {
  it('removes both the pre-execute deny and the monotonic guard when the fiber disposes', async () => {
    const ctx = new Context()
    await mountAgentLoopTestDependencies(ctx)
    const fiber = await ctx.plugin(DangerCommandGuard, { auditPath: join(tempDir(), 'audit.jsonl') })
    const bodyCalls = { count: 0 }
    await expectDenied(ctx, bodyCalls, 'bash', 'rm -rf /',
      '危险命令已拦截：rm -rf 删除根目录/家目录不可恢复（安全红线）。')

    await fiber.dispose()

    const result = await ctx.tools.execute({
      callId: CallId('after-dispose'), name: 'bash', arguments: { command: 'rm -rf /' }, signal: testToolSignal,
    })
    expect(result.isError).toBe(false)
    expect(bodyCalls.count).toBe(1)
  })
})

// ---- real-load-path guard ----

describe('dsh-danger-command-guard real-load-path guard', () => {
  it('has no default export and keeps name/inject through unwrapExports', () => {
    expect('default' in DangerCommandGuard).toBe(false)
    const loader = Object.create(Loader.prototype) as Loader
    const unwrapped = loader.unwrapExports(DangerCommandGuard) as Record<string, unknown>
    expect(unwrapped).toBe(DangerCommandGuard)
    expect(unwrapped.name).toBe('danger-command-guard')
    expect(unwrapped.inject).toEqual(['tools'])
    expect(typeof unwrapped.apply).toBe('function')
  })
})
