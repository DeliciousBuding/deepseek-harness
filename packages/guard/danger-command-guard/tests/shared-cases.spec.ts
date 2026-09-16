/** Public command data mirrored from the Python guard; no case is executed by a shell. */
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { judgeCommand, judgeCommandHardened } from '@deepseek-ai/dsh-danger-command-guard'
import fixture from './fixtures/shell-guard-cases.json'

describe('shared shell-guard cases', () => {
  it('keeps the generated fixture intact across LF and CRLF checkouts', () => {
    const content = readFileSync(new URL('./fixtures/shell-guard-cases.json', import.meta.url), 'utf8').replace(/\r\n/g, '\n')
    const digest = createHash('sha256').update(content, 'utf8').digest('hex')
    const recorded = readFileSync(new URL('./fixtures/shell-guard-cases.json.sha256', import.meta.url), 'utf8').trim()
    expect(recorded).toBe(digest + '  shell-guard-cases.json')
    expect(fixture.schema_version).toBe(1)
    expect(new Set(fixture.cases.map(testCase => testCase.id)).size).toBe(fixture.cases.length)
  })

  it.each(fixture.cases)('$id', (testCase) => {
    expect(judgeCommand(testCase.command)?.rule ?? null).toBe(testCase.raw_rule)
    expect(judgeCommandHardened(testCase.command)?.rule ?? null).toBe(testCase.hardened_rule)
  })
})
