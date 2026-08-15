# Agent Note: Danger-command guard — native deny policy ported from shell_guard.py

Status: implemented

English | [中文](2026-08-15-danger-command-guard.zh.md)

## Problem

The machine-level hook-kit already blocks catastrophic shell commands for Claude Code, Codex, and Cursor through `shell_guard.py` (the multi-platform guard SSOT, mounted as an external PreToolUse hook). The DeepSeek Harness had no equivalent: an agent running in the `web` profile could issue `rm -rf /`, `docker system prune -af`, `git push --force`, `git reset --hard`, or the PowerShell/cmd equivalents, and nothing between the model and the shell would stop it. A bridge that shells out to the Python script would forfeit the native plugin surface (typed decisions, full `ctx`, no serialization boundary), so the guard belongs in a native Cordis plugin whose rule set ports the SSOT verbatim.

## Decision

Ship `@deepseek-ai/dsh-danger-command-guard` (`packages/guard/danger-command-guard/`), a function plugin (`name`/`inject`/`apply`) guarding the `bash`/`pwsh` tool names through two extension points:

- **`tools/pre-execute`** — the extensible waterfall gate. On a match it returns `PreToolDecision.deny` with the model-visible Chinese reason (materialized as an `Error: <reason>` tool result); everything else delegates with `next()`.
- **`ctx.tools.guard()`** — the monotonic final guard. It re-judges after the whole waterfall, so an upstream listener that short-circuited with an allow decision cannot resurrect a call this final invariant forbids.

The rule set is a line-for-line port of `shell_guard.py`: the four inline regex rules (`rm-root`, `prune-af`, `push-force` with `--force-with-lease` veto, `reset-hard`) plus the two predicate checks (`ps-remove`, `cmd-rd`) with the same `ROOT_TARGET` terminator logic and IGNORECASE semantics. The deny texts are verbatim Chinese. The unit-test deny/pass matrices copy the parametrize lists from `tests/test_shell_guard.py` so the two implementations stay provably identical.

A denial also appends one JSONL audit line in the hook-kit `audit.py` format (`ts`/`event: harness_deny`/`actor: dsh`/`rule`/`tool`/`command` truncated at `commandPreviewChars`/`cwd`/`session_id`) to `$HOOK_KIT_AUDIT_LOG` or `~/.config/hook-kit/audit.jsonl`, written directly from TypeScript (no Python subprocess). The write is fail-soft: audit I/O errors are swallowed and never affect the guard decision or the tool call.

## Consequences

- The `web` profile on the local machine mounts the row (`~/.dsh/profiles/web/cordis.patch.yml`, `insert` with id `danger-command-guard`); the package resolves through the app dependency closure healed into `$DSH_HOME/profiles/node_modules`.
- Denials now produce a model-visible error result instead of executing; the session log records the deny through the ordinary `tool/result` pipeline, so no new session event was needed.
- Guard, deny text, and audit format share one semantic source with the hook-kit; any rule change there must be ported here with its tests.
- Audit rotation stays on the Python side (this plugin appends without rotating); scope is the `bash`/`pwsh` tool names only.

## Alternatives considered

- **Shelling out to `shell_guard.py` as an external hook** — rejected: it forfeits the native typed-decision surface and adds a subprocess + serialization boundary per tool call; the native plugin is strictly more powerful.
- **Pre-execute deny only, no monotonic guard** — rejected: a listener upstream of ours that returns an allow decision without delegating would silently bypass the guard; `ctx.tools.guard()` makes the deny an ordering-proof invariant.
- **Enforcing in the loop or the shell providers** — rejected: the tool pipeline's interception points are the documented home for policy, and a registry-level guard covers every shell provider at once.
