# dsh-danger-command-guard

English | [中文](README.zh.md)

Native danger-command guard: monotonic deny policy over catastrophic shell commands on the `bash`/`pwsh` tools, plus a JSONL audit trail in the local hook-kit audit log. Command matching follows the Python shell guard and is checked against a shared public fixture; the TypeScript plugin runs independently and keeps its Chinese deny text.

## Plugin (namespace: `danger-command-guard`)

A function/namespace plugin (`name` / `inject` / `apply`) consuming `ctx.tools`. It registers two extension points on the tool registry:

- a `tools/pre-execute` waterfall listener that denies early with the model-visible reason;
- a `ctx.tools.guard()` monotonic guard that re-checks after the whole waterfall, so an upstream listener that short-circuited with an allow decision cannot resurrect a call this final invariant forbids.

```yaml
- insert:
    - id: danger-command-guard
      name: '@deepseek-ai/dsh-danger-command-guard'
```

Loading is profile-scoped: the package resolves through the profile's own dependency closure (`link:` in `~/.dsh/profiles/<name>/package.json`), and the `insert` row above registers it. The core `apps/cli` bundle never depends on it — this is an external plugin, not part of the harness core.

### Rules

| rule | Command class | Note |
| --- | --- | --- |
| `rm-root` | `rm -r[f]` / `--force -r` / `-fr` / `--recursive --force` against `/`, `~`, `//`, `/c/`, `$HOME`, `${HOME}` | quoted / trailing-slash / `/*` / `~/*` variants; matches the PowerShell `rm` alias too |
| `prune-af` | `docker (system\|container\|image\|volume) prune` with `-af`, `--all --force`, or separated `-a -f` / `-f -a` | plain `prune -f` stays allowed |
| `push-force` | `git push --force` / `-f` | lease alone is allowed; explicit `--force` or lowercase `-f` still denies, even with lease |
| `push-plus` | `git push +refspec` | force-overwrites a remote branch (equivalent to `--force`) |
| `reset-hard` | `git reset --hard` | |
| `ps-remove` | `Remove-Item` with both `-Recurse` and `-Force` (any order) against a root/home target | flag detection uses `(?:^\|\s)` because `-` is a non-word character |
| `cmd-rd` | `rd`/`rmdir /s /q` against a root/home target | |
| `git-dot` | shell writes to `.git` internals: redirection, write commands, Python file writes | read-only commands and neighbouring names such as `.gitignore` are allowed |

The root/home target requires a terminator (whitespace, quote, end of string, `/`, or `*`), so sub-paths like `/tmp/...` or `C:\project` never match.

### GuardFall hardening (`bash` only)

The `bash` tool additionally runs the hardened judge (`judgeCommandHardened`), mirroring `shell_guard.py`'s `judge_shell_hardened` — the `pwsh` tool stays on the raw judge because POSIX tokenization would mangle `C:\` backslashes:

- **Class A (quote merge)** — `r''m -rf /` is POSIX-tokenized then re-judged (`rm -rf /`).
- **Class B (`$IFS`)** — `rm${IFS}-rf${IFS}/` with a destructive binary (`rm`/`docker`/`git`) → `ifs-obfuscation`.
- **Class C (substitution)** — `echo "$(rm -rf /)"` recurses into `$(...)` / backtick bodies → `subst-<rule>`.
- **Line continuation** — `rm -rf \<newline>/` is folded to one line before judging; bare newlines remain command separators.

Unquoted semicolons, pipes, and newlines isolate statements; separators inside quoted arguments do not. Quoted or escaped Bash heredocs and PowerShell here-string bodies are stripped before continuation folding, without discarding commands or redirects on their declaration line. Expandable PowerShell bodies and unquoted Bash heredocs retain `$()` scanning in the hardened judge. PowerShell backticks are escapes, not Bash substitutions.

### Escape hatches (audited, never silent)

| env | effect | audit event |
| --- | --- | --- |
| `HOOK_KIT_GUARD_OFF=1` | disable the guard session-wide | `guard_bypass` |
| `HOOK_KIT_GUARD_ALLOW_RULES=rm-root,...` | allow specific rules | `guard_rule_bypass` |
| `HOOK_KIT_GUARD_DRY_RUN=1` | audit-only, never deny | `harness_deny_dryrun` |

A denied call's reason carries the escape-hatch hint (rule id + audit path), so the model knows how to proceed deliberately instead of guessing.

### Deny behavior

A denial returns a `PreToolDecision.deny` with the Chinese reason (materialized as an `Error: <reason>` tool result the model sees) and appends one JSONL line to the audit log — same format as the server hook-kit's `audit.py`:

```json
{"ts":"2026-08-15T16:40:05","event":"harness_deny","actor":"dsh","rule":"rm-root","tool":"bash","command":"rm -rf /","cwd":"D:/repo","session_id":"a1"}
```

`command` is truncated at `commandPreviewChars` (default 200); `session_id` is omitted for agent-less calls; `cwd` is the harness process working directory. The write is fail-soft: any audit I/O error is swallowed and never affects the guard decision or the tool call it denies. The file is appended directly from TypeScript (no Python subprocess).

### Config

| Field | Default | Meaning |
| --- | --- | --- |
| `auditPath` | `$HOOK_KIT_AUDIT_LOG`, else `~/.config/hook-kit/audit.jsonl` | JSONL log path; blank fails loud |
| `actor` | `dsh` | `actor` value on audit entries |
| `commandPreviewChars` | `200` | command preview cap; must be an integer ≥ 1 |

## Shared regression data

[The generated cases](tests/fixtures/shell-guard-cases.json) and adjacent SHA-256 file mirror the Python guard's `tests/fixtures/shell-guard-cases.json`. Its `sync_guard_cases.py <package-root>` helper refreshes both; `--check` compares them without writing. The checksum covers UTF-8 with LF newlines. Package CI verifies the digest and both raw/hardened verdicts without fetching the Python repository; commands remain test data and are never run by a shell.

## Model Experience

### Conditional deny result

#### What the model sees

No prompt or schema is added. When a guarded tool is called with a dangerous command, the call returns `Error: <deny reason>` with the exact Chinese texts below; every other call passes through unchanged.

##### Possible denial reasons (one per call)

```markdown
危险命令已拦截：rm -rf 删除根目录/家目录不可恢复（安全红线）。
危险命令已拦截：docker prune -af 有事故前科（2026-05-28），仅允许 docker system prune -f。
危险操作已拦截：git push --force 属破坏性操作（--force-with-lease 放行）。
危险操作已拦截：git reset --hard 属破坏性操作。
危险命令已拦截：Remove-Item -Recurse -Force 删除根目录/家目录不可恢复。
危险命令已拦截：rd/rmdir /s /q 删除根目录/家目录不可恢复。
危险操作已拦截：写入 .git/ 内部文件会破坏 git 历史与钩子（红线同 apply_patch 路径；.gitignore/.gitattributes 除外；只读 cat/Get-Content/git 子命令不受影响）。
```

#### Token effect

Zero tokens on allowed calls. A denial replaces the (not executed) tool output with one small retained error result, saving the model from retrying a forbidden command with a full provider result.

#### KV Cache effect

Append-only; the deny result follows the reusable request prefix and does not invalidate existing KV-cache entries.

## Known Limitations and Deferred Work

- **Audit log rotation** — the Python `audit.py` rotates its log past 5 MB; this plugin appends without rotation. A long-running web profile should rely on the server-side rotation or add a rotation step here later.
- **Scope is the `bash`/`pwsh` tool names** — `tool-bash-persistent` also registers the tool name `bash` (covered); shell-like capability names outside these two (e.g. `terminal-bash`'s terminal tools) are not judged until their tool names are added to the matcher set.
- **`cwd` is the harness process directory** — the audit `cwd` field approximates the tool's working directory; the resolved shell workdir is owned by the shell providers.
