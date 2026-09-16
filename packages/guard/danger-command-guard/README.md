# dsh-danger-command-guard

English | [中文](README.zh.md)

Native danger-command guard: monotonic deny policy over catastrophic shell commands on the `bash`/`pwsh` tools, plus a JSONL audit trail in the local hook-kit audit log. The rule set, matching semantics, and deny text port the hook-kit's `shell_guard.py` (the multi-platform harness guard SSOT) verbatim, so every harness platform blocks the same disaster class and writes to the same audit log.

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

### Rules (ported from shell_guard.py, IGNORECASE, verbatim deny text)

| rule | Command class | Note |
| --- | --- | --- |
| `rm-root` | `rm -r[f]` / `--force -r` / `-fr` / `--recursive --force` against `/`, `~`, `//`, `/c/`, `$HOME`, `${HOME}` | quoted / trailing-slash / `/*` / `~/*` variants; matches the PowerShell `rm` alias too |
| `prune-af` | `docker (system\|container\|image\|volume) prune` with `-af`, `--all --force`, or separated `-a -f` / `-f -a` | plain `prune -f` stays allowed |
| `push-force` | `git push --force` / `-f` | `--force-with-lease` is veto-exempt |
| `push-plus` | `git push +refspec` | force-overwrites a remote branch (equivalent to `--force`) |
| `reset-hard` | `git reset --hard` | |
| `ps-remove` | `Remove-Item` with both `-Recurse` and `-Force` (any order) against a root/home target | flag detection uses `(?:^\|\s)` because `-` is a non-word character |
| `cmd-rd` | `rd`/`rmdir /s /q` against a root/home target | |

The root/home target requires a terminator (whitespace, quote, end of string, `/`, or `*`), so sub-paths like `/tmp/...` or `C:\project` never match.

### GuardFall hardening (`bash` only)

The `bash` tool additionally runs the hardened judge (`judgeCommandHardened`), mirroring `shell_guard.py`'s `judge_shell_hardened` — the `pwsh` tool stays on the raw judge because POSIX tokenization would mangle `C:\` backslashes:

- **Class A (quote merge)** — `r''m -rf /` is POSIX-tokenized then re-judged (`rm -rf /`).
- **Class B (`$IFS`)** — `rm${IFS}-rf${IFS}/` with a destructive binary (`rm`/`docker`/`git`) → `ifs-obfuscation`.
- **Class C (substitution)** — `echo "$(rm -rf /)"` recurses into `$(...)` / backtick bodies → `subst-<rule>`.
- **Line continuation** — `rm -rf \<newline>/` is folded to one line before judging.

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

## Model Experience

### Conditional deny result

#### What the model sees

No prompt or schema is added. When a guarded tool is called with a dangerous command, the call returns `Error: <deny reason>` with the exact Chinese texts below; every other call passes through unchanged.

- `危险命令已拦截：rm -rf 删除根目录/家目录不可恢复（安全红线）。`
- `危险命令已拦截：docker prune -af 有事故前科（2026-05-28），仅允许 docker system prune -f。`
- `危险操作已拦截：git push --force 属破坏性操作（--force-with-lease 放行）。`
- `危险操作已拦截：git reset --hard 属破坏性操作。`
- `危险命令已拦截：Remove-Item -Recurse -Force 删除根目录/家目录不可恢复。`
- `危险命令已拦截：rd/rmdir /s /q 删除根目录/家目录不可恢复。`

#### Token effect

Zero tokens on allowed calls. A denial replaces the (not executed) tool output with one small retained error result, saving the model from retrying a forbidden command with a full provider result.

#### KV Cache effect

Append-only; the deny result follows the reusable request prefix and does not invalidate existing KV-cache entries.

## Known Limitations and Deferred Work

- **Audit log rotation** — the Python `audit.py` rotates its log past 5 MB; this plugin appends without rotation. A long-running web profile should rely on the server-side rotation or add a rotation step here later.
- **Scope is the `bash`/`pwsh` tool names** — `tool-bash-persistent` also registers the tool name `bash` (covered); shell-like capability names outside these two (e.g. `terminal-bash`'s terminal tools) are not judged until their tool names are added to the matcher set.
- **`cwd` is the harness process directory** — the audit `cwd` field approximates the tool's working directory; the resolved shell workdir is owned by the shell providers.
