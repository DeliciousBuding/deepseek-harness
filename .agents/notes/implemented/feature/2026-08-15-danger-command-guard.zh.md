# Agent Note: 危险命令守卫——移植自 shell_guard.py 的原生 deny 策略

Status: implemented

[English](2026-08-15-danger-command-guard.md) | 中文

## Problem

本机 hook-kit 已通过 `shell_guard.py`（多平台守卫 SSOT，作为外部 PreToolUse hook 挂载）为 Claude Code、Codex、Cursor 拦截灾难级 shell 命令。DeepSeek Harness 此前没有等价物：跑在 `web` profile 里的 agent 可以发出 `rm -rf /`、`docker system prune -af`、`git push --force`、`git reset --hard` 及 PowerShell/cmd 等价物，模型与 shell 之间没有任何拦截。桥接方式（外部调用 Python 脚本）会放弃原生插件面（类型化决策、完整 `ctx`、无序列化边界），因此守卫应做成原生 Cordis 插件，规则集逐字移植 SSOT。

## Decision

落地 `@deepseek-ai/dsh-danger-command-guard`（`packages/guard/danger-command-guard/`），函数插件（`name`/`inject`/`apply`），经两个扩展点守卫 `bash`/`pwsh` 工具名：

- **`tools/pre-execute`** — 可扩展 waterfall 门禁。命中即返回 `PreToolDecision.deny`，携带模型可见的中文 reason（物化为 `Error: <reason>` 工具结果）；其余一律 `next()` 委托。
- **`ctx.tools.guard()`** — 单调终局守卫。整个 waterfall 结束后重新判定，上游监听器即使短路返回 allow 也无法复活该最终不变量禁止的调用。

规则集是 `shell_guard.py` 的逐行移植：四条内联正则规则（`rm-root`、`prune-af`、`push-force` 带 `--force-with-lease` veto、`reset-hard`）加两个谓词检查（`ps-remove`、`cmd-rd`），沿用同一 `ROOT_TARGET` 终止符逻辑与 IGNORECASE 语义，拦截文案逐字中文一致。单测 deny/pass 矩阵照搬 `tests/test_shell_guard.py` 的 parametrize 列表，使两个实现可证明地保持一致。

deny 同时追加一行 hook-kit `audit.py` 格式的 JSONL 审计（`ts`/`event: harness_deny`/`actor: dsh`/`rule`/`tool`/按 `commandPreviewChars` 截断的 `command`/`cwd`/`session_id`）到 `$HOOK_KIT_AUDIT_LOG` 或 `~/.config/hook-kit/audit.jsonl`，由 TypeScript 直接写文件（不调 Python）。写入 fail-soft：审计 I/O 错误一律吞掉，绝不影响守卫判定或工具调用。

## Consequences

- 本机 `web` profile 挂载该行（`~/.dsh/profiles/web/cordis.patch.yml`，`insert`，id 为 `danger-command-guard`）；包经应用依赖闭包 heal 到 `$DSH_HOME/profiles/node_modules` 解析。
- 拦截现在产生模型可见的错误结果而非执行；会话日志经普通 `tool/result` 管线记录 deny，无需新会话事件。
- 守卫、拦截文案与审计格式与 hook-kit 共享同一语义源；那边任何规则变更都须连同测试移植到这里。
- 审计轮转仍留在 Python 侧（本插件只追加不轮转）；范围仅限 `bash`/`pwsh` 两个工具名。

## Alternatives considered

- **外部调用 `shell_guard.py` 作 hook** — 否决：放弃原生类型化决策面，且每次工具调用多一次子进程 + 序列化边界；原生插件严格更强。
- **只做 pre-execute deny，不要单调守卫** — 否决：我们上游的监听器若不委托就返回 allow，会静默绕过守卫；`ctx.tools.guard()` 使 deny 成为与顺序无关的不变量。
- **在 loop 或 shell provider 里强制执行** — 否决：工具管线的拦截点是策略的文档化归宿，注册表级守卫一次覆盖所有 shell provider。
