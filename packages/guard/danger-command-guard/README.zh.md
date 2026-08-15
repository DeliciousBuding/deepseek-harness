# dsh-danger-command-guard

[English](README.md) | 中文

原生危险命令守卫：对 `bash`/`pwsh` 工具上的灾难级 shell 命令执行单调 deny 策略，并向本地 hook-kit 审计日志追加 JSONL 审计。规则集、匹配语义与拦截文案逐条移植自 hook-kit 的 `shell_guard.py`（多平台 harness 守卫 SSOT），保证各 harness 平台拦截同一灾难类别、写入同一审计日志。

## 插件（命名空间：`danger-command-guard`）

函数/命名空间插件（`name` / `inject` / `apply`），消费 `ctx.tools`，在工具注册表上挂载两个扩展点：

- `tools/pre-execute` waterfall 监听器：提前 deny，reason 对模型可见；
- `ctx.tools.guard()` 单调守卫：整个 waterfall 结束后再查一遍——上游监听器即使短路返回 allow，也无法复活这个最终不变量所禁止的调用。

```yaml
- insert:
    - id: danger-command-guard
      name: '@deepseek-ai/dsh-danger-command-guard'
```

加载是 profile 作用域：包通过 profile 自身的依赖闭包解析（`~/.dsh/profiles/<name>/package.json` 里的 `link:`），上面的 `insert` 行完成注册。核心 `apps/cli` bundle **从不依赖它**——这是外置插件，不属于 harness 核心。

### 规则（移植自 shell_guard.py，IGNORECASE，拦截文案逐字一致）

| 规则 | 命令类别 | 备注 |
| --- | --- | --- |
| `rm-root` | `rm -r[f]` / `--force -r` / `-fr` / `--recursive --force` 删除 `/`、`~`、`//`、`/c/`、`$HOME`、`${HOME}` | 覆盖引号/尾斜杠/`/*`/`~/*` 变体；同样命中 PowerShell 的 `rm` 别名 |
| `prune-af` | `docker (system\|container\|image\|volume) prune` 带 `-af`、`--all --force` 或分离写法 `-a -f` / `-f -a` | 单独 `prune -f` 放行 |
| `push-force` | `git push --force` / `-f` | `--force-with-lease` 经 veto 豁免 |
| `push-plus` | `git push +refspec` | 强制覆盖远端分支（等价 `--force`） |
| `reset-hard` | `git reset --hard` | |
| `ps-remove` | `Remove-Item` 同时带 `-Recurse` 与 `-Force`（任意顺序）且目标为根/家目录 | flag 检测用 `(?:^\|\s)`，因 `-` 是非词字符 |
| `cmd-rd` | `rd`/`rmdir /s /q` 且目标为根/家目录 | |

根/家目录目标必须跟随终止符（空白、引号、行尾、`/` 或 `*`），因此 `/tmp/...`、`C:\project` 等子路径永不误伤。

### GuardFall 加固（仅 `bash`）

`bash` 工具额外走加固判定（`judgeCommandHardened`，对应 `shell_guard.py` 的 `judge_shell_hardened`）——`pwsh` 保持原始判定，因为 POSIX 令牌化会误拆 `C:\` 反斜杠：

- **A 类（引号合并）** — `r''m -rf /` 先 POSIX 令牌化再复判（`rm -rf /`）。
- **B 类（`$IFS`）** — `rm${IFS}-rf${IFS}/` 叠加破坏性二元组（`rm`/`docker`/`git`）→ `ifs-obfuscation`。
- **C 类（命令替换）** — `echo "$(rm -rf /)"` 递归进入 `$(...)` / 反引号体 → `subst-<rule>`。
- **行续接** — `rm -rf \<换行>/` 先折叠成单行再判定。

### 逃生口（全程审计，绝不静默）

| 环境变量 | 效果 | 审计事件 |
| --- | --- | --- |
| `HOOK_KIT_GUARD_OFF=1` | 会话级整体关闭守卫 | `guard_bypass` |
| `HOOK_KIT_GUARD_ALLOW_RULES=rm-root,...` | 按规则放行 | `guard_rule_bypass` |
| `HOOK_KIT_GUARD_DRY_RUN=1` | 只审计不拦截 | `harness_deny_dryrun` |

被拦调用的 reason 自带逃生口提示（命中 rule id + 审计路径），模型据此可主动决定如何放行，而非瞎猜。

### deny 行为

命中时返回 `PreToolDecision.deny`（物化为模型可见的 `Error: <reason>` 工具结果），并追加一行 JSONL 到审计日志——与 server hook-kit `audit.py` 同格式：

```json
{"ts":"2026-08-15T16:40:05","event":"harness_deny","actor":"dsh","rule":"rm-root","tool":"bash","command":"rm -rf /","cwd":"D:/repo","session_id":"a1"}
```

`command` 按 `commandPreviewChars` 截断（默认 200）；无 agent 的调用省略 `session_id`；`cwd` 为 harness 进程工作目录。写入为 fail-soft：审计 I/O 的任何错误都被吞掉，绝不影响守卫判定或被拦截的工具调用。文件由 TypeScript 直接追加（不调 Python）。

### 配置

| 字段 | 默认 | 含义 |
| --- | --- | --- |
| `auditPath` | `$HOOK_KIT_AUDIT_LOG`，否则 `~/.config/hook-kit/audit.jsonl` | JSONL 日志路径；空值 fail loud |
| `actor` | `dsh` | 审计条目上的 `actor` 值 |
| `commandPreviewChars` | `200` | 命令预览截断长度；必须为 ≥ 1 的整数 |

## Model Experience

### 条件性 deny 结果

#### 模型看到什么

不新增任何 prompt 或 schema。当被守卫工具以危险命令调用时，调用返回 `Error: <拦截原因>`，文案如下（逐字）；其余调用原样放行。

- `危险命令已拦截：rm -rf 删除根目录/家目录不可恢复（安全红线）。`
- `危险命令已拦截：docker prune -af 有事故前科（2026-05-28），仅允许 docker system prune -f。`
- `危险操作已拦截：git push --force 属破坏性操作（--force-with-lease 放行）。`
- `危险操作已拦截：git reset --hard 属破坏性操作。`
- `危险命令已拦截：Remove-Item -Recurse -Force 删除根目录/家目录不可恢复。`
- `危险命令已拦截：rd/rmdir /s /q 删除根目录/家目录不可恢复。`

#### Token 影响

放行调用零 token。拦截时用一条小型保留错误结果替换（未执行的）工具输出，避免模型拿着完整的 provider 结果反复重试被禁命令。

#### KV Cache 影响

仅追加；deny 结果跟随可复用的请求前缀，不使既有 KV-cache 条目失效。

## Known Limitations and Deferred Work

- **审计日志轮转** — Python 侧 `audit.py` 超过 5 MB 会轮转；本插件只追加不轮转。长期运行的 web profile 应依赖服务端轮转，或后续在此补轮转步骤。
- **范围是 `bash`/`pwsh` 两个工具名** — `tool-bash-persistent` 注册的工具名同样是 `bash`（已覆盖）；这两个名字之外的类 shell 能力（如 `terminal-bash` 的终端工具）在工具名加入匹配集之前不判定。
- **`cwd` 是 harness 进程目录** — 审计 `cwd` 字段近似工具的工作目录；解析后的 shell workdir 归 shell provider 所有。
