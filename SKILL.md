---
name: dingtalk-message-decrypt
description: 读取或整理钉钉聊天记录时使用：运行脚本批量读取并解密单聊、群聊和引用，输出可供 AI 分析的正文。适用于聊天总结、周报、待办、纪要和决策追溯；遇到 dws 加密占位符也使用此技能。
---

# 钉钉消息批量读取

按用户指定的会话和时间运行本技能的 `scripts/dws_decrypt.py`，先读输出的 `summary.json`，再分析 `messages.jsonl`，并说明未读到的内容。

脚本负责批量读取和解密，模型只分析结果。不要逐条调用模型解密，也不要把加密占位符当正文总结。

## 直接执行

以下 `<skill>` 指本 SKILL.md 所在目录。使用当前已认证 dws 账号；不要擅自切账号。为账号/任务使用独立输出目录和 `--scope` 标签。

已有底层 API JSON/JSONL：

```text
python <skill>/scripts/dws_decrypt.py --input <原始文件> --out <结果目录> --scope <账号标签>
```

读取已明确的会话和时间窗（CID 必须来自真实返回）：

```text
python <skill>/scripts/dws_decrypt.py --conversation-id <cid> --start "2026-10-01 00:00:00" --end "2026-10-15 23:59:59" --out <结果目录> --scope <账号标签>
```

跨会话批量读取可用 `--days 92 --kind all`；保持用户指定的时间和会话范围。恢复分页用同一 `--out`、`--scope` 加 `--resume`，不再指定 `--days`。

每次新建输出目录的持续采集，应传 `--read-policy-store <账号私有目录>/read-policy.sqlite3`，并使用经认证核验的账号 scope；它跨批次记住明确的保密群读取限制，直接跳过相关正文请求，保留 partial 和缺口说明。不同账号使用不同文件；不要清除记录来重试已知被禁止的路径。

已确认 `CRYPTO_DISABLED` 时，首次加 `--known-policy-disabled` 记录该事实，后续相同输出目录自动停止重试。纯离线处理加 `--server off --client off`。只有策略确实恢复才用 `--server retry`。

先读 `summary.json`；再按任务读取 `messages.jsonl`。退出码 2 表示保留了部分可用结果，不是脚本崩溃。引用、冲突、剩余密文见 `unresolved.jsonl`；原始记录保留于 `resolved.jsonl`。

跨设备失败先检查 `local_crypto.dependencies` 和 `python_executable`：`local_dependency_unavailable` 表示依赖不可用，按报告的 `install_command` 在同一解释器环境修复后重跑。`Crypto` 对应 `pycryptodome`；`cached_key_count=0` 不能证明客户端缺密钥。详细字段和来源核验见 [跨设备排查](references/automation.md#跨设备排查)。

客户端升级后若 `local_crypto.stop_reason=unsupported_client_fingerprint`，检查
`local_crypto.client_compatibility`；这是磁盘指纹校验失败，尚未进入密钥查找。
可运行 `python <skill>/scripts/client_doctor.py --dll "<实际 MainFrame.dll 路径>"` 生成无正文、无密钥的离线诊断。
已知指纹也不代表业务恢复；新版本接入与验收见 [客户端兼容性](references/client-compatibility.md)。

## 必须保留的判断

- 单聊和群聊正文都可能加密。高层 `+chat-messages` / `+at-me` 可能只给占位符；需要底层 `chat message list` 的 `content`。脚本负责分页，不传 `--max-items`，不要再绕回 `list-all` / `+search-msg` 来恢复密文。
- 服务端用 `full`，要求 dws >=1.0.63，`--file` 必须是相对文件名（脚本设置 cwd）。`safechat` 中间结果 `1_1_<hex>` 不是明文；脚本的本地后端会继续完成 DING 层，不能单独将中间结果交给模型。不要试 `ding`、清空密钥缓存或升级来修复服务端策略关闭。
- `CRYPTO_DISABLED` 只停止服务端重试，不阻断已验证的本地后端。默认 `--client auto --local-crypto auto` 按消息企业/版本，从已登录且版本匹配的 Windows 客户端定向读取缓存 key，在内存中解包并完成 AES-CBC。key不落盘；不滚屏、不调用目标函数或写进程。另需 `pefile` 和 PyCryptodome。
- 消息有 `oid` 时优先映射，显式 `corpId` 必须一致；缺失时可查精确 CID 的群会话 `corpId`。单聊等缺企业字段时，脚本会一次扫描本批目标的原生会话对象，只有完整扫描、双读稳定、全部候选和两种组织选择分支一致时才采用组织归属。记录来源与时点，不猜当前登录主企业或遍历其他企业key试解。缺身份、缺企业/版本key或未知客户端版本均保留未解决；当前会话元数据不能独立证明全部历史的企业归属稳定。
- `--local-crypto off` 关闭密钥后端，保留已加载正文补充；`--client off` 同时关闭两者。纯离线处理仍用 `--server off --client off`。只有本地解密失败且仍有正文密文时才扫描已加载消息。
- `client_observed` 是客户端观察，不是独立密码学解密；无确切 API 身份的正文保存在单独补充文件，不按时间猜配。没有驻留消息时可得到 0，继续交付已有结果并如实列出缺口。
- 可读数、服务端解密数、客户端补充数、分页完整性分别报告。旧“100% 解密”结论混入过中间信封，不能沿用。

参数语义、恢复/缓存隔离、输出字段与当前验证边界见 [automation.md](references/automation.md)。

## 维护

源码在独立技能 Git 仓库。改源码后运行仓库的 `sync_to_agents.sh`，同步到 `~/.agents/skills/dingtalk-message-decrypt`，其余宿主通过符号链接跟随。

未来 agent 自动路由由调用方的 dws/chat 技能触发，可用 `scripts/install_routes.py --skill-file <聊天技能的SKILL.md>` 安装可逆路由。它只改指定文件中的标记块，先备份；上游重装覆盖该块后可重跑。不劫持 dws 命令或改其他能力路由。
