# 钉钉聊天记录读取与解密 · Agent Skill

让 AI 读取你的钉钉单聊和群聊，自动处理加密消息，用于总结、周报、待办和决策追溯。

## 给 Agent 的一句话

> 需要读取钉钉聊天记录时，先读本仓库的 [SKILL.md](SKILL.md)，按用户指定的会话和时间运行 `scripts/dws_decrypt.py`，再读取 `summary.json` 和 `messages.jsonl` 完成分析，并说明未读到的内容。

把仓库链接发给你的 AI，再告诉它具体任务即可，例如：

```text
请使用 https://github.com/hzqedison/dingtalk-message-decrypt 这个技能，
读取「项目讨论群」最近 7 天的聊天，整理结论、待办和未解决的问题。
```

Agent 需要能执行本机脚本，并加载这个技能。Codex、Claude Code、WorkBuddy 可共用同一份安装；直接运行原始 `dws` 命令不会自动获得此能力。

## 实际怎么用

已安装技能后，运行统一入口。`<skill>` 是 `SKILL.md` 所在目录；替换下方占位符，CID 从钉钉接口的真实结果获取。

```text
python <skill>/scripts/dws_decrypt.py --conversation-id <真实CID> --days 7 --out <结果目录> --scope <账号标签>
```

脚本负责读取、分页、解密和保存进度；批处理不调用大模型，也不需要你逐条打开或阅读消息。AI 按顺序读取结果：

| 输出 | Agent 用它做什么 |
| --- | --- |
| `summary.json` | 先确认读到了多少、范围是否完整、有哪些缺口 |
| `messages.jsonl` | 按任务需要读取正文，生成总结、周报或待办 |
| `unresolved.jsonl` | 说明仍未解决的内容，不猜测缺失正文 |

已有原始消息文件时，用 `--input <raw.json或raw.jsonl>` 替换会话和时间参数。中断后，用同一 `--out`、`--scope` 加 `--resume` 继续，不再传 `--days`。退出码 `2` 表示有部分结果，应先检查汇总；账号切换后使用新的结果目录和账号标签。

## 使用条件

- Python 3.10+，已安装并登录的 `dws >= 1.0.63`。
- 本地解密还需要 `pefile`、PyCryptodome，以及已登录、指纹匹配的 Windows 钉钉。`9.0.2.261015001` 已有运行样本验证；`9.0.2.261018001` 有 DELL 限定批次恢复回执；`9.0.4.261021001` 已完成静态核验及维护端一条保存正文的真实恢复对照，DELL 原失败样本仍待验收。三版分别选择独立布局，详见 [261021001 核验记录](references/client-261021001-validation.md)。
- 服务端解密不可用时，脚本会尝试本地解密。缺少匹配密钥、身份信息或遇到未知客户端版本时，会保留未解决项，不能保证全部历史可读。

完整参数、解密方式和验证边界见 [使用说明](references/automation.md)。

另一台电脑运行失败时，先看 `summary.json` 的 `local_crypto.dependencies`。缺少 `Crypto` 应在运行脚本的同一 Python 环境安装 `pycryptodome`；报告中的 `install_command` 给出了对应解释器。不要仅凭 `cached_key_count=0` 判断客户端缺密钥。具体步骤见 [跨设备排查](references/automation.md#跨设备排查)。

客户端升级后出现 `unsupported_client_fingerprint` 时，用
`python <skill>/scripts/client_doctor.py --dll "<实际 MainFrame.dll 路径>"`
生成离线指纹诊断。此时尚未进入密钥查找；不要添加新哈希来强行放行。
三个客户端读取入口共用兼容注册表，自动选择上述两版的独立布局；其他指纹继续拒绝。
`adapter_validation=runtime_batch_reported` 表示收到限定批次的运行验收回执，
不代表当前调用已恢复消息、全部历史可读或账号身份已独立核实。
扩展方法与验收要求见 [客户端兼容性](references/client-compatibility.md)。

## 安装与更新

**只维护这一个仓库的读取代码**：客户端适配、统一读取器、调用校验与接入示例一起更新。
日报或其他 Agent 的调用脚本首次接入，请读 [调用层接入说明](references/caller-integration/README.md)。
通用校验位于 `scripts/caller_checks.py`，随技能部署；各设备仅保留业务配置和少量调用代码。
更新技能不会自动修改已有业务脚本，也不会运行排程、发布日报或发送通知。

将本仓库放在本机，首次安装前检查 `install.sh`，保存已有的同名技能目录，再从仓库目录运行：

```bash
bash install.sh
```

Windows 请使用 Git Bash。主目录为 `~/.agents/skills/dingtalk-message-decrypt`；安装脚本为 `.codex`、`.claude`、`.workbuddy` 创建入口。以后更新仓库后运行：

```bash
bash sync_to_agents.sh
```

安装和同步会生成本地 `deployment.json`，记录源码提交、是否有未提交修改及部署文件哈希。部署目录没有 `.git` 是正常现象；执行 `python <skill>/scripts/deployment_info.py` 可核验来源和文件是否变动。旧部署没有该文件时来源未知，需从源码仓库重新同步；它不代表自动更新到最新版本。

若要让已有的 dws 聊天技能自动使用此流程，可为它安装路由（首次修改会备份）：

```text
python scripts/install_routes.py --skill-file <聊天技能的SKILL.md路径>
```

这只修改指定技能的调用指引，不替换 `dws` 程序。其他 Agent 可按各自的技能加载方式加载 [SKILL.md](SKILL.md)。

## 验证与技术文档

已用真实单聊、群聊快照验证；其中 11 条独立样本与客户端正文逐字节一致。离线测试覆盖分页、解密、缓存、依赖缺失诊断和部署来源核验，详细范围、未解决项及历史验证记录见 [验证说明](references/automation.md#目前的验证结论2026-10-18)。

```text
python -m unittest discover -s tests -v
```

开发者可继续阅读 [本地解密路径](references/client-paths.md)。[已加载正文采集工具](skills/dingtalk-plaintext-harvest/SKILL.md) 仅用于辅助观察；日常读取使用上面的统一入口。

聊天数据、密钥和运行缓存不提交到本仓库，也不随技能同步。
