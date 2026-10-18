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
- 本地解密还需要 `pefile`、PyCryptodome，以及已登录、版本匹配的 Windows 钉钉；当前验证版本为 `9.0.2.261015001`。
- 服务端解密不可用时，脚本会尝试本地解密。缺少匹配密钥、身份信息或遇到未知客户端版本时，会保留未解决项，不能保证全部历史可读。

完整参数、解密方式和验证边界见 [使用说明](references/automation.md)。

## 安装与更新

将本仓库放在本机，首次安装前检查 `install.sh`，保存已有的同名技能目录，再从仓库目录运行：

```bash
bash install.sh
```

Windows 请使用 Git Bash。主目录为 `~/.agents/skills/dingtalk-message-decrypt`；安装脚本为 `.codex`、`.claude`、`.workbuddy` 创建入口。以后更新仓库后运行：

```bash
bash sync_to_agents.sh
```

若要让已有的 dws 聊天技能自动使用此流程，可为它安装路由（首次修改会备份）：

```text
python scripts/install_routes.py --skill-file <聊天技能的SKILL.md路径>
```

这只修改指定技能的调用指引，不替换 `dws` 程序。其他 Agent 可按各自的技能加载方式加载 [SKILL.md](SKILL.md)。

## 验证与技术文档

已通过 160 项离线测试，并用真实单聊、群聊快照验证；其中 11 条独立样本与客户端正文逐字节一致。详细范围、未解决项及历史验证记录见 [验证说明](references/automation.md#目前的验证结论2026-10-18)。

```text
python -m unittest discover -s tests -v
```

开发者可继续阅读 [本地解密路径](references/client-paths.md)。[已加载正文采集工具](skills/dingtalk-plaintext-harvest/SKILL.md) 仅用于辅助观察；日常读取使用上面的统一入口。

聊天数据、密钥和运行缓存不提交到本仓库，也不随技能同步。
