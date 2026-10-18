# dingtalk-message-decrypt

给 agent 使用的钉钉消息批处理技能：读取原始消息、处理三方密文、保存进度和缓存，输出可读内容及未解决项。批处理阶段不调用大模型，模型只需读取汇总并分析需要的正文。

服务端 `full` 返回 `CRYPTO_DISABLED` 时会记住状态，停止无效重试，并自动尝试已验证的 Windows 本地解密链路。它将 dws SafeChat 中间信封交给确定性 DING 解码器，以明确企业和版本的客户端缓存 key 解密，key不落盘。消息不必显示在当前界面。缺key、缺身份或未知客户端版本仍保留缺口；旧版把中间信封当明文的“100%”结论已撤回。

## 使用

需要 Python 3.10+，已安装并登录的 dws >=1.0.63。本地解密另需 `pefile`、PyCryptodome及已登录的已验证版本 Windows 钉钉。不会自动安装、切账号或更改钉钉配置。

```text
python scripts/dws_decrypt.py --input raw.json --out out --scope my-work
python scripts/dws_decrypt.py --conversation-id <真实CID> --days 30 --out out-chat --scope my-work
python scripts/dws_decrypt.py --days 92 --kind all --out out-all --scope my-work
python scripts/dws_decrypt.py --out out-all --scope my-work --resume
```

已确认服务端策略关闭时加 `--known-policy-disabled`，同一输出目录之后自动记住；离线检查加 `--server off --client off`。账号切换后必须换 scope 和输出目录，标签不替代真实账号选择。

读取 `summary.json` 获取数量和缺口，`messages.jsonl` 获取可读正文；`resolved.jsonl` 保留原始输入和独立解析结果。退出码 0 / 2 / 1 分别表示提供记录已解决、部分完成、执行错误。导入快照的分页完整性仍为 unknown。

本地解密缓存按 scope、CID、密文及显式企业身份隔离，重放标记为 `decrypted_local_cache`，保留 `enterprise`、`key_version`、`identity_source` 和原始解密来源，不计作本轮重新解密。旧缓存只有在同 scope 的 `resolved.jsonl` 提供匹配的消息身份、密文哈希和正文时才恢复本地来源；仅有旧缓存正文不能推断来源。已有原始输入与合法缓存时，用 `--input raw.json --server off --client off` 可纯离线重放，不需要打开目标会话。

[SKILL.md](SKILL.md) 是 agent 入口；详细参数、输出和限制见 [automation.md](references/automation.md)。

## 安装与路由

仓库访问由 owner 授权。源码保留在 Git 仓库，部署主源为 `~/.agents/skills/dingtalk-message-decrypt`，`.codex`、`.claude`、`.workbuddy` 通过链接跟随。

已有部署升级：

```bash
bash sync_to_agents.sh
```

首次部署可检查并运行 `install.sh`。安装脚本会创建三处宿主链接，已有同名实体目录应先保存；升级只用同步脚本。

如 dws 聊天技能没有解密路由，可明确指定文件安装（文件首次修改前会保存备份，重复执行幂等）：

```text
python scripts/install_routes.py --skill-file <dingtalk-chat/SKILL.md>
```

对独立 dws 单技能入口可重复传 `--skill-file`。此路由仅影响聊天记录读取。上游重装若覆盖路由需重跑；不替换 dws 可执行文件。不同 agent 必须实际加载技能后才会遵循此流程，不能保证所有未知 agent 自动使用。

## 验证

```text
python -m unittest discover -s tests -v
```

测试用合成数据/fake runner，验证分页恢复、重复记录、引用、策略熔断、缓存隔离、信封拒绝和客户端身份边界，不调用模型或在线接口。

真实算法验证：11条不同消息通过原始密文→SafeChat信封→本地DING解密，全部与独立保存的客户端正文逐字节一致，其中1条曾由用户核对。生产入口也通过该确认样本。测试并不代表所有企业、历史版本或单聊已覆盖，具体运行看summary中的来源和缺口。

整批生产快照：273条原始记录，126条原始明文加133条本地解密正文，共259条可读正文；29条加密引用亦解决。14条空正文和1条空引用保留未解决。服务端full调用0，SafeChat调用133次、会话身份查询1次，未扫描界面消息。160项离线回归测试通过。

单聊也已接入自动路径：缺消息oid时，一次扫描精确CID的原生会话组织元数据，只有完整、稳定且无分歧的候选才采用。两个单聊28条近期记录中16条密文正文与4条密文引用恢复，共27条可读正文、1条空内容；无需打开或逐条阅读。当前会话身份不证明所有历史归属稳定，缺候选或身份冲突仍保留未解决。

扩大历史验证：三个单聊1456条输入（记录日期跨度2024-10-08至2026-10-06，导入快照不表示该跨度完整），1174条密文正文和77条密文引用全部恢复，加245条原始明文，共1419条可读正文。37条空正文和2条空引用仍未解决，剩余密文为0。full调用0、SafeChat调用1174、会话查询3次、身份扫描1次；不需正文观察或界面操作。

缓存升级另在原批次副本验证：`--server off --client off` 成功迁移133条本地缓存，259条可读正文按原顺序、CID和消息ID逐条相同，133条正文与29条引用的企业、版本及身份来源保留。运行禁止外部进程调用，原批次文件哈希未变；原有15个未解决字段仍保留，离线重放没有新增可读消息。

聊天原文、密文、SQLite 缓存及运行日志不进入 Git，也不随技能同步。历史旧脚本仅保留在 `scripts/legacy/` 供审计，不作为运行入口。
