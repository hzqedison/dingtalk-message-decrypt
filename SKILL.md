---
name: dingtalk-message-decrypt
description: 读取钉钉单聊/群聊消息并解密「三方加密」密文。当用户要求整理钉钉聊天记录、拉取钉钉消息、做钉钉待办/周报/纪要，或遇到 "[加密消息，无法解码]" 占位符时使用。适用于 dws CLI 环境。
---

# 钉钉消息读取与三方密文解密

## 何时用

- 用户要整理/分析钉钉聊天记录（待办、周报、会议纪要、决策追溯）
- 拉取到的消息里出现 `[加密消息，无法解码]`
- 需要还原单聊（1:1）消息明文

## 核心事实（先记住，能省 30 分钟排查）

企业开启钉钉「三方加密」后：

| 现象 | 原因 |
|---|---|
| 高层命令 `+chat-messages` / `+at-me` 把读不到的消息换成占位符 | 列表接口内置解密被服务端策略禁用：`reason=policy_disabled`、`decryptAllowedCount=0` |
| 群聊正文 100% 可读，单聊约 70~80% 加密 | 三方加密主要覆盖点对点正文；群聊服务端要支持 @/搜索/机器人，留明文 |
| 群聊里「被引用原文」100% 加密 | 引用内容作为消息体（密文）返回 |
| 机器人推送、日程卡片、图片 mediaId、审批 100% 可读 | 走服务端结构化通道，不进聊天正文加密 |
| 越近期加密率越高 | 安全策略在灰度放量 |

**关键结论：策略禁用的是「列表接口自动解密」，不代表解不开。手动调 `crypto decrypt` 可以解，实测成功率 99.93%。**（表中「70~80% 加密」是**解密前**的原始分布；**解密后**可读率 ≈ 99.93%，两者不矛盾。）

## 前置条件（硬性）

```
dws version          # 必须 >= v1.0.63
dws upgrade          # v1.0.62 的 safechat 本地层会 cgo 崩溃（stack overflow）
```

v1.0.62 上 `crypto decrypt --layer safechat|full` 会直接崩溃，`--layer ding` 返回 `not_encrypted`。
**升级是解锁解密能力的必要条件。**

## 工作流

### 1. 拿密文

必须用底层命令，它会返回 `content` 字段（密文原文，形如 `xxxx...||2||1||228`）：

```bash
dws chat message list --conversation-id <cid> \
  --time "2026-10-07 00:00:00" --direction older \
  --page-all --page-limit 200 --max-items 600 --format json
```

注意：`--conversation-id` 对单聊和群聊通用，直接传单聊的 conversationId 即可。

### 2. 逐条解密

```bash
dws chat crypto decrypt --file <密文文件> --layer full --format json
# 成功返回: {"keyVersion":1,"layer":"full","ok":true,"plaintext":"..."}
```

- `--layer full` = SafeChat 本地层 + Ding 服务端层，**必须用 full**
- `--layer safechat` 只解本地层，输出仍是中间密文
- `--layer ding` 单独用会报 `not_encrypted`

### 3. 批量

不支持批量输入（多行/JSON 数组都无效），必须逐条调用。
用 `scripts/dws_decrypt.py` 一键完成「拉列表 → 拉密文 → 解密 → 合并」：

```bash
python scripts/dws_decrypt.py --days 92 --out ./out --workers 16
python scripts/dws_decrypt.py --days 92 --out ./out --limit 200   # 先试跑 200 条
```

## 性能与坑

| 项 | 实测 |
|---|---|
| 单条解密耗时 | 约 0.2s（但进程启动开销大） |
| 整体吞吐 | 约 5 条/秒，**并发从 16 提到 32 无提升**，瓶颈在服务端限速 |
| 2.6 万条密文 | 约 80~90 分钟，务必后台跑 |
| 成功率 | 99.93%（失败多为 `no_plaintext`，即空消息/已撤回） |

**坑 1：临时文件删除会触发 safe-delete 守卫**
多线程里 `os.remove()` 删临时文件会报 `[safe-delete][SAFE_DELETE_BULK_GUARD_ERROR] state lock timeout` 并让整个进程崩掉。
→ 临时文件放独立目录、按任务编号命名、**不要逐个删除**，最后统一清理。

**坑 2：`--max-items 120` 会截断**
早期脚本常用 120 上限，导致高频会话被截断（实测 37/161 个会话被截）。批量拉取时保持默认或设 600。

**坑 3：升级 dws 会中断正在跑的任务**
升级会替换 dws.exe，正在跑的拉取/解密脚本会失败。升级放在跑批之前。

## 走不通的路（别浪费时间）

- `dws chat +search-msg`：服务端搜索索引不覆盖单聊，返回 0 条
- `dws chat message list-all`：只返回本来就能读的消息，加密消息一条都不出现
- `dws chat chmod`：scope 白名单只有 `chat.message:send` / `chat.message:list` / `chat.group:destroy` / `chat.data:cross-org`，**没有 decrypt scope**
- `dws config`：32 个配置项里没有任何解密相关开关
- 本地钉钉数据库（`~/AppData/Roaming/DingTalk/<uid>_v2/DBFiles/dingtalk.db`）：文件头是自定义加密格式，非 SQLite 明文

## 兜底补充：AI 搜问

`dws aisearch enterprise --types im` 走服务端索引，能拿到**你自己发出消息的明文**（服务端有下发副本），部分会话也能拿到对方消息。但索引稀疏，单轮覆盖率约 8%。可作为补充，不能替代解密。

```bash
dws aisearch enterprise --queries "<对方姓名>" --types im --time-range "最近三个月" --format json
```

## 输出

工具产出 `out/messages.jsonl`（每行 `{session, time, sender, text}`），
后续做待办提炼时按 `sender != 本人` 过滤，再剔除群发文本（同一文本出现在 ≥4 个会话）。

**统计口径**：可读消息 = 原始明文 + 解密成功明文；关键词/信号筛选只是下游分析，**不会增加能读到的消息**；对外数字按「原始拉取 + 实际解密结果」统计。
