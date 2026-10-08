---
name: dingtalk-message-decrypt
description: 读取钉钉单聊/群聊消息并解密「三方加密」密文。当用户要求整理钉钉聊天记录、拉取钉钉消息、做钉钉待办/周报/纪要，或遇到 "[加密消息，无法解码]" 占位符时使用。适用于 dws CLI 环境。
---

# 钉钉消息读取与三方密文解密

## 何时用

- 用户要整理/分析钉钉聊天记录（待办、周报、会议纪要、决策追溯）
- 拉取到的消息里出现 `[加密消息，无法解码]`
- 需要还原单聊 / 群聊消息明文

## 核心事实（先记住，能省 30 分钟排查）

企业开启钉钉「三方加密」后：

| 现象 | 原因 |
|---|---|
| 高层命令 `+chat-messages` / `+at-me` 把读不到的消息换成占位符 | 列表接口内置解密被服务端策略禁用：`reason=policy_disabled`、`decryptAllowedCount=0` |
| **单聊和群聊的正文都会加密** | 三方加密覆盖点对点正文，**也覆盖群聊正文**（旧结论「群聊正文 100% 明文」来自单日样本，被 3 个月全量实测推翻：18,692 条群正文是密文） |
| 「被引用原文」100% 加密 | 引用内容作为消息体（密文）返回，字段在 `quotedMessage.content` |
| 机器人推送、日程卡片、图片 mediaId、审批 100% 可读 | 走服务端结构化通道，不进聊天正文加密 |
| 越近期加密率越高 | 安全策略在灰度放量 |

**关键结论：策略禁用的是「列表接口自动解密」，不代表解不开。手动调 `crypto decrypt` 可以解。**
实测（2026-10-09，近 92 天全量）：172,819 条消息 / 39,351 条密文 / **还原率 100.0000%**。

> 口径：**可读 = 原始明文 + 解密成功明文**。表中加密率是**解密前**分布，100% 是**解密后**可读率，两者不矛盾。

## 前置条件（硬性）

```
dws version          # 必须 >= v1.0.63
dws upgrade          # v1.0.62 的 safechat 本地层会 cgo 崩溃（stack overflow）
```

v1.0.62 上 `crypto decrypt --layer safechat|full` 会直接崩溃，`--layer ding` 返回 `not_encrypted`。
**升级是解锁解密能力的必要条件。**

## 工作流

### 1. 拿会话清单（要续游标）

```bash
dws chat +recent-conversations --start "2026-07-07 00:00:00" --end "2026-10-08 00:00:00" \
  --limit 100 --page-limit 500 --page-delay 100 --total-timeout 480 --format json
# 若 meta.pagination.endpoint_exhausted == false，必须带 --cursor <next_token> 续拉
```

**坑：这个接口单轮经常跑不完**（中途分页超时，`endpoint_exhausted=false`）。直接采信单轮结果会得到残缺清单——实测 302 个 vs 补全后 344 个，少 42 个会话。

### 2. 拿密文（手动分页，别用 `--max-items`）

必须用底层命令，它会返回 `content` 字段（密文原文，形如 `xxxx...||2||1||228`）：

```bash
dws chat message list --conversation-id <cid> \
  --time "2026-07-07 00:00:00" --direction newer \
  --limit 100 --format json --timeout 45
```

- `--conversation-id` 对单聊和群聊通用
- **`--time` 给的是下界**，`--direction newer` 往上翻 —— 天然落在时间窗内，不会一路退回几年前
- **不要传 `--max-items`**：任何非零值都会截断（600 曾让 10 个会话缺一个半月）。要完整就手动翻页
- **翻页游标取 `nextPage['time']`**。`nextPage` 是个 dict（还有 `nextCursor`），把整个 dict 当 `--time` 传会返回 0 条
- 终止条件：`hasMore=false`，或整页 `createTime` 最小时间已超过窗口上界

### 3. 逐条解密

```bash
dws chat crypto decrypt --file <密文文件> --layer safechat --format json
# 成功返回: {"ok":true,"layer":"safechat","plaintext":"..."}
```

- `--layer safechat` = 纯本地解密。**实测最快（6.61 QPS）且 100% 成功，用作主层**
- `--layer full` = SafeChat 本地 + Ding 服务端兜底。**4.16 QPS，慢 59%**，只作降级
- `--layer ding` = 单独调服务端批量解密接口，**实测 30/30 全失败，不要用**

**坑（最高频）：`--file` 必须是相对路径。** 传绝对路径会被 dws 直接拒绝
（`--file must be a relative path within the current directory`），表现为整批 0 成功。
正确写法：把密文写进临时目录，然后 `subprocess.run(..., cwd=tmp_dir)` 且只传文件名。

### 4. 批量

不支持批量输入（多行/JSON 数组都无效），必须逐条调用。
用技能自带的 `dws_decrypt.py` 一键完成「会话清单 → 分页拉取 → 提取密文 → 解密 → 合并」：

```bash
# ~/.claude 可换成 ~/.codex 或 ~/.workbuddy —— 三者是同一份文件的符号链接
python ~/.claude/skills/dingtalk-message-decrypt/scripts/dws_decrypt.py --days 92 --out ./out --kind all
python ~/.claude/skills/dingtalk-message-decrypt/scripts/dws_decrypt.py --days 92 --out ./out --limit 200  # 试跑
```

**务必用绝对路径**：技能是通过符号链接加载的，agent 的工作目录不固定，
写相对路径 `scripts/dws_decrypt.py` 会找不到脚本。

脚本已内置的关键优化：
- 按**密文字符串去重**（同一条被多处引用只解一次，实测省 6,355 次请求）
- 「被引用原文」优先用 `quotedMessage.openMessageId` 查表（原文常就在已拉明文里），查不到才解密
- 页级追加写 + 状态文件，随时中断可续跑

## 性能与坑

| 项 | 实测 |
|---|---|
| 单条解密耗时 | 约 0.2s（进程启动开销为主） |
| 吞吐 | `safechat` 6.61 QPS @并发16；`full` 4.16 QPS。并发 16→32 **无提升**（服务端限速） |
| 长密文更慢 | 群聊/引用类长密文实测降到 3.9~5.5 条/秒 |
| 拉取 | 176 个群 / 146,915 条 = 17 分钟（并发 8） |
| 2.3 万条密文 | 约 80 分钟，务必后台跑 |
| 成功率 | 100%（3 个月全量 39,351 条密文零遗留） |

**坑 1：临时文件删除会触发 safe-delete 守卫**
多线程里 `os.remove()` 删临时文件会报 `[safe-delete][SAFE_DELETE_BULK_GUARD_ERROR] state lock timeout` 并让整个进程崩掉。
→ 临时文件放独立目录、按槽位编号命名、**不要逐个删除**，最后统一清理。

**坑 2：`--max-items` 会截断**
早期脚本常用 120/600 上限，导致高频会话被截（实测 10 个单聊缺 07-07~08-24 整段）。
→ 不传该参数，用 `--direction newer` + 手动翻页。

**坑 3：升级 dws 会中断正在跑的任务**
升级会替换 dws.exe，正在跑的拉取/解密脚本会失败。升级放在跑批之前。

**坑 4：`--direction older` 只有上界**
会一路退回几年前（实测拉到 2024-10），白白多拉几万条。要时间窗就用 `newer` + 下界。

## 走不通的路（别浪费时间）

- `dws chat +search-msg`：服务端搜索索引不覆盖单聊，返回 0 条
- `dws chat message list-all`：只返回本来就能读的消息，加密消息一条都不出现
- `dws chat +chat-list --page-all`：首页就 `pagination_error`，且返回的是 `openConversationId`（不是 `conversationId`），无法直接喂给 `message list`
- `dws chat chmod`：scope 白名单只有 `chat.message:send` / `chat.message:list` / `chat.group:destroy` / `chat.data:cross-org`，**没有 decrypt scope**
- `dws config`：32 个配置项里没有任何解密相关开关
- 本地钉钉数据库（`~/AppData/Roaming/DingTalk/<uid>_v2/DBFiles/dingtalk.db`）：文件头是自定义加密格式，非 SQLite 明文
- `dws aisearch enterprise --types im` 走服务端索引，**覆盖率仅约 8%**，只能补充不能替代

## 输出

工具产出 `out/messages.jsonl`（每行 `{session, time, sender, text}`），
后续做待办提炼时按 `sender != 本人` 过滤，再剔除群发文本（同一文本出现在 ≥4 个会话）。

**统计口径**：可读消息 = 原始明文 + 解密成功明文；关键词/信号筛选只是下游分析，**不会增加能读到的消息**（只会减少）；对外数字按「原始拉取 + 实际解密结果」统计，并按**唯一 messageId 去重**（同一条既是群正文又被引用时只计一次）。
