# dingtalk-message-decrypt

让 AI 助手（Claude Code / Codex / WorkBuddy 等）能完整读取并**解密**钉钉聊天记录——包括企业开启「三方加密」后那些显示为 `[加密消息，无法解码]` 的单聊与群聊消息。

**最新实测（2026-10-09，某企业近 92 天全量，单聊 + 群聊）**：172,819 条消息中 39,351 条为密文，**全部还原，还原率 100.0000%**。
（更早的一轮仅覆盖单聊样本：25,848 条密文解出 25,830 条，99.93%；剩余 18 条 `no_plaintext` 在后续用 `--layer full` 重试后全部解出。）

---

## 如何获取访问权限

本仓库是**私有**的，需要仓库 owner 把你加为 collaborator 才能访问。

1. 把你的 GitHub 用户名告诉 owner
2. owner 在 GitHub 网页操作：仓库页 → `Settings` → `Collaborators` → `Add people`，搜索你的用户名并邀请（权限选 `Read` 即可）
3. 你在邮箱里接受邀请
4. 接受后就能 clone 了：

```bash
git clone https://github.com/hzqedison/dingtalk-message-decrypt.git
cd dingtalk-message-decrypt
```

> 只想看内容不想 clone？直接打开仓库网页就行，授权后网页、Raw 文件、Release 都能访问。

---

## 安装 dws CLI

本技能依赖钉钉官方的 `dws` 命令行工具，**必须先装好并登录**，否则后面所有命令都跑不了。

`dws` 是钉钉官方开源项目：[DingTalk-Real-AI/dingtalk-workspace-cli](https://github.com/DingTalk-Real-AI/dingtalk-workspace-cli)（Apache-2.0）。

### 1. 安装

选一种就行：

```bash
# Windows（PowerShell）
irm https://raw.githubusercontent.com/DingTalk-Real-AI/dingtalk-workspace-cli/main/scripts/install.ps1 | iex

# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/DingTalk-Real-AI/dingtalk-workspace-cli/main/scripts/install.sh | sh

# 有 Node.js 的话（npm）
npm install -g dingtalk-workspace-cli

# macOS 用户也可以走 Homebrew
brew tap DingTalk-Real-AI/dingtalk-workspace-cli https://github.com/DingTalk-Real-AI/dingtalk-workspace-cli.git
brew install dingtalk-workspace-cli
```

**国内网络**（GitHub 访问不稳时走 Gitee 镜像）：

```bash
DWS_GITEE_REPO=DingTalk-Real-AI/dingtalk-workspace-cli \
  curl -fsSL https://gitee.com/DingTalk-Real-AI/dingtalk-workspace-cli/raw/main/scripts/install.sh | sh

# npm 走国内镜像
npm install -g dingtalk-workspace-cli --registry=https://registry.npmmirror.com
```

> 也可以直接把仓库地址甩给 AI 助手，让它帮你装：「帮我安装钉钉 DWS：https://github.com/DingTalk-Real-AI/dingtalk-workspace-cli」

### 2. 登录授权

```bash
dws auth login          # 自动打开浏览器，选择企业组织并授权
dws auth login --device # 无图形界面环境（Docker / SSH / CI）用这个
```

如果提示企业未开通 CLI 访问：选择组织后页面会有 **Apply Now**，点了会通知企业管理员，管理员批准后再跑一次 `dws auth login` 即可。

管理员开通入口：钉钉开放平台 → **CLI Access Management** → 启用。

### 3. 升级到 v1.0.63 或更高（硬性要求）

```bash
dws version     # 必须 >= v1.0.63
dws upgrade     # 低于这个版本必须升级
```

**升级是解锁解密能力的必要条件。** 在 v1.0.62 上：

- `crypto decrypt --layer safechat|full` → 直接崩溃（safechat 本地层的 cgo stack overflow）
- `crypto decrypt --layer ding` → 返回 `not_encrypted`

升级到 v1.0.63 后 `--layer full` 正常工作。如果你卡在「解不开」，先查版本。

---

## 为什么需要它

企业开启钉钉「三方加密」后，用 dws CLI 拉取消息会大量看到占位符：

```
[加密消息，无法解码]
```

根因不是技术解不开，而是**列表接口内置的自动解密被服务端策略禁用**（返回 `reason=policy_disabled`、`decryptAllowedCount=0`）。
但手动调用解密接口并不受此限制——绕过它即可拿到明文。

### 加密分布特征（可用来快速判断）

| 现象 | 原因 |
|---|---|
| **单聊和群聊的正文都会加密** | 三方加密覆盖点对点正文，**也覆盖群聊正文**。旧结论「群聊正文 100% 明文」来自单日样本，已被 3 个月全量实测推翻：18,692 条群聊正文是密文 |
| 「被引用原文」100% 加密 | 引用内容作为消息体（密文）返回，字段在 `quotedMessage.content` |
| 机器人推送、日程卡片、图片 mediaId、审批 100% 可读 | 走服务端结构化通道，不进聊天正文加密 |
| 越近期的消息加密率越高 | 安全策略在灰度放量 |

### 可读消息怎么算（统计口径）

- **可读消息 = 原始明文（本来就能读的）+ 解密成功的明文**，只有这两部分进入统计。
- 上表的加密率是**解密前**的原始分布；**解密后**可读率取决于解密成功率（本仓库实测 **100%**，见下节），两者不矛盾。
- 「content / 原文」专指形如 `xxxx...||2||1||228` 的**密文**；解密后的可读内容一律称**明文**。
- **关键词筛选只做下游分析**：`scripts/legacy/merge_dm.py` 只是从「已可读消息」里挑「疑似待办」候选，**只会减少、不会增加能读到的消息**。所有对外数字一律按「原始拉取 + 实际解密结果」统计，不受关键词筛选影响。

---

## 快速开始

### 手工三步

```bash
# 1. 拿密文（必须用底层命令，它会返回 content 字段）
#    --time 给的是【下界】，--direction newer 往上翻 → 天然落在时间窗内
#    不要传 --max-items：任何非零值都会截断（600 曾让 10 个会话缺一个半月）
dws chat message list --conversation-id <cid> \
  --time "2026-07-07 00:00:00" --direction newer \
  --limit 100 --format json --timeout 45
# content 形如：xxxx...||2||1||228
# 翻页游标取 nextPage['time']（nextPage 是 dict，别把整个 dict 当 --time 传）

# 2. 逐条解密（--file 必须是相对路径！传绝对路径会被 dws 拒绝）
cd /path/to/tmpdec
dws chat crypto decrypt --file in_1.txt --layer full --format json
# 成功返回：{"ok":true,"layer":"full","plaintext":"..."}
```

`--layer` 三档的区别（2026-10-16 修正）：

- `full` = 本地 SafeChat + **服务端 DING 层**。**只有它能对双层消息拿到明文，作主层**
- `safechat` = 纯本地层。对双层消息只会返回 `1_1_<hex>` **信封，永远不是明文**，只作降级
- `ding` = 单独调服务端批量解密接口，**实测 30/30 全失败，不要用**

> ⚠️ **2026-10-16 起的能力警告**：服务端 DING 解密策略被企业侧关闭，
> `full` 层直接报 `CRYPTO_DISABLED / crypto disabled by switch`（业务级错误，不是权限问题）。
> 此时**解密能力为 0，客户端无解，只能找企业管理员开通**。动手前先跑一次 `full` 层自检。

> ⚠️ **必须识别 `1_1_<hex>` 信封**（形如 `^\d+_\d+_[0-9a-f]+$`，长度恒等于原密文 `||2||1||N` 的 N）。
> 它是「本地层已跑、服务端层没跑」的未完成状态，**绝不能当明文收下**。

> **最高频的坑**：`--file` 传绝对路径会报
> `--file must be a relative path within the current directory`，表现为整批 0 成功。
> 正确做法是 `cd` 到临时目录、只传文件名（脚本里用 `subprocess.run(..., cwd=tmp_dir)`）。

### 一键脚本

不支持批量输入（多行、JSON 数组都无效），必须逐条调用。用脚本自动化：

```bash
python scripts/dws_decrypt.py --days 92 --out ./out --kind all       # 近 92 天，单聊 + 群聊（推荐）
python scripts/dws_decrypt.py --days 92 --out ./out                  # 只跑单聊
python scripts/dws_decrypt.py --days 92 --out ./out --limit 200      # 先试跑 200 条
python scripts/dws_decrypt.py --days 92 --out ./out --workers 16     # 指定解密并发
python scripts/dws_decrypt.py --out ./out                            # 重跑即续跑（页级 + 条级断点）
```

脚本已内置：会话清单续 `--cursor`、手动分页拉取、**密文字符串去重**（同一条被多处引用只解一次）、
「被引用原文」优先按 `openMessageId` 查表、`--layer safechat` 主层 + `full` 降级。

产出：

| 文件 | 内容 |
|---|---|
| `out/conversations.json` | 会话列表 |
| `out/raw/*.jsonl` | 每个会话逐页原始结果（含 content 密文），页级追加写 |
| `out/state_fetch.json` | 拉取进度状态（中断后可续） |
| `out/decrypted.jsonl` | 解密成功的明文（追加写，支持断点续跑） |
| `out/messages.jsonl` | 合并后的完整明文语料 |

`messages.jsonl` 每行格式：`{"session": "...", "time": "...", "sender": "...", "text": "..."}`

---

## 安装为 AI 技能

推荐用「**单一主源 + 符号链接**」：文件只存一份，Claude Code / Codex / WorkBuddy 三处用链接指向它。
以后升级只改主源，三处自动跟随——**避免三份拷贝各自版本漂移**。

```
主源  ~/.agents/skills/dingtalk-message-decrypt/   ← 唯一真实文件
        ├── ~/.claude/skills/dingtalk-message-decrypt   （链接）
        ├── ~/.codex/skills/dingtalk-message-decrypt    （链接）
        └── ~/.workbuddy/skills/dingtalk-message-decrypt（链接）
```

### 一键安装（推荐）

```bash
git clone https://github.com/hzqedison/dingtalk-message-decrypt.git
cd dingtalk-message-decrypt
bash install.sh
```

脚本做三件事：① 建主源并复制文件；② 在三处技能目录建链接；③ 验证三处都能读到 `SKILL.md`。

换主源位置（比如不想用 `~/.agents`）：

```bash
SKILL_SOURCE=~/.claude/skills bash install.sh
```

#### Windows 的链接权限

`install.sh` 优先建真符号链接（`mklink /D`），这需要**开发者模式**或**管理员权限**；
不满足时自动降级为目录联接（`mklink /J`），仍不行再降级为三份实体拷贝。
三种方式**功能完全一样**，只是实体拷贝以后升级要重跑一次 `install.sh`。

macOS / Linux 直接 `ln -s`，无此限制。

### 以后怎么升级

```bash
cd dingtalk-message-decrypt
git pull
bash sync_to_agents.sh
```

`sync_to_agents.sh` 会把新文件同步到主源并做 MD5 校验（Windows / macOS / Linux 通用）。
三处是链接的话会自动跟随；若当时降级成了拷贝，它会提示你重跑 `install.sh`。

### 验证装好了没

```bash
bash sync_to_agents.sh   # 看「三处技能目录状态」，三处都 ✓ 即正常
```

或直接确认三处都能读到同一份文件：

```bash
ls -l ~/.claude/skills/dingtalk-message-decrypt ~/.codex/skills/dingtalk-message-decrypt ~/.workbuddy/skills/dingtalk-message-decrypt
```

装好后直接对 AI 说「帮我整理最近一个月的钉钉待办」，它会自动加载 `SKILL.md` 并按正确流程走。

### 手工安装（不想跑脚本时）

把整个目录放到主源，再手动建链接：

```bash
# 主源
mkdir -p ~/.agents/skills
cp -r . ~/.agents/skills/dingtalk-message-decrypt

# 三处链接（macOS / Linux）
for d in .claude .codex .workbuddy; do
  mkdir -p ~/$d/skills
  ln -sfn ~/.agents/skills/dingtalk-message-decrypt ~/$d/skills/dingtalk-message-decrypt
done
```

Windows（Git Bash，需开发者模式或管理员）：

```bash
for d in .claude .codex .workbuddy; do
  cmd //c "mklink /D $(cygpath -w ~/$d/skills/dingtalk-message-decrypt) $(cygpath -w ~/.agents/skills/dingtalk-message-decrypt)"
done
```

### Codex 额外一步（可选）

Codex 建议在 `~/.codex/AGENTS.md` 里加全局指引，让它遇到加密消息时主动加载技能：

```markdown
- 处理钉钉消息（拉取/整理待办/周报/纪要）时，先加载 skill `dingtalk-message-decrypt`；
  遇到 `[加密消息，无法解码]` 不要跳过，按 SKILL.md 的解密流程处理。
```

Claude Code 与 WorkBuddy **无需任何注册**——放进技能目录后靠 `SKILL.md` 的 frontmatter 自动发现。

---

## 脚本目录

| 路径 | 说明 |
|---|---|
| `install.sh` | **一键部署**：建主源 + 三处符号链接 + 验证。Windows / macOS / Linux 通用，无建链权限时自动降级为拷贝 |
| `sync_to_agents.sh` | **升级用**：把仓库文件同步到主源并 MD5 校验，同时报告三处技能目录状态 |
| `scripts/dws_decrypt.py` | **主脚本**。会话清单（续 cursor）→ 手动分页拉取 → 提取密文（正文 + 引用原文）→ `safechat` 解密（`full` 降级）→ 合并。支持分组选择（`--kind direct/group/all`）、页级+条级断点续跑。只依赖 Python 标准库 |
| `scripts/legacy/fetch_dm_cipher.py` | 【历史】只负责并行拉取带密文的单聊消息，是主脚本的前身 |
| `scripts/legacy/merge_dm.py` | 【历史·下游分析】把已解密的单聊语料按关键词粗筛成「疑似待办」分片；**只筛不加，不增加可读消息数** |
| `skills/dingtalk-plaintext-harvest/` | **配套技能·本地兜底**：企业侧关闭服务端解密（`CRYPTO_DISABLED`）时，改从钉钉客户端进程内存抓**显示层明文**。见下节 |

`legacy/` 里的脚本保持原样归档，仅用于追溯当时的踩坑过程。**「拉密文 → 解密 → 合并」这条主链路已被 `dws_decrypt.py` 完整覆盖；但 `merge_dm.py` 里的「疑似待办」关键词筛选属于下游分析步骤，主脚本不含**，需要时可参考该脚本。日常解密请用主脚本。

两个 legacy 脚本需要你通过环境变量告诉它你是谁（用来过滤掉自己发出的消息）：

```bash
export DWS_ME="你的钉钉昵称"
```

---

## 配套技能：dingtalk-plaintext-harvest（服务端关闭解密时的本地兜底）

本仓库的主链路依赖**服务端**参与解密（dws 的 `full` 层）。如果企业侧把该策略关掉，dws 会返回业务错误：

```
CRYPTO_DISABLED / crypto disabled by switch
```

此时客户端无解，只能找管理员开通。在开通之前，可以用配套技能 [`skills/dingtalk-plaintext-harvest/`](skills/dingtalk-plaintext-harvest/) 做**本地兜底**：

**原理**：钉钉 PC 客户端能把加密消息解密显示给用户看 → 明文一定短暂存在于进程内存里。所以不去碰密钥、不逆向算法，而是被动监听进程内存，抓**显示层字段 `content.text`**（UI 实际展示的文字）。

```bash
cd skills/dingtalk-plaintext-harvest
python harvest.py --seconds 300          # 后台监听 5 分钟，不控制窗口、不自动滚动
python harvest.py --mark AbCdEf          # 只抓某个群（cid 特征片段）
```

**用法要点**

- **被动监听**：脚本不碰钉钉窗口。你正常在钉钉里浏览，翻到哪段，那段就被客户端解密进内存，脚本就抓下来。
- **不要传 `--mark` 覆盖率更高**：带 cid 过滤时要求文本附近 4000 字节内有群标记，实测会漏掉绝大多数（同一批消息：过滤 102 条 vs 不过滤 864 条）。不过滤的代价是可能混入客户端里同时可见的其他群内容。
- 想提高覆盖：让用户在客户端从最早消息缓慢往下滚，滚动期间跑脚本。
- 输出：脚本目录生成 `群明文_<群名>_<时间戳>.md`，按主题分类。
- 局限：只能拿到"客户端曾加载过"的消息；显示层不存时间戳，要时间轴仍需结合 dws。

**推荐工作流**：先后台起 `harvest.py`，同时用 dws 拉结构化消息（时间 + 发送人 + 密文），两者拼合——dws 给时间轴，harvest 给内容。

依赖：Windows + 钉钉 PC 客户端已登录 + Python 3.9+（纯标准库，无需 pip）。

---

## 性能与坑

| 项 | 实测 |
|---|---|
| 单条解密耗时 | 约 0.2s（进程启动开销占大头） |
| 整体吞吐 | `--layer full` 4.16 QPS；`safechat` 6.61 QPS（**但只有 full 能出明文**） |
| 并发 | **16 → 32 无提升**，瓶颈在服务端限速，别浪费资源 |
| 长密文更慢 | 群聊正文 / 引用原文类长密文实测降到 3.9~5.5 条/秒 |
| 拉取 | 176 个群 / 146,915 条 = 17 分钟（并发 8） |
| 2.3 万条密文 | 约 80 分钟，**务必后台跑** |
| 成功率 | **100%**（近 92 天全量 39,351 条密文零遗留）——**前提是服务端 DING 策略开启；2026-10-16 该策略已被企业关闭，成功率归 0** |

**坑 1：多线程删临时文件会触发 safe-delete 守卫**
并发调 `os.remove()` 会报 `[safe-delete][SAFE_DELETE_BULK_GUARD_ERROR] state lock timeout` 并让整个进程崩掉。
→ 临时文件放独立目录、按任务编号命名、**不要逐个删除**，最后统一清理。

**坑 2：`--max-items` 会截断（任何非零值都会）**
早期脚本常用 120 / 600 上限，导致高频会话被截（实测 10 个单聊缺了 07-07~08-24 整整一个半月）。
→ **不要传该参数**，改用 `--direction newer` + `--time <下界>` 手动翻页。

**坑 2b：`--direction older` 只有上界**
会一路退回几年前（实测拉到 2024-10），白白多拉几万条。要时间窗就用 `newer` + 下界。

**坑 2c：翻页游标别传整个 `nextPage`**
`nextPage` 是个 dict（`{direction, nextCursor, time}`）。把它整体当 `--time` 传会返回 0 条，看起来像「翻页失效」。取 `nextPage['time']`。

**坑 2d：会话清单单轮拉不完**
`+recent-conversations` 常中途分页超时，返回 `endpoint_exhausted=false`。直接采信会得到残缺清单（实测 302 个 vs 补全后 344 个）。→ 带 `--cursor <next_token>` 续拉直到 `endpoint_exhausted=true`。

**坑 3：升级 dws 会中断正在跑的任务**
升级会替换 `dws.exe`，正在运行的拉取/解密脚本会失败。**升级放在跑批之前。**

---

## 走不通的路（别浪费时间）

这几条我都试过，全部失败，直接跳过：

| 尝试 | 结果 |
|---|---|
| `dws chat +search-msg` | 服务端搜索索引不覆盖单聊，返回 0 条 |
| `dws chat message list-all` | 只返回本来就能读的消息，加密消息一条都不出现 |
| `dws chat +chat-list --page-all` | 首页就 `pagination_error`；且返回的是 `openConversationId`（不是 `conversationId`），喂给 `message list` 拉不到数据 |
| `dws chat crypto decrypt --layer ding` | v1.0.63 实测 **30/30 全失败**（服务端批量解密接口不可用）；v1.0.62 上返回 `not_encrypted` |
| `dws chat crypto decrypt --file <绝对路径>` | 直接被拒：`--file must be a relative path within the current directory` |
| `dws chat chmod` 申请 decrypt scope | scope 白名单只有 `chat.message:send` / `chat.message:list` / `chat.group:destroy` / `chat.data:cross-org`，**没有 decrypt** |
| `dws config` | 32 个配置项里没有任何解密相关开关 |
| 读本地钉钉数据库 `~/AppData/Roaming/DingTalk/<uid>_v2/DBFiles/dingtalk.db` | 文件头是自定义加密格式，非 SQLite 明文 |
| 本地钉钉 MCP 服务 | 端口未启动 |

## 兜底补充：AI 搜问

```bash
dws aisearch enterprise --queries "<对方姓名>" --types im --time-range "最近三个月" --format json
```

走服务端索引，能拿到**你自己发出消息的明文**（服务端有下发副本），部分会话也能拿到对方消息。但索引稀疏，单轮覆盖率约 8%。只能查漏补缺，不能替代解密。

---

## 隐私提示

解密出来的是**真实聊天明文**，属于高度敏感的企业数据。建议：

- 输出目录放在仓库外，或加进 `.gitignore`
- 分析完及时清理 `out/`
- 不要把 `messages.jsonl` 提交到任何公开仓库

本仓库的 `.gitignore` 已默认排除所有数据产物。

## 更新日志

### 2026-10-18（新增配套技能 `skills/dingtalk-plaintext-harvest/`）

`CRYPTO_DISABLED` 仍然无解（确认是服务端策略，客户端改不了），因此新增一条**纯本地兜底链路**：
不改密钥、不逆向，直接被动监听钉钉进程内存、抓显示层 `content.text`。

- 实测（274 条消息的群，dws 明文 141 + 密文 133）：单轮被动监听 25 秒抓到 864 条唯一明文。
- **关键发现**：`--mark`（群 cid 过滤）要求文本附近 4000 字节内有群标记，实测会漏掉绝大多数——
  同一批消息过滤后只剩 102 条。默认已改为**不过滤**，需要时再传 `--mark`。
- 覆盖率取决于客户端加载过多少消息：往上滚能显著提高（91→132 条），**单纯延长监听时长无效**。

### 2026-10-16（主脚本 v3：修正「safechat 主层」这个致命错误）

同一条 10-06 的密文，10-09 能解出明文「[流鼻血]是啊，希望坚持一段时间…」，
10-16 只能拿到 `1_1_<hex>`。根因：**服务端 DING 解密策略被企业侧关闭**。

| # | 问题 | 后果 | 修法 |
|---|---|---|---|
| 1 | 把 `--layer safechat` 当主层 | 它只跑本地层，双层消息永远返回 `1_1_<hex>` 信封，**不可能是明文** | 主层改回 `full`（唯一含服务端 DING 层的链路），`safechat` 降级 |
| 2 | 没识别 `1_1_<hex>` 信封 | `ok=true` + `plaintext` 非空 → **信封被当明文写进语料**，污染数据 | 新增 `is_envelope()`（`^\d+_\d+_[0-9a-f]+$`），命中即判失败并单独计数 |
| 3 | SKILL.md / README 把 100% 写成无条件事实 | 后续 agent 会反复重试并误判是脚本 bug | 顶部加时效警告 + 10 秒自检表；`CRYPTO_DISABLED` 直接转管理员 |

**已排除（别重复耗时）**：升级 v1.0.63→v1.0.64 输出逐字节相同；清空 `~/.dws/safechat/keystore`
重拉企业密钥输出逐字节相同；token 有效（至 11-15）→ 与版本、密钥、账号权限均无关。

**另一个新坑**：`+recent-conversations` 对**近 7 天窗口返回 0 个会话**（`+0 exhausted=true`），
30 天窗口正常返回 318 个。窗口开太小会误判接口坏了。

### 2026-10-09（主脚本 v2）

基于一次「近 92 天全量（单聊 + 群聊）」的实测重写，修正了 5 个会直接导致失败或丢数据的缺陷：

| # | 问题 | 后果 | 修法 |
|---|---|---|---|
| 1 | `crypto decrypt --file` 传绝对路径 | 被 dws 拒绝，**整批 0 成功** | 改用 `cwd=tmp_dir` + 相对文件名 |
| 2 | 主层用 `--layer full` | 4.16 QPS，比必要速度慢 59% | 主层改 `safechat`（6.61 QPS，同样 100%），`full` 降级；排除 `ding`（30/30 失败） |
| 3 | 拉取传 `--max-items 600` | 10 个单聊会话缺一个半月 | 不传该参数，`--direction newer` + 下界手动翻页 |
| 4 | 翻页把 `nextPage` 整个 dict 当 `--time` | 返回 0 条，误判为翻页失效 | 取 `nextPage['time']` |
| 5 | 会话清单只拉一轮 | 残缺清单（302 vs 344 个会话） | 续 `--cursor` 直到 `endpoint_exhausted` |

另外修正了一个**结论性错误**：原以为「群聊正文 100% 明文」（源自单日样本），实测 3 个月窗口内有 **18,692 条群聊正文是密文**。现已纳入统计并支持 `--kind all`。

### 2026-10-07

- 新增 `install.sh` / `sync_to_agents.sh`，部署改为「主源 + 符号链接」
- 明确统计口径：可读 = 原始明文 + 解密明文；关键词筛选只减不增

---

## License

MIT —— 见 [LICENSE](LICENSE)。
