# dingtalk-message-decrypt

让 AI 助手（Claude Code / Codex / WorkBuddy 等）能完整读取并**解密**钉钉聊天记录——包括企业开启「三方加密」后那些显示为 `[加密消息，无法解码]` 的单聊消息。

实测：25,848 条密文，成功解密 25,830 条，**成功率 99.93%**。

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
| 群聊正文 100% 可读，单聊 70~80% 加密 | 三方加密主要覆盖点对点正文；群聊服务端要支持 @/搜索/机器人，留明文 |
| 群聊里「被引用原文」100% 加密 | 引用内容作为消息体（密文）返回 |
| 机器人推送、日程卡片、图片 mediaId、审批 100% 可读 | 走服务端结构化通道，不进聊天正文加密 |
| 越近期的消息加密率越高 | 安全策略在灰度放量 |

---

## 快速开始

### 手工三步

```bash
# 1. 拿密文（必须用底层命令，它会返回 content 字段）
dws chat message list --conversation-id <cid> \
  --time "2026-10-07 00:00:00" --direction older \
  --page-all --page-limit 200 --max-items 600 --format json
# content 形如：xxxx...||2||1||228

# 2. 逐条解密
dws chat crypto decrypt --file <密文文件> --layer full --format json
# 成功返回：{"keyVersion":1,"layer":"full","ok":true,"plaintext":"..."}
```

`--layer` 三档的区别：

- `full` = SafeChat 本地层 + Ding 服务端层 —— **必须用这个**
- `safechat` = 只解本地层，输出仍是中间密文
- `ding` = 单独用会报 `not_encrypted`

### 一键脚本

不支持批量输入（多行、JSON 数组都无效），必须逐条调用。用脚本自动化：

```bash
python scripts/dws_decrypt.py --days 92 --out ./out                 # 近 92 天全部单聊
python scripts/dws_decrypt.py --days 92 --out ./out --limit 200     # 先试跑 200 条
python scripts/dws_decrypt.py --days 92 --out ./out --workers 16    # 指定并发
python scripts/dws_decrypt.py --resume --out ./out                  # 断点续跑
```

产出：

| 文件 | 内容 |
|---|---|
| `out/conversations.json` | 会话列表 |
| `out/raw/NNN.json` | 每个会话原始拉取结果（含 content 密文） |
| `out/decrypted.jsonl` | 解密成功的明文（可追加，支持断点续跑） |
| `out/messages.jsonl` | 合并后的完整明文语料 |

`messages.jsonl` 每行格式：`{"session": "...", "time": "...", "sender": "...", "text": "..."}`

---

## 安装为 AI 技能

clone 下来后，把整个目录复制到你的 AI 工具技能目录即可被自动发现：

```bash
cd dingtalk-message-decrypt

# Claude Code
cp -r . ~/.claude/skills/dingtalk-message-decrypt

# Codex
cp -r . ~/.codex/skills/dingtalk-message-decrypt

# WorkBuddy
cp -r . ~/.workbuddy/skills/dingtalk-message-decrypt
```

装好后直接对 AI 说「帮我整理最近一个月的钉钉待办」，它会自动加载 `SKILL.md` 并按正确流程走。

对 Codex，可在 `~/.codex/AGENTS.md` 里加一行全局指引：

```markdown
- 处理钉钉消息（拉取/整理待办/周报/纪要）时，先加载 skill `dingtalk-message-decrypt`；
  遇到 `[加密消息，无法解码]` 不要跳过，按 SKILL.md 的解密流程处理。
```

---

## 脚本目录

| 路径 | 说明 |
|---|---|
| `scripts/dws_decrypt.py` | **主脚本**。拉列表 → 拉密文 → 逐条解密 → 合并，一条命令跑完，支持断点续跑。只依赖 Python 标准库 |
| `scripts/legacy/fetch_dm_cipher.py` | 【历史】只负责并行拉取带密文的单聊消息，是主脚本的前身 |
| `scripts/legacy/merge_dm.py` | 【历史】合并明文与解密结果、按关键词粗筛待办信号，演示了信号筛选思路 |

`legacy/` 里的脚本保持原样归档，用于追溯当时的踩坑过程，功能已被 `dws_decrypt.py` 完全覆盖，**日常请用主脚本**。

两个 legacy 脚本需要你通过环境变量告诉它你是谁（用来过滤掉自己发出的消息）：

```bash
export DWS_ME="你的钉钉昵称"
```

---

## 性能与坑

| 项 | 实测 |
|---|---|
| 单条解密耗时 | 约 0.2s（进程启动开销占大头） |
| 整体吞吐 | 约 **5 条/秒** |
| 并发 | **16 → 32 无提升**，瓶颈在服务端限速，别浪费资源 |
| 2.6 万条密文 | 约 80~90 分钟，**务必后台跑** |
| 成功率 | 99.93%（失败几乎都是 `no_plaintext`，即空消息/已撤回） |

**坑 1：多线程删临时文件会触发 safe-delete 守卫**
并发调 `os.remove()` 会报 `[safe-delete][SAFE_DELETE_BULK_GUARD_ERROR] state lock timeout` 并让整个进程崩掉。
→ 临时文件放独立目录、按任务编号命名、**不要逐个删除**，最后统一清理。

**坑 2：`--max-items 120` 会截断**
早期脚本常用的 120 上限会导致高频会话被截断（实测 37/161 个会话中招）。批量拉取时保持默认 600 或更大。

**坑 3：升级 dws 会中断正在跑的任务**
升级会替换 `dws.exe`，正在运行的拉取/解密脚本会失败。**升级放在跑批之前。**

---

## 走不通的路（别浪费时间）

这几条我都试过，全部失败，直接跳过：

| 尝试 | 结果 |
|---|---|
| `dws chat +search-msg` | 服务端搜索索引不覆盖单聊，返回 0 条 |
| `dws chat message list-all` | 只返回本来就能读的消息，加密消息一条都不出现 |
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

## License

MIT —— 见 [LICENSE](LICENSE)。
