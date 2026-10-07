#!/usr/bin/env bash
#
# install.sh — 把本技能部署为「单一主源 + 符号链接」
#
# 主源只放一份，Claude Code / Codex / WorkBuddy 三处用符号链接指向它。
# 以后升级只改主源，三处自动跟随（避免多份拷贝版本漂移）。
#
# 用法：
#   bash install.sh                      # 默认主源 ~/.agents/skills/dingtalk-message-decrypt
#   SKILL_SOURCE=~/.claude/skills bash install.sh   # 自定义主源位置
#
set -uo pipefail

NAME="dingtalk-message-decrypt"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${SKILL_SOURCE:-$HOME/.agents/skills}"
DST="$SOURCE_DIR/$NAME"
CONSUMERS=("$HOME/.claude/skills" "$HOME/.codex/skills" "$HOME/.workbuddy/skills")

if [ ! -f "$SRC/SKILL.md" ]; then
  echo "错误：$SRC 下没找到 SKILL.md，请在仓库根目录执行本脚本。" >&2
  exit 1
fi

# ---------- 平台判定 ----------
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
  Darwin)               OS="macos" ;;
  Linux*)               OS="linux" ;;
  *)                    OS="unknown" ;;
esac
echo "平台：$OS"

# ---------- 1. 建主源 ----------
echo
echo "[1/3] 建立主源：$DST"
mkdir -p "$DST/scripts/legacy"
# 注意：用 `!` 而非 `-not` —— macOS 自带 BSD find 不认 GNU 的 `-not`
while IFS= read -r f; do
  mkdir -p "$DST/$(dirname "$f")"
  cp -f "$SRC/$f" "$DST/$f"
done < <(cd "$SRC" && find . -type f \
          ! -path "./.git/*" \
          ! -name "install.sh" \
          ! -name "sync_to_agents.sh" | sed 's|^\./||')
echo "  已复制 $(find "$DST" -type f | wc -l | tr -d ' ') 个文件"

# ---------- 2. 三处建链接 ----------
echo
echo "[2/3] 在三处技能目录建立链接"

link_unix() {          # $1=链接路径 $2=目标
  rm -rf "$1" 2>/dev/null
  ln -sfn "$2" "$1" && echo "  ✓ $1 -> $2 (symlink)"
}

link_windows() {       # $1=链接路径 $2=目标
  rm -rf "$1" 2>/dev/null
  local win_link win_target
  win_link="$(cygpath -w "$1" 2>/dev/null || echo "$1")"
  win_target="$(cygpath -w "$2" 2>/dev/null || echo "$2")"
  # ① 真符号链接（需开发者模式或管理员权限）
  if cmd //c "mklink /D \"$win_link\" \"$win_target\"" >/dev/null 2>&1; then
    echo "  ✓ $1 -> $2 (mklink /D)"
    return 0
  fi
  # ② 降级为目录联接（普通权限即可）
  if cmd //c "mklink /J \"$win_link\" \"$win_target\"" >/dev/null 2>&1; then
    echo "  ⚠ $1 -> $2 (目录联接 /J，权限不足时的降级方案)"
    return 0
  fi
  # ③ 再降级为实体拷贝（功能一样，但以后要手动同步）
  mkdir -p "$1" && cp -rf "$2/." "$1/" && \
    echo "  ⚠ $1 实体拷贝（无法建链接，以后升级需重跑本脚本）"
}

for dir in "${CONSUMERS[@]}"; do
  [ -d "$dir" ] || mkdir -p "$dir"
  link_path="$dir/$NAME"
  if [ "$OS" = "windows" ]; then
    link_windows "$link_path" "$DST"
  else
    link_unix "$link_path" "$DST"
  fi
done

# ---------- 3. 验证 ----------
echo
echo "[3/3] 验证"
ok=1
for dir in "${CONSUMERS[@]}"; do
  p="$dir/$NAME/SKILL.md"
  if [ -f "$p" ]; then
    echo "  ✓ $(basename "$(dirname "$dir")")/skills/$NAME  (SKILL.md $(wc -c < "$p" | tr -d ' ') B)"
  else
    echo "  ✗ $(basename "$(dirname "$dir")")/skills/$NAME 读取失败"; ok=0
  fi
done

echo
if [ "$ok" = "1" ]; then
  echo "安装完成。以后升级：改完仓库后跑 bash sync_to_agents.sh"
else
  echo "部分目录未就绪，请检查上面输出。" >&2
  exit 1
fi
