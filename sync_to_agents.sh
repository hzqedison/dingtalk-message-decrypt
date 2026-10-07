#!/usr/bin/env bash
#
# sync_to_agents.sh — 把仓库里的技能文件同步到本机「主源」
#
# 三处符号链接（~/.claude ~/.codex ~/.workbuddy）会自动跟随主源，无需再动。
# 如果还没建过链接，请先跑一次 install.sh。
#
# 用法：bash sync_to_agents.sh
#
set -uo pipefail

NAME="dingtalk-message-decrypt"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${SKILL_SOURCE:-$HOME/.agents/skills}"
DST="$SOURCE_DIR/$NAME"

if [ ! -f "$SRC/SKILL.md" ]; then
  echo "错误：$SRC 下没找到 SKILL.md，请在仓库根目录执行本脚本。" >&2
  exit 1
fi

# 跨平台 md5：Linux/Git Bash 用 md5sum，macOS 用 md5 -q
md5_of() {
  if command -v md5sum >/dev/null 2>&1; then
    md5sum "$1" 2>/dev/null | cut -d' ' -f1
  elif command -v md5 >/dev/null 2>&1; then
    md5 -q "$1" 2>/dev/null          # macOS
  else
    echo ""
  fi
}

mkdir -p "$DST"

echo "同步：$SRC -> $DST"
echo
echo "== 文件校验 =="
fail=0
# 用 `!` 而非 `-not`：macOS 的 BSD find 不认 GNU 的 `-not`
while IFS= read -r f; do
  mkdir -p "$DST/$(dirname "$f")"
  cp -f "$SRC/$f" "$DST/$f"
  a="$(md5_of "$SRC/$f")"
  b="$(md5_of "$DST/$f")"
  if [ -n "$a" ] && [ "$a" = "$b" ]; then
    echo "  OK   $f"
  else
    echo "  DIFF $f"; fail=1
  fi
done < <(cd "$SRC" && find . -type f \
          ! -path "./.git/*" \
          ! -name "install.sh" \
          ! -name "sync_to_agents.sh" | sed 's|^\./||')

echo
echo "== 三处技能目录状态 =="
for d in .claude .codex .workbuddy; do
  p="$HOME/$d/skills/$NAME"
  if [ -L "$p" ]; then
    echo "  ✓ $d/skills/$NAME -> $(readlink "$p")"
  elif [ -d "$p" ]; then
    echo "  ⚠ $d/skills/$NAME 是实体目录（非链接），升级不会自动跟随"
  else
    echo "  ✗ $d/skills/$NAME 不存在，请先跑 bash install.sh"
  fi
done

exit $fail
