#!/usr/bin/env bash
#=============================================================================
# vps-hardening-no-key.sh — 无 SSH Key / 保持密码登录版入口
#
# 本文件是薄封装：找到主脚本 vps-hardening.sh（自动安装目录 / 同目录 / 下载），
# 然后以 --mode password 执行。这样两种登录模式共用同一套加固逻辑与安全闸门，
# 不会出现两份脚本各写一套、逐渐走样的问题。
#
# 用法：
#   sudo bash vps-hardening-no-key.sh              # 交互式菜单（密码模式）
#   sudo bash vps-hardening-no-key.sh --auto       # 顺序执行第 2~8 项
#   sudo bash vps-hardening-no-key.sh --step 4     # 只重设密码/验证密码通道
#   sudo bash vps-hardening-no-key.sh --fail2ban   # 只执行第 8 项
#
# 其余参数与环境变量（DEBUG=1 / FORCE=1 / VPS_FW / VPS_REPO / VPS_REF）
# 与主脚本完全一致，直接透传。
#=============================================================================

if [ -z "${BASH_VERSION:-}" ]; then
  echo "请用 bash 运行：sudo bash vps-hardening-no-key.sh" >&2
  exit 1
fi

set -uo pipefail

REPO="${VPS_REPO:-strivewu0813/vps-security-hardening}"
REF="${VPS_REF:-main}"

#------------------------------ 先校验参数（避免参数错误还去联网/写文件）------------------------------#

passthru=()
for a in "$@"; do
  case "$a" in
    --key|--mode=key)
      echo "本脚本固定为密码登录模式；如需 SSH Key 模式请使用 vps-hardening.sh。" >&2
      exit 1 ;;
    --mode)
      echo "本脚本不接受 --mode（固定密码登录模式）；请用 --no-key / --password 或直接运行 vps-hardening.sh --mode key。" >&2
      exit 1 ;;
    --password|--no-key|--mode=password) : ;;      # 与固定模式一致，忽略
    *) passthru+=("$a") ;;
  esac
done

#------------------------------ 定位主引擎 ------------------------------#

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 15 --max-time 120 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -T 30 -O "$2" "$1"
  else return 127; fi
}

# 判定“这是主引擎”：用行首锚定的函数定义标记（与 install.sh 的校验标记一致）
is_engine() {
  [ -r "$1" ] && grep -qE '^step5_sshd\(\)' "$1" 2>/dev/null && grep -qE '^build_ssh_block\(\)' "$1" 2>/dev/null
}

self="${BASH_SOURCE[0]:-}"
selfdir=""
if [ -n "$self" ] && [ -f "$self" ]; then
  selfdir=$(cd -- "$(dirname -- "$self")" >/dev/null 2>&1 && pwd)
fi

engine=""
for cand in \
  "${selfdir:-/nonexistent}/vps-hardening" \
  "${selfdir:-/nonexistent}/vps-hardening.sh" \
  /usr/local/bin/vps-hardening \
  "${VPS_LIB_DIR:-/usr/local/lib/vps-hardening}/vps-hardening.sh"
do
  if is_engine "$cand"; then engine="$cand"; break; fi
done

if [ -z "$engine" ]; then
  echo "未找到主脚本 vps-hardening，尝试下载……"
  dest=/usr/local/bin/vps-hardening
  [ -w /usr/local/bin ] || dest="${TMPDIR:-/tmp}/vps-hardening.sh"
  tmp=$(mktemp) || { echo "无法创建临时文件"; exit 1; }
  trap 'rm -f "${tmp:-}"' EXIT INT TERM HUP
  for base in "https://raw.githubusercontent.com/$REPO/$REF" "https://cdn.jsdelivr.net/gh/$REPO@$REF"; do
    url="$base/vps-hardening.sh"
    echo "下载: $url"
    if fetch "$url" "$tmp" && is_engine "$tmp"; then
      # 覆盖前先备份非同项目文件，避免直接冲掉别人的东西
      if [ -f "$dest" ] && ! grep -qF 'vps-hardening' "$dest" 2>/dev/null; then
        cp -f "$dest" "${dest}.bak" 2>/dev/null && echo "已备份原文件到 ${dest}.bak"
      fi
      if cat "$tmp" > "$dest"; then
        chmod 755 "$dest" 2>/dev/null || true
        engine="$dest"
        break
      fi
      echo "写入 $dest 失败，改用临时目录重试……"
      dest="${TMPDIR:-/tmp}/vps-hardening.sh"
      if cat "$tmp" > "$dest"; then
        chmod 755 "$dest" 2>/dev/null || true
        engine="$dest"
        break
      fi
    fi
    echo "该来源不可用，尝试下一个……"
  done
  rm -f "$tmp"
fi

if [ -z "$engine" ]; then
  echo "无法获取主脚本。请先执行 install.sh，或把 vps-hardening.sh 与 lib/platform.sh 放到同一目录。" >&2
  exit 1
fi

exec bash "$engine" --mode password ${passthru[@]+"${passthru[@]}"}
