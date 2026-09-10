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

set -uo pipefail

REPO="${VPS_REPO:-strivewu0813/vps-security-hardening}"
REF="${VPS_REF:-main}"

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 15 --max-time 120 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -T 30 -O "$2" "$1"
  else return 127; fi
}

is_engine() {
  [ -r "$1" ] && grep -q 'build_ssh_block' "$1" 2>/dev/null
}

self="${BASH_SOURCE[0]:-}"
selfdir=""
if [ -n "$self" ] && [ -f "$self" ]; then
  selfdir=$(cd -- "$(dirname -- "$self")" >/dev/null 2>&1 && pwd)
fi

engine=""
for cand in \
  "${selfdir:-/nonexistent}/vps-hardening.sh" \
  /usr/local/bin/vps-hardening \
  /usr/local/lib/vps-hardening/vps-hardening.sh
do
  if is_engine "$cand"; then engine="$cand"; break; fi
done

if [ -z "$engine" ]; then
  echo "未找到主脚本 vps-hardening.sh，尝试下载……"
  dest=/usr/local/bin/vps-hardening
  tmp=$(mktemp) || { echo "无法创建临时文件"; exit 1; }
  mkdir -p /usr/local/bin 2>/dev/null || dest=/tmp/vps-hardening.sh
  for base in "https://raw.githubusercontent.com/$REPO/$REF" "https://cdn.jsdelivr.net/gh/$REPO@$REF"; do
    url="$base/vps-hardening.sh"
    echo "下载: $url"
    if fetch "$url" "$tmp" && is_engine "$tmp"; then
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
  echo "无法获取主脚本。请先执行 install.sh，或把 vps-hardening.sh 与 lib/platform.sh 放到同一目录。"
  exit 1
fi

# 本入口固定为密码登录模式：拒绝会改变模式的参数，避免“从密码入口跑成 Key 模式”
passthru=()
for a in "$@"; do
  case "$a" in
    --key|--mode|--mode=*)
      echo "本脚本固定为密码登录模式（--mode password）；如需 SSH Key 模式请使用 vps-hardening.sh。" >&2
      exit 1 ;;
    --password|--no-key) : ;;      # 冗余指定，忽略
    *) passthru+=("$a") ;;
  esac
done

exec bash "$engine" --mode password ${passthru[@]+"${passthru[@]}"}
