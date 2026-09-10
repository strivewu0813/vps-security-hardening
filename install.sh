#!/usr/bin/env bash
#=============================================================================
# install.sh — VPS 基础安全加固脚本 一键安装入口
#
# 推荐用法（先下载、看一眼再执行；可避免管道直通 root）：
#   curl -fsSLO https://raw.githubusercontent.com/strivewu0813/vps-security-hardening/main/install.sh
#   sudo bash install.sh
#
# 一行版：
#   curl -fsSL https://raw.githubusercontent.com/strivewu0813/vps-security-hardening/main/install.sh | sudo bash
#   带参数时（bash -s -- 后面的参数会传给本脚本）：
#   curl -fsSL https://raw.githubusercontent.com/strivewu0813/vps-security-hardening/main/install.sh | sudo bash -s -- --no-key
#
# 功能：
#   * 把两个加固脚本安装到 /usr/local/bin（vps-hardening / vps-hardening-no-key），可随时重复运行
#   * 下载源自动回退：raw.githubusercontent.com → cdn.jsdelivr.net（国内更易连通）
#   * 若当前目录里已有仓库文件（本地克隆），优先使用本地文件，不联网
#   * 通过管道运行时，自动把交互输入切换到 /dev/tty，避免和脚本自身 stdin 争用
#
# 参数：
#   --key            安装并运行 SSH Key 版（默认）
#   --no-key         安装并运行 无 SSH Key / 密码版
#   --install-only   只安装到 /usr/local/bin，不立即运行
#   --auto           透传：顺序执行第 2~8 项
#   --step N         透传：只执行第 N 项（2~10）
#   --fail2ban       透传：只执行第 8 项 Fail2ban
#   --ref REF        指定分支或标签（默认 main）
#   --mirror URL     指定下载镜像前缀（默认按内置列表回退）
#   --dir DIR        指定安装目录（默认 /usr/local/bin）
#   -h, --help       显示本帮助
#=============================================================================

set -uo pipefail

REPO="${REPO:-strivewu0813/vps-security-hardening}"
REF="main"
INSTALL_DIR="/usr/local/bin"
MIRROR_OVERRIDE=""
VARIANT="key"
DO_RUN=1
PASSTHRU=()

C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
C_CYN=$'\e[36m'; C_BLD=$'\e[1m';   C_N=$'\e[0m'

info() { printf '%b' "${C_CYN}[INFO]${C_N} $*\n"; }
ok()   { printf '%b' "${C_GRN}[ OK ]${C_N} $*\n"; }
warn() { printf '%b' "${C_YEL}[WARN]${C_N} $*\n" >&2; }
err()  { printf '%b' "${C_RED}[ERR ]${C_N} $*\n" >&2; }
hdr()  { printf '%b' "\n${C_BLD}${C_CYN}========== $* ==========${C_N}\n"; }

usage() {
  cat <<'EOF'
用法：
  sudo bash install.sh [参数]
  curl -fsSL <install.sh 地址> | sudo bash -s -- [参数]

参数：
  --key            安装并运行 SSH Key 版（默认）
  --no-key         安装并运行 无 SSH Key / 密码版
  --install-only   只安装到 /usr/local/bin，不立即运行
  --auto           透传：顺序执行第 2~8 项
  --step N         透传：只执行第 N 项（2~10）
  --fail2ban       透传：只执行第 8 项 Fail2ban
  --ref REF        指定分支或标签（默认 main）
  --mirror URL     指定下载镜像前缀（默认 raw.githubusercontent.com → cdn.jsdelivr.net）
  --dir DIR        指定安装目录（默认 /usr/local/bin）
  -h, --help       显示本帮助

安装位置：
  /usr/local/bin/vps-hardening           SSH Key 版
  /usr/local/bin/vps-hardening-no-key    无 SSH Key / 密码登录版
EOF
}

#------------------------------ 基础检查 ------------------------------#

# 本脚本所在目录（管道运行时为空）
self_dir() {
  local self="${BASH_SOURCE[0]:-}"
  if [ -n "$self" ] && [ -f "$self" ]; then
    (cd -- "$(dirname -- "$self")" >/dev/null 2>&1 && pwd)
  fi
  return 0
}

ensure_root() {
  if [ "$(id -u)" -eq 0 ]; then
    return 0
  fi
  if [ -n "${SELF_PATH:-}" ] && [ -f "$SELF_PATH" ]; then
    echo "需要 root 权限，使用 sudo 重新执行……"
    exec sudo -E bash "$SELF_PATH" "$@"
  fi
  err "需要 root 权限。通过管道运行时请这样执行："
  err "  curl -fsSL <install.sh 地址> | sudo bash -s -- [参数]"
  exit 1
}

#------------------------------ 下载与校验 ------------------------------#

fetch() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 15 --max-time 120 -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 30 -O "$out" "$url"
  else
    return 127
  fi
}

base_urls() {
  if [ -n "$MIRROR_OVERRIDE" ]; then
    printf '%s\n' "${MIRROR_OVERRIDE%/}"
    return 0
  fi
  printf '%s\n' "https://raw.githubusercontent.com/$REPO/$REF"
  printf '%s\n' "https://cdn.jsdelivr.net/gh/$REPO@$REF"
}

# 校验下载结果确实是我们期望的脚本（防止拿到 HTML 错误页或截断内容）
# 主脚本/封装：以 #!/...bash 开头且含 main "$@"；平台适配层：含 plat_detect 定义
valid_script() {
  local f="$1"
  [ -s "$f" ] || return 1
  head -n1 "$f" | grep -q 'bash' || return 1
  if grep -q '^plat_detect()' "$f"; then
    grep -q 'ssh_apply_and_verify\|ssh_conf_prepare' "$f" || return 1
    return 0
  fi
  grep -q '^main "\$@"' "$f" || return 1
  grep -q 'vps-hardening' "$f" || return 1
  return 0
}

# 取得脚本内容：优先本地目录，其次按镜像列表逐个下载
acquire() {
  local name="$1" dest="$2" base url tmp
  if [ -n "${SELF_DIR:-}" ] && valid_script "$SELF_DIR/$name"; then
    info "使用本地文件: $SELF_DIR/$name"
    cp -f "$SELF_DIR/$name" "$dest" || return 1
    return 0
  fi
  tmp=$(mktemp) || { err "无法创建临时文件"; return 1; }
  while IFS= read -r base; do
    [ -n "$base" ] || continue
    url="$base/$name"
    info "下载: $url"
    if fetch "$url" "$tmp" && valid_script "$tmp"; then
      if cp -f "$tmp" "$dest"; then
        rm -f "$tmp"
        ok "已获取 $name"
        return 0
      fi
    fi
    warn "该来源不可用或内容校验未通过，尝试下一个……"
  done < <(base_urls)
  rm -f "$tmp"
  err "无法获取 $name（所有来源均失败）。可手动下载后放在本目录再运行，或稍后重试。"
  return 1
}

install_scripts() {
  local key_dest="$INSTALL_DIR/vps-hardening"
  local nokey_dest="$INSTALL_DIR/vps-hardening-no-key"
  local lib_dir=/usr/local/lib/vps-hardening
  local lib_dest="$lib_dir/platform.sh"
  mkdir -p "$INSTALL_DIR" || { err "无法创建 $INSTALL_DIR"; return 1; }
  mkdir -p "$lib_dir" 2>/dev/null || { err "无法创建 $lib_dir"; return 1; }
  backup_foreign "$key_dest"
  backup_foreign "$nokey_dest"
  acquire "vps-hardening.sh" "$key_dest" || return 1
  acquire "vps-hardening-no-key.sh" "$nokey_dest" || return 1
  acquire "lib/platform.sh" "$lib_dest" || return 1
  chmod 755 "$key_dest" "$nokey_dest" 2>/dev/null || true
  chmod 644 "$lib_dest" 2>/dev/null || true
  return 0
}

# 目标位置若已有同名但非本项目的文件，先备份，不直接覆盖别人的东西
backup_foreign() {
  local dest="$1"
  if [ -f "$dest" ] && ! grep -q 'vps-hardening' "$dest" 2>/dev/null; then
    if cp -f "$dest" "${dest}.bak" 2>/dev/null; then
      warn "发现同名但非本项目的文件 $dest，已备份为 ${dest}.bak"
    fi
  fi
  return 0
}

#------------------------------ 运行 ------------------------------#

run_script() {
  local target="$1"; shift
  if [ ! -f "$target" ]; then
    err "找不到 $target"
    return 1
  fi
  # 主脚本需要平台适配层：已装到 /usr/local/lib/vps-hardening/platform.sh
  if [ ! -r /usr/local/lib/vps-hardening/platform.sh ]; then
    warn "未找到 /usr/local/lib/vps-hardening/platform.sh，主脚本会尝试自行下载。"
  fi
  if [ -t 0 ]; then
    bash "$target" "$@"
    return $?
  fi
  if [ -r /dev/tty ] && [ -w /dev/tty ]; then
    info "检测到通过管道运行：交互输入已切换到 /dev/tty"
    bash "$target" "$@" < /dev/tty
    return $?
  fi
  err "当前没有可用的交互终端（/dev/tty 不可用），无法进行交互式加固。"
  err "请手动执行: sudo $target $*"
  return 1
}

show_howto() {
  hdr "安装完成"
  echo "  脚本位置："
  echo "    $INSTALL_DIR/vps-hardening          SSH Key 版（推荐）"
  echo "    $INSTALL_DIR/vps-hardening-no-key   无 SSH Key / 密码登录版"
  echo
  echo "  以后可随时重新运行（加固流程支持中断后继续）："
  echo "    sudo $INSTALL_DIR/vps-hardening"
  echo "    sudo $INSTALL_DIR/vps-hardening-no-key"
  echo "    sudo $INSTALL_DIR/vps-hardening --step 5      # 只重跑某一项"
  echo
  echo "  操作日志: /var/log/vps-hardening.log"
  echo "  文档与说明: https://github.com/$REPO"
}

#------------------------------ 参数解析 ------------------------------#

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --key) VARIANT="key" ;;
      --no-key|--nokey) VARIANT="no-key" ;;
      --install-only|--download-only) DO_RUN=0 ;;
      --auto|--fail2ban) PASSTHRU+=("$1") ;;
      --step)
        shift
        if [ -z "${1:-}" ]; then err "--step 需要跟一个数字（2~10）"; exit 1; fi
        PASSTHRU+=("--step" "$1") ;;
      --ref)
        shift
        if [ -z "${1:-}" ]; then err "--ref 需要跟分支或标签名"; exit 1; fi
        REF="$1" ;;
      --mirror)
        shift
        if [ -z "${1:-}" ]; then err "--mirror 需要跟一个 URL 前缀"; exit 1; fi
        MIRROR_OVERRIDE="$1" ;;
      --dir)
        shift
        if [ -z "${1:-}" ]; then err "--dir 需要跟一个目录"; exit 1; fi
        INSTALL_DIR="${1%/}" ;;
      -h|--help) usage; exit 0 ;;
      *) err "未知参数: $1"; echo; usage; exit 1 ;;
    esac
    shift
  done
}

#------------------------------ 入口 ------------------------------#

main() {
  SELF_PATH=""
  local self="${BASH_SOURCE[0]:-}"
  if [ -n "$self" ] && [ -f "$self" ]; then SELF_PATH="$self"; fi
  SELF_DIR=$(self_dir)

  local ORIG=("$@")
  parse_args "$@"
  ensure_root ${ORIG[@]+"${ORIG[@]}"}

  hdr "VPS 基础安全加固脚本 一键安装"
  info "仓库: $REPO   分支/标签: $REF"
  if [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/vps-hardening.sh" ]; then
    info "检测到本地脚本目录，将使用本地文件（不联网）"
  fi

  install_scripts || exit 1

  if [ "$DO_RUN" = "0" ]; then
    show_howto
    ok "已按要求只安装、不运行。"
    return 0
  fi

  local target
  if [ "$VARIANT" = "no-key" ]; then
    target="$INSTALL_DIR/vps-hardening-no-key"
  else
    target="$INSTALL_DIR/vps-hardening"
  fi

  hdr "开始运行: $target"
  run_script "$target" ${PASSTHRU[@]+"${PASSTHRU[@]}"}
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    ok "执行结束。"
  else
    warn "执行未正常结束（退出码 $rc）：请按上面的提示处理后重跑，例如 sudo $target --step 5"
  fi
  show_howto
  return "$rc"
}

main "$@"
