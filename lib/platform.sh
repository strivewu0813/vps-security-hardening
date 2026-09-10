#!/usr/bin/env bash
#=============================================================================
# lib/platform.sh — VPS 加固脚本的跨发行版适配层
#
# 被 vps-hardening.sh 引入。提供：
#   * 发行版/家族检测（Debian 系、RHEL 系、SUSE、Arch、Alpine、Gentoo、Void、BSD）
#   * 包管理器抽象（apt/dnf/yum/zypper/pacman/apk/emerge/xbps/pkg/pkg_add）
#   * init 抽象（systemd/openrc/sysv/runit/BSD rc）
#   * 防火墙抽象（ufw/firewalld/nftables/iptables；BSD 给出手工指引）
#   * sshd 适配（二进制/版本/服务名/drop-in 或直改配置、Include 注入、语法与生效值检查）
#   * 自动安全更新（unattended-upgrades / dnf-automatic / yum-cron / zypper / apk / freebsd-update）
#   * 网络工具适配（ip/ifconfig、ss/netstat）、重启需求检测、基础 UI 函数
#
# 设计原则：只做“检测 + 尽力而为 + 明确降级”，任何平台不支持的项都打印手工命令，
#           绝不因为不支持的平台而做出危险动作（例如“以为开了防火墙其实没开”）。
#=============================================================================

#------------------------------ UI / 基础 ------------------------------#

C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
C_CYN=$'\e[36m'; C_BLD=$'\e[1m';   C_N=$'\e[0m'

if ! declare -F info >/dev/null 2>&1; then
  info() { printf '%b' "${C_CYN}[INFO]${C_N} $*\n"; }
  ok()   { printf '%b' "${C_GRN}[ OK ]${C_N} $*\n"; }
  warn() { printf '%b' "${C_YEL}[WARN]${C_N} $*\n" >&2; }
  err()  { printf '%b' "${C_RED}[ERR ]${C_N} $*\n" >&2; }
  hdr()  { printf '%b' "\n${C_BLD}${C_CYN}========== $* ==========${C_N}\n"; }
fi

need_cmd() { command -v "$1" >/dev/null 2>&1; }

# 等待输入的确认（危险操作前的闸门）；EOF 时按“否”处理，避免误放行
confirm() {
  local msg="$1" ans=""
  printf '%b' "${C_YEL}?${C_N} $msg [y/N]:\n"
  read -r ans || ans=n
  case "${ans,,}" in y|yes) return 0;; *) return 1;; esac
}

# 带超时地运行命令（BSD 默认没有 timeout；能用就用，不能用就直接跑）
run_timed() {
  local secs="$1"; shift
  if need_cmd timeout; then timeout "$secs" "$@"; else "$@"; fi
}

# 带超时的确认：无输入/EOF 时按默认值处理（避免“卡住不动”）
# $1=提示 $2=秒数(默认15) $3=默认值 y|n(默认 y)
confirm_timed() {
  local msg="$1" secs="${2:-15}" def="${3:-y}" ans=""
  printf '%b' "${C_YEL}?${C_N} $msg [y/N] ${C_CYN}(${secs}s 无输入则按默认 ${def})${C_N}:\n"
  if read -r -t "$secs" ans; then
    case "${ans,,}" in
      '') [ "$def" = "y" ] && return 0 || return 1 ;;
      y|yes) return 0 ;;
      *) return 1 ;;
    esac
  fi
  echo
  warn "${secs}s 内没有输入，按默认 ${def} 处理。"
  [ "$def" = "y" ]
}

# 提示独占一行再读取（某些终端/VNC Console 不渲染无换行提示符）
ask() {
  local prompt="$1" var="$2" ans=""
  printf '%s\n> ' "$prompt"
  IFS= read -r ans || return 1
  printf -v "$var" '%s' "$ans"
  return 0
}

#------------------------------ 平台检测 ------------------------------#

PLAT_OS=""; PLAT_ID=""; PLAT_LIKE=""; PLAT_VER=""; PLAT_NAME=""
PLAT_FAMILY=""; PLAT_ARCH=""
PKG=""
INIT=""
SUDO_GROUP=""
SSH_SVC=""; SSH_SOCKET=""; SSHD_BIN=""; SSHD_VER=""; SSH_KBD_KEY="KbdInteractiveAuthentication"
SSHD_T_OK=0; SSHD_TEST_OUT=""
SSH_CONF=""; SSH_CONF_MODE=""; SSH_INCLUDE_INJECTED=0
FW_BACKEND=""; FW_WHY=""
HAVE_TIMEOUT=0; HAVE_SYSTEMD=0

plat_detect() {
  PLAT_ARCH=$(uname -m 2>/dev/null || echo unknown)
  PLAT_OS=$(uname -s 2>/dev/null || echo unknown)

  if [ "$PLAT_OS" = "Linux" ] && [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    PLAT_ID="${ID:-unknown}"; PLAT_LIKE="${ID_LIKE:-}"; PLAT_VER="${VERSION_ID:-}"
    PLAT_NAME="${PRETTY_NAME:-${ID:-Linux}}"
  else
    PLAT_ID=$(printf '%s' "$PLAT_OS" | tr '[:upper:]' '[:lower:]')
    PLAT_LIKE=""; PLAT_VER=$(uname -r 2>/dev/null || echo '')
    PLAT_NAME="$PLAT_OS $PLAT_VER"
  fi

  # 家族映射：先按 ID 精确匹配，再退回 ID_LIKE（避免 ol/solus 之类的模糊匹配误判）
  case "$PLAT_ID" in
    ubuntu|debian|linuxmint|kali|raspbian|devuan|pop|elementary|zorin|neon|parrot) PLAT_FAMILY=debian ;;
    rhel|centos|almalinux|rocky|fedora|amzn|ol|oracle|scientific|virtuozzo)        PLAT_FAMILY=rhel ;;
    opensuse*|sles|sled|suse)                                                     PLAT_FAMILY=suse ;;
    arch|manjaro|endeavouros|garuda|artix|cachyos|arcolinux)                      PLAT_FAMILY=arch ;;
    alpine|postmarketos)                                                          PLAT_FAMILY=alpine ;;
    gentoo|funtoo)                                                                PLAT_FAMILY=gentoo ;;
    void)                                                                         PLAT_FAMILY=void ;;
    freebsd|openbsd|netbsd|dragonfly)                                             PLAT_FAMILY=bsd ;;
    darwin|macos)                                                                 PLAT_FAMILY=darwin ;;
    *)
      case " ${PLAT_LIKE:-} " in
        *debian*|*ubuntu*)    PLAT_FAMILY=debian ;;
        *rhel*|*fedora*|*centos*) PLAT_FAMILY=rhel ;;
        *suse*)               PLAT_FAMILY=suse ;;
        *arch*)               PLAT_FAMILY=arch ;;
        *alpine*)             PLAT_FAMILY=alpine ;;
        *gentoo*)             PLAT_FAMILY=gentoo ;;
        *void*)               PLAT_FAMILY=void ;;
        *bsd*)                PLAT_FAMILY=bsd ;;
        *)                    PLAT_FAMILY=unknown ;;
      esac ;;
  esac

  case "$PLAT_FAMILY" in
    debian) PKG=apt ;;
    rhel)   if need_cmd dnf; then PKG=dnf; elif need_cmd yum; then PKG=yum; else PKG=""; fi ;;
    suse)   PKG=zypper ;;
    arch)   PKG=pacman ;;
    alpine) PKG=apk ;;
    gentoo) PKG=emerge ;;
    void)   PKG=xbps ;;
    bsd)    if [ "$PLAT_ID" = "freebsd" ]; then PKG=pkg; else PKG=pkg_add; fi ;;
    *)      PKG="" ;;
  esac

  # init 系统
  if need_cmd systemctl && [ -d /run/systemd/system ]; then
    INIT=systemd; HAVE_SYSTEMD=1
  elif need_cmd rc-service; then
    INIT=openrc
  elif need_cmd sv && { [ -d /etc/sv ] || [ -d /var/service ]; }; then
    INIT=runit
  elif [ "$PLAT_FAMILY" = "bsd" ]; then
    INIT=bsd
  elif need_cmd service && [ -d /etc/init.d ]; then
    INIT=sysv
  else
    INIT=none
  fi

  need_cmd timeout && HAVE_TIMEOUT=1

  # sudo 组名（Debian 系用 sudo，其余多为 wheel）
  if grep -q '^sudo:' /etc/group 2>/dev/null; then SUDO_GROUP=sudo
  elif grep -q '^wheel:' /etc/group 2>/dev/null; then SUDO_GROUP=wheel
  else SUDO_GROUP=""; fi

  plat_detect_ssh
  fw_detect
}

plat_report() {
  info "系统     : $PLAT_NAME  [家族=$PLAT_FAMILY 架构=$PLAT_ARCH]"
  info "包管理器 : ${PKG:-未识别}   init: $INIT   sudo 组: ${SUDO_GROUP:-未找到}"
  info "SSH      : 服务=${SSH_SVC:-未知} 二进制=${SSHD_BIN:-未找到} 版本=${SSHD_VER:-未知}"
  info "防火墙   : ${FW_BACKEND:-未识别}  ($FW_WHY)"
  if [ "$SSHD_T_OK" != "1" ]; then
    warn "当前 OpenSSH 不支持 sshd -T（< 6.8）：生效值校验将降级为“检查我们写入的配置 + sshd -t 语法检查”。"
  fi
}

plat_is_supported() {
  case "$PLAT_FAMILY" in
    debian|rhel|suse|arch|alpine|gentoo|void|bsd) return 0 ;;
    *) return 1 ;;
  esac
}

#------------------------------ 包管理 ------------------------------#

pkg_update() {
  case "$PKG" in
    apt)    DEBIAN_FRONTEND=noninteractive apt-get update ;;
    dnf)    dnf -y -q makecache ;;
    yum)    yum -y -q makecache ;;
    zypper) zypper --non-interactive --quiet refresh ;;
    pacman) pacman -Sy --noconfirm >/dev/null ;;
    apk)    apk update ;;
    emerge) emerge --sync --quiet ;;
    xbps)   xbps-install -S -y ;;
    pkg)    pkg update -f ;;
    pkg_add) return 0 ;;              # OpenBSD 无独立索引刷新
    *)      return 1 ;;
  esac
}

pkg_upgrade_all() {
  case "$PKG" in
    apt)    DEBIAN_FRONTEND=noninteractive apt-get -y \
              -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade ;;
    dnf)    dnf -y --refresh upgrade ;;
    yum)    yum -y update ;;
    zypper) zypper --non-interactive update ;;
    pacman) pacman -Su --noconfirm ;;
    apk)    apk upgrade --available ;;
    emerge) emerge -uDN --with-bdeps=y @world ;;
    xbps)   xbps-install -Su -y ;;
    pkg)    pkg upgrade -y ;;
    pkg_add) pkg_add -u ;;
    *)      return 1 ;;
  esac
}

pkg_has() {
  case "$PKG" in
    apt)    dpkg -s "$1" >/dev/null 2>&1 ;;
    dnf|yum) rpm -q "$1" >/dev/null 2>&1 ;;
    zypper) rpm -q "$1" >/dev/null 2>&1 ;;
    pacman) pacman -Q "$1" >/dev/null 2>&1 ;;
    apk)    apk info -e "$1" >/dev/null 2>&1 ;;
    emerge) portageq has_version / "$1" >/dev/null 2>&1 || emerge -s "$1" >/dev/null 2>&1 ;;
    xbps)   xbps-query "$1" >/dev/null 2>&1 ;;
    pkg)    pkg info -e "$1" >/dev/null 2>&1 ;;
    pkg_add) pkg_info -e "$1" >/dev/null 2>&1 ;;
    *)      return 1 ;;
  esac
}

# 安装包；返回 1 表示无法安装（调用方应打印手工命令后降级）
pkg_install() {
  case "$PKG" in
    apt)    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    dnf)    dnf -y install "$@" ;;
    yum)    yum -y install "$@" ;;
    zypper) zypper --non-interactive install "$@" ;;
    pacman) pacman -S --noconfirm --needed "$@" ;;
    apk)    apk add "$@" ;;
    emerge) emerge --quiet "$@" ;;
    xbps)   xbps-install -y "$@" ;;
    pkg)    pkg install -y "$@" ;;
    pkg_add) pkg_add "$@" ;;
    *)      return 1 ;;
  esac
}

# 安装 fail2ban（RHEL 系可能需要先装 EPEL；FreeBSD 的包名是 pyXY-fail2ban）
pkg_install_fail2ban() {
  pkg_install fail2ban && return 0
  case "$PLAT_FAMILY" in
    rhel)
      warn "直接安装 fail2ban 失败，尝试先启用 EPEL……"
      pkg_install epel-release >/dev/null 2>&1 || true
      pkg_install fail2ban && return 0 ;;
    bsd)
      if [ "$PLAT_ID" = "freebsd" ]; then
        local cand=""
        cand=$(pkg search -q -e 'py[0-9]+-fail2ban' 2>/dev/null | tail -n1)
        [ -n "$cand" ] || cand=py311-fail2ban
        warn "FreeBSD 上 fail2ban 的实际包名是 ${cand}，尝试安装……"
        pkg_install "$cand" && return 0
      fi ;;
    alpine)
      warn "Alpine 需要 community 仓库：请确认 /etc/apk/repositories 含 community 后重试。" ;;
  esac
  return 1
}

#------------------------------ init 抽象 ------------------------------#

svc_exists() {
  local n="$1"
  case "$INIT" in
    systemd) systemctl list-unit-files 2>/dev/null | grep -q "^${n}\.service[[:space:]]" ;;
    openrc)  [ -x "/etc/init.d/$n" ] ;;
    sysv)    [ -x "/etc/init.d/$n" ] ;;
    runit)   [ -d "/etc/sv/$n" ] || [ -d "/var/service/$n" ] ;;
    bsd)     [ -x "/etc/rc.d/$n" ] || [ -x "/usr/local/etc/rc.d/$n" ] ;;
    *)       return 1 ;;
  esac
}

# BSD：OpenBSD 用 rcctl，FreeBSD/NetBSD/DragonFly 用 service
bsd_ctl() {
  # $1=动作 $2=服务名
  if [ "$PLAT_ID" = "openbsd" ] && need_cmd rcctl; then
    case "$1" in
      status) rcctl check "$2" >/dev/null 2>&1 ;;
      start)  rcctl start "$2" ;;
      stop)   rcctl stop "$2" ;;
      restart) rcctl restart "$2" ;;
      enable) rcctl enable "$2" ;;
      enabled) rcctl get "$2" status >/dev/null 2>&1 ;;
    esac
  else
    case "$1" in
      status) service "$2" onestatus >/dev/null 2>&1 ;;
      start)  service "$2" start ;;
      stop)   service "$2" stop ;;
      restart) service "$2" restart ;;
      enable) if need_cmd sysrc; then sysrc "${2}_enable=YES" >/dev/null 2>&1; fi ;;
      enabled) grep -q "^${2}_enable=\"YES\"" /etc/rc.conf 2>/dev/null ;;
    esac
  fi
}

svc_active() {
  local n="$1"
  case "$INIT" in
    systemd) systemctl is-active --quiet "$n" ;;
    openrc)  rc-service "$n" status >/dev/null 2>&1 ;;
    sysv)    service "$n" status >/dev/null 2>&1 ;;
    runit)   sv status "$n" 2>/dev/null | grep -q '^run:' ;;
    bsd)     bsd_ctl status "$n" ;;
    *)       return 1 ;;
  esac
}

svc_is_enabled() {
  local n="$1" f=""
  case "$INIT" in
    systemd) systemctl is-enabled --quiet "$n" 2>/dev/null ;;
    openrc)  rc-update show default 2>/dev/null | grep -q "^[[:space:]]*${n}\b" ;;
    sysv)    for f in /etc/rc3.d/S*"$n" /etc/rc2.d/S*"$n"; do [ -e "$f" ] && return 0; done; return 1 ;;
    runit)   [ -L "/var/service/$n" ] || [ -L "/etc/service/$n" ] ;;
    bsd)     bsd_ctl enabled "$n" ;;
    *)       return 1 ;;
  esac
}

svc_enable_now() {
  local n="$1"
  case "$INIT" in
    systemd) systemctl enable --now "$n" ;;
    openrc)  { rc-update add "$n" default >/dev/null 2>&1 || true; }; rc-service "$n" start ;;
    sysv)    { if need_cmd update-rc.d; then update-rc.d "$n" defaults >/dev/null 2>&1; \
               elif need_cmd chkconfig; then chkconfig "$n" on >/dev/null 2>&1; fi; }; service "$n" start ;;
    runit)   { [ -L "/var/service/$n" ] || ln -sf "/etc/sv/$n" /var/service/ 2>/dev/null; } ; sv up "$n" ;;
    bsd)     { bsd_ctl enable "$n" || true; }; bsd_ctl start "$n" ;;
    *)       return 1 ;;
  esac
}

svc_restart() {
  local n="$1"
  case "$INIT" in
    systemd) systemctl restart "$n" ;;
    openrc)  rc-service "$n" restart ;;
    sysv)    service "$n" restart ;;
    runit)   sv restart "$n" ;;
    bsd)     bsd_ctl restart "$n" ;;
    *)       return 1 ;;
  esac
}

# 仅当服务正在运行才重启（非 systemd 平台等价于 restart）
svc_try_restart() {
  local n="$1"
  if [ "$INIT" = "systemd" ]; then systemctl try-restart "$n"; else svc_restart "$n"; fi
}

svc_enable_only() {
  local n="$1"
  case "$INIT" in
    systemd) systemctl enable "$n" >/dev/null 2>&1 ;;
    openrc)  rc-update add "$n" default >/dev/null 2>&1 ;;
    sysv)    if need_cmd update-rc.d; then update-rc.d "$n" defaults >/dev/null 2>&1; \
             elif need_cmd chkconfig; then chkconfig "$n" on >/dev/null 2>&1; fi ;;
    runit)   [ -L "/var/service/$n" ] || ln -sf "/etc/sv/$n" /var/service/ 2>/dev/null ;;
    bsd)     bsd_ctl enable "$n" ;;
    *)       return 1 ;;
  esac
}

svc_daemon_reload() {
  [ "$INIT" = "systemd" ] && systemctl daemon-reload || true
}

svc_status_text() {
  local n="$1"
  case "$INIT" in
    systemd) systemctl status "$n" --no-pager 2>/dev/null | head -n 5 ;;
    openrc)  rc-service "$n" status 2>&1 | head -n 5 ;;
    sysv)    service "$n" status 2>&1 | head -n 5 ;;
    runit)   sv status "$n" 2>&1 ;;
    bsd)     service "$n" status 2>&1 | head -n 5 ;;
  esac
}

svc_stop() {
  local n="$1"
  case "$INIT" in
    systemd) systemctl stop "$n" ;;
    openrc)  rc-service "$n" stop ;;
    sysv)    service "$n" stop ;;
    runit)   sv down "$n" ;;
    bsd)     bsd_ctl stop "$n" ;;
    *)       return 1 ;;
  esac
}

svc_start() {
  local n="$1"
  case "$INIT" in
    systemd) systemctl start "$n" ;;
    openrc)  rc-service "$n" start ;;
    sysv)    service "$n" start ;;
    runit)   sv up "$n" ;;
    bsd)     bsd_ctl start "$n" ;;
    *)       return 1 ;;
  esac
}

# 安装 systemd timer（仅 systemd 平台可用）；$1=名字 $2=OnCalendar $3=命令
install_systemd_timer() {
  local name="$1" sched="$2" cmd="$3"
  [ "$INIT" = "systemd" ] || return 1
  cat > "/etc/systemd/system/${name}.service" <<EOF
[Unit]
Description=${name} (generated by vps-hardening)

[Service]
Type=oneshot
ExecStart=${cmd}
EOF
  cat > "/etc/systemd/system/${name}.timer" <<EOF
[Unit]
Description=${name} timer (generated by vps-hardening)

[Timer]
OnCalendar=${sched}
Persistent=true

[Install]
WantedBy=timers.target
EOF
  svc_daemon_reload
  systemctl enable --now "${name}.timer" >/dev/null 2>&1
}

svc_list_running() {
  case "$INIT" in
    systemd) systemctl --type=service --state=running 2>/dev/null ;;
    openrc)  rc-status --servicedir /etc/init.d 2>/dev/null | head -n 60 ;;
    sysv)    service --status-all 2>&1 | head -n 60 ;;
    runit)   sv status /var/service/* 2>/dev/null | head -n 60 ;;
    bsd)     service -l 2>/dev/null | head -n 60 ;;
  esac
}

#------------------------------ 网络信息 ------------------------------#

net_addrs() {
  if need_cmd ip; then ip -br addr 2>/dev/null
  elif need_cmd ifconfig; then ifconfig -a 2>/dev/null | grep -E '^[a-z]|inet'
  else return 1; fi
}

net_listen() {
  if need_cmd ss; then ss -lntup 2>/dev/null || ss -lntu 2>/dev/null
  elif need_cmd netstat; then netstat -lntup 2>/dev/null || netstat -lntu 2>/dev/null
  elif need_cmd sockstat; then sockstat -4 -l 2>/dev/null     # FreeBSD
  else return 1; fi
}

# 端口是否在监听（用于重启 SSH 后的验证）
listen_port_ok() {
  local port="$1" out=""
  if need_cmd ss; then out=$(ss -ltn 2>/dev/null)
  elif need_cmd netstat; then out=$(netstat -ltn 2>/dev/null)
  elif need_cmd sockstat; then out=$(sockstat -4 -l 2>/dev/null)
  else
    # 没有工具时不要“当作成功”：交给调用方用服务状态判断
    return 2
  fi
  printf '%s\n' "$out" | grep -Eq "[:.]${port}[[:space:]]"
}

all_ssh_ports() {
  {
    [ -n "$SSHD_BIN" ] && "$SSHD_BIN" -T 2>/dev/null | awk '/^port /{print $2}'
    if [ "$INIT" = "systemd" ] && need_cmd systemctl; then
      systemctl show -p Listen --value ssh.socket 2>/dev/null | tr ' ' '\n' \
        | sed -n 's/.*[:.]\([0-9]\{1,5\}\)$/\1/p'
      systemctl show -p ListenStream --value sshd.socket 2>/dev/null | tr ' ' '\n' \
        | sed -n 's/.*[:.]\([0-9]\{1,5\}\)$/\1/p'
    fi
    # BSD：从配置文件里取
    if [ "$PLAT_FAMILY" = "bsd" ] && [ -r /etc/ssh/sshd_config ]; then
      awk '/^[[:space:]]*Port[[:space:]]/{print $2}' /etc/ssh/sshd_config
    fi
  } | grep -E '^[0-9]+$' | sort -un
}

current_session_port() {
  local p=""
  if [ -n "${SSH_CONNECTION:-}" ]; then
    p=${SSH_CONNECTION##* }
  elif [ -n "${SSH_CLIENT:-}" ]; then
    p=$(printf '%s' "$SSH_CLIENT" | awk '{print $3}')
  fi
  if ! printf '%s' "$p" | grep -qE '^[0-9]+$'; then
    if need_cmd ss; then
      p=$(ss -tnp 2>/dev/null | awk '/sshd/{print $4}' | sed -n 's/.*[:.]\([0-9]\{1,5\}\)$/\1/p' | head -n1)
    elif need_cmd netstat; then
      p=$(netstat -tnp 2>/dev/null | awk '/sshd/{print $4}' | sed -n 's/.*[.:]\([0-9]\{1,5\}\)$/\1/p' | head -n1)
    fi
  fi
  printf '%s' "$p"
}

valid_ipv4() {
  local ip="$1" o
  printf '%s' "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
  for o in ${ip//./ }; do
    case "$o" in ''|*[!0-9]*) return 1 ;; esac
    o=$((10#$o))
    [ "$o" -le 255 ] || return 1
  done
  return 0
}

valid_ipv6() {
  local ip="$1" groups n
  case "$ip" in
    *:*) : ;;
    *) return 1 ;;
  esac
  printf '%s' "$ip" | grep -qE '^[0-9a-fA-F:]+$' || return 1
  case "$ip" in *:::*|*::*::*) return 1 ;; esac          # 最多一个 ::
  # 逐段检查：每段 ≤4 位十六进制
  for groups in ${ip//:/ }; do
    [ ${#groups} -le 4 ] || return 1
  done
  n=$(printf '%s' "$ip" | awk -F: '{print NF-1}')
  case "$ip" in
    *::*) [ "$n" -le 8 ] || return 1 ;;
    *)    [ "$n" -eq 7 ] || return 1 ;;
  esac
  return 0
}

#------------------------------ 防火墙 ------------------------------#

fw_detect() {
  FW_BACKEND=""; FW_WHY=""
  local forced="${VPS_FW:-}"

  # 1) 已在运行的防火墙优先
  if need_cmd firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    FW_BACKEND=firewalld; FW_WHY="firewalld 正在运行（本机现有防火墙，优先沿用）"
  elif need_cmd ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    FW_BACKEND=ufw; FW_WHY="ufw 已启用（本机现有防火墙，优先沿用）"
  fi

  # 2) 按发行版默认
  if [ -z "$FW_BACKEND" ]; then
    case "$PLAT_FAMILY" in
      debian) if need_cmd ufw || [ -n "$PKG" ]; then FW_BACKEND=ufw; FW_WHY="Debian 系默认使用 ufw"; fi ;;
      rhel)   if need_cmd firewall-cmd || need_cmd firewall-offline-cmd; then FW_BACKEND=firewalld; FW_WHY="RHEL 系默认使用 firewalld"; fi ;;
      suse)   if need_cmd firewall-cmd; then FW_BACKEND=firewalld; FW_WHY="SUSE 默认使用 firewalld"; fi ;;
      arch)   if need_cmd ufw; then FW_BACKEND=ufw; FW_WHY="Arch 上检测到 ufw"
              elif need_cmd firewall-cmd; then FW_BACKEND=firewalld; FW_WHY="Arch 上检测到 firewalld"
              elif need_cmd nft; then FW_BACKEND=manual; FW_WHY="仅检测到 nftables：直接改写全局规则集可能破坏 Docker/既有规则，故交给你手工配置"
              fi ;;
      alpine) if need_cmd ufw; then FW_BACKEND=ufw; FW_WHY="Alpine 上检测到 ufw"; else FW_BACKEND=none; FW_WHY="Alpine 默认无防火墙，可 apk add ufw"; fi ;;
      bsd)    FW_BACKEND=manual; FW_WHY="BSD 使用 pf，需手工配置（脚本不自动改 pf.conf）" ;;
    esac
  fi

  # 3) 兜底
  if [ -z "$FW_BACKEND" ]; then
    if need_cmd ufw; then FW_BACKEND=ufw; FW_WHY="检测到 ufw"
    elif need_cmd firewall-cmd; then FW_BACKEND=firewalld; FW_WHY="检测到 firewalld"
    else FW_BACKEND=manual; FW_WHY="未检测到 ufw/firewalld，需要手工配置防火墙"; fi
  fi
  # firewalld 后端必须要有在线客户端 firewall-cmd（只有 firewall-offline-cmd 时无法在线加规则）
  if [ "$FW_BACKEND" = "firewalld" ] && ! need_cmd firewall-cmd; then
    FW_BACKEND=manual
    FW_WHY="只找到 firewall-offline-cmd（离线工具），脚本需要在线 firewall-cmd"
  fi

  # 4) 环境变量强制覆盖（VPS_FW=ufw|firewalld|nftables|iptables|manual|none）
  case "$forced" in
    ufw|firewalld|manual|none) FW_BACKEND="$forced"; FW_WHY="由 VPS_FW 指定" ;;
    iptables) FW_BACKEND=iptables; FW_WHY="由 VPS_FW 指定（注意与 Docker 的兼容性）" ;;
    nftables) FW_BACKEND=manual; FW_WHY="由 VPS_FW=nftables：为避免破坏 Docker/既有规则，脚本不自动改写全局规则集" ;;
  esac
  return 0
}

fw_is_active() {
  case "$FW_BACKEND" in
    ufw)       ufw status 2>/dev/null | grep -qi '^Status: active' ;;
    firewalld) firewall-cmd --state >/dev/null 2>&1 ;;
    nftables)  [ -n "$(nft list ruleset 2>/dev/null)" ] ;;
    iptables)  iptables -S 2>/dev/null | grep -q -- '-A INPUT' ;;
    *)         return 1 ;;
  esac
}

fw_enable() {
  case "$FW_BACKEND" in
    ufw)       ufw --force enable ;;
    firewalld) svc_enable_now firewalld; firewall-cmd --reload >/dev/null 2>&1 || true ;;
    nftables)  nft -f /etc/nftables.conf ;;
    iptables)  fw_iptables_persist ;;
    *)         return 1 ;;
  esac
}

fw_allow_port() {
  local port="$1" proto="${2:-tcp}"
  case "$FW_BACKEND" in
    ufw)       ufw allow "${port}/${proto}" ;;
    firewalld) firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null && firewall-cmd --reload >/dev/null ;;
    iptables)  iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null \
                 || iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT ;;
    *)         fw_manual_note; return 1 ;;
  esac
}

fw_delete_port() {
  local port="$1" proto="${2:-tcp}"
  case "$FW_BACKEND" in
    ufw)       ufw delete allow "${port}/${proto}" ;;
    firewalld) firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null && firewall-cmd --reload >/dev/null ;;
    iptables)  iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null ;;
    *)         return 1 ;;
  esac
}

fw_allow_from() {
  local ip="$1" port="$2" proto="${3:-tcp}"
  case "$FW_BACKEND" in
    ufw)       ufw allow from "$ip" to any port "$port" proto "$proto" ;;
    firewalld) firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$ip\" port port=\"$port\" protocol=\"$proto\" accept" >/dev/null \
                 && firewall-cmd --reload >/dev/null ;;
    iptables)  iptables -I INPUT -s "$ip" -p "$proto" --dport "$port" -j ACCEPT ;;
    *)         return 1 ;;
  esac
}

fw_rule_has_port() {
  local port="$1" proto="${2:-tcp}"
  case "$FW_BACKEND" in
    ufw)       ufw show added 2>/dev/null | grep -q "^ufw allow ${port}/${proto}\$" ;;
    firewalld) firewall-cmd --permanent --query-port="${port}/${proto}" >/dev/null 2>&1 ;;
    iptables)  iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null ;;
    *)         return 1 ;;
  esac
}

fw_has_global_port() {
  local port="$1" proto="${2:-tcp}"
  case "$FW_BACKEND" in
    ufw)       ufw status 2>/dev/null | grep -Eq "^${port}/${proto}[[:space:]]+ALLOW[[:space:]]+Anywhere" ;;
    firewalld) firewall-cmd --permanent --query-port="${port}/${proto}" >/dev/null 2>&1 ;;
    iptables)  iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null ;;
    *)         return 1 ;;
  esac
}

fw_defaults_deny_incoming() {
  case "$FW_BACKEND" in
    ufw)       ufw default deny incoming && ufw default allow outgoing ;;
    firewalld) firewall-cmd --permanent --zone=public --set-target=default >/dev/null 2>&1 || true ;;
    iptables)  iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT ;;
    *)         return 1 ;;
  esac
}

fw_show() {
  case "$FW_BACKEND" in
    ufw)       ufw status numbered ;;
    firewalld) firewall-cmd --list-all ;;
    iptables)  iptables -S ;;
  esac
}

fw_manual_note() {
  warn "本平台不自动配置防火墙（$FW_WHY）。"
  info "手工参考（按你的实际 SSH 端口替换 <PORT>）："
  case "$PLAT_FAMILY" in
    bsd)
      if [ "$PLAT_ID" = "freebsd" ]; then
        info "  FreeBSD(pf): 编辑 /etc/pf.conf，加入  pass in proto tcp to any port <PORT>"
        info "               然后 sysrc pf_enable=YES && service pf start"
      else
        info "  OpenBSD(pf): 编辑 /etc/pf.conf，加入  pass in proto tcp to any port <PORT>"
        info "               然后 pfctl -f /etc/pf.conf"
      fi ;;
    alpine)
      info "  Alpine : apk add ufw && ufw allow <PORT>/tcp && ufw default deny incoming && ufw enable" ;;
    *)
      info "  nftables: 在现有规则集中为 SSH 端口加 accept，并把 input 链默认策略设为 drop"
      info "            例：nft add rule inet filter input tcp dport <PORT> accept"
      info "            注意：不要整表 flush，否则会清掉 Docker 等程序写入的规则"
      info "  firewalld: firewall-cmd --permanent --add-port=<PORT>/tcp && firewall-cmd --reload"
      info "  ufw     : ufw allow <PORT>/tcp && ufw default deny incoming && ufw enable" ;;
  esac
}

# ---- iptables：规则 + 持久化 ----
fw_iptables_persist() {
  case "$PLAT_FAMILY" in
    debian)
      if need_cmd netfilter-persistent; then netfilter-persistent save
      elif [ -d /etc/iptables ]; then iptables-save > /etc/iptables/rules.v4; ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
      else warn "未找到 netfilter-persistent：规则重启后会丢失，请安装 iptables-persistent。"; fi ;;
    rhel)
      if [ -d /etc/sysconfig ]; then iptables-save > /etc/sysconfig/iptables; svc_enable_only iptables || true
      else warn "未找到 /etc/sysconfig：请确认 iptables-services 已安装以持久化规则。"; fi ;;
    *)
      warn "该发行版未自动持久化 iptables 规则，请自行保存（例如写入开机脚本）。" ;;
  esac
}

#------------------------------ SSH / sshd ------------------------------#

plat_detect_ssh() {
  SSHD_BIN=""
  local p
  if need_cmd sshd; then SSHD_BIN=$(command -v sshd)
  else
    for p in /usr/sbin/sshd /usr/local/sbin/sshd /usr/lib/ssh/sshd /usr/libexec/sshd; do
      [ -x "$p" ] && { SSHD_BIN="$p"; break; }
    done
  fi

  SSHD_VER=""
  if [ -n "$SSHD_BIN" ]; then
    SSHD_VER=$("$SSHD_BIN" -V 2>&1 | head -n1 | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+/) {print $i; exit}}')
  fi
  if [ -z "$SSHD_VER" ] && need_cmd ssh; then
    SSHD_VER=$(ssh -V 2>&1 | head -n1 | sed -n 's/.*OpenSSH_\([0-9][0-9.]*\).*/\1/p')
  fi

  # sshd -T 支持情况（OpenSSH >= 6.8）
  SSHD_T_OK=0
  if [ -n "$SSHD_BIN" ] && "$SSHD_BIN" -T >/dev/null 2>&1; then SSHD_T_OK=1; fi

  # 版本相关的键盘交互认证关键字（8.7 起改名）
  local vmaj vmin
  vmaj=$(printf '%s' "$SSHD_VER" | cut -d. -f1)
  vmin=$(printf '%s' "$SSHD_VER" | cut -d. -f2)
  if [ -n "$vmaj" ] && [ -n "$vmin" ] && { [ "$vmaj" -gt 8 ] || { [ "$vmaj" -eq 8 ] && [ "$vmin" -ge 7 ]; }; }; then
    SSH_KBD_KEY=KbdInteractiveAuthentication
  elif [ -n "$vmaj" ]; then
    SSH_KBD_KEY=ChallengeResponseAuthentication
  else
    SSH_KBD_KEY=KbdInteractiveAuthentication     # 未知版本先按新版写，sshd -t 会兜底纠正
  fi

  # 服务名
  SSH_SVC=""
  for cand in ssh sshd; do
    if svc_exists "$cand"; then SSH_SVC="$cand"; break; fi
  done
  [ -z "$SSH_SVC" ] && SSH_SVC=ssh

  SSH_SOCKET=""
  if [ "$INIT" = "systemd" ]; then
    for sock in ssh.socket sshd.socket; do
      if systemctl list-unit-files 2>/dev/null | grep -q "^${sock}[[:space:]]"; then SSH_SOCKET="$sock"; break; fi
    done
  fi
}

# 选择并准备“我们管理的 sshd 配置文件”；设置 SSH_CONF（路径）与 SSH_CONF_MODE（dropin|direct）
# 返回 1 表示无法安全地管理 sshd 配置（调用方应中止）
ssh_conf_prepare() {
  local main_conf=/etc/ssh/sshd_config dropin_dir=/etc/ssh/sshd_config.d
  [ -f "$main_conf" ] || { err "未找到 $main_conf"; return 1; }

  # 备份一次（保留原始副本）
  if [ ! -f "${main_conf}.vps-hardening.bak" ]; then
    cp -a "$main_conf" "${main_conf}.vps-hardening.bak" 2>/dev/null \
      && info "已备份原配置到 ${main_conf}.vps-hardening.bak"
  fi

  if [ "$PLAT_FAMILY" = "bsd" ]; then
    SSH_CONF="$main_conf"; SSH_CONF_MODE=direct
    return 0
  fi

  mkdir -p "$dropin_dir" 2>/dev/null || true

  # 情况 1：sshd_config 已经 Include drop-in 目录（Debian 系新版本、RHEL 9、Arch、SUSE 等）
  if grep -Eq "^[[:space:]]*Include[[:space:]]+${dropin_dir}/\*\.conf" "$main_conf" 2>/dev/null; then
    SSH_CONF="$dropin_dir/00-vps-hardening.conf"; SSH_CONF_MODE=dropin
    return 0
  fi

  # 情况 2：drop-in 目录存在但我们没被 Include —— 在文件最前面注入 Include（首值生效，放最前才有优先级）
  if [ -d "$dropin_dir" ] || mkdir -p "$dropin_dir" 2>/dev/null; then
    if grep -q '^# Managed by vps-hardening' "$main_conf" 2>/dev/null; then
      SSH_CONF="$dropin_dir/00-vps-hardening.conf"; SSH_CONF_MODE=dropin
      return 0
    fi
    # 若目录里已有别人的 drop-in：注入 Include 会改变它们的优先级（它们会优先于主配置），
    # 这是有实际影响的改动，必须先让人确认，否则退回“直改主配置”模式。
    local others=0
    others=$(find "$dropin_dir" -maxdepth 1 -name '*.conf' ! -name '00-vps-hardening.conf' 2>/dev/null | wc -l | tr -d ' ')
    if [ "${others:-0}" != "0" ]; then
      warn "$dropin_dir 中已有 ${others} 个其它配置文件，而主配置尚未 Include 该目录。"
      warn "注入 Include 会让这些文件（例如 50-cloud-init.conf）开始生效并优先于主配置。"
      if ! confirm_timed "仍然注入 Include（按 drop-in 方式管理）？" 20 n; then
        SSH_CONF="$main_conf"; SSH_CONF_MODE=direct
        info "已改为直接维护 $main_conf（会注释冲突项并写入带标记的块）。"
        return 0
      fi
    fi
    local tmp
    tmp=$(mktemp) || return 1
    { echo '# Managed by vps-hardening: include drop-ins first (first-value-wins)'
      echo "Include ${dropin_dir}/*.conf"
      cat "$main_conf"
    } > "$tmp" && cat "$tmp" > "$main_conf" && rm -f "$tmp"
    SSH_INCLUDE_INJECTED=1        # 记录：中止时需要把这段注入撤掉
    SSH_CONF="$dropin_dir/00-vps-hardening.conf"; SSH_CONF_MODE=dropin
    return 0
  fi

  # 情况 3：老系统 —— 直接改主配置（注释掉冲突项，再追加我们的块）
  SSH_CONF="$main_conf"; SSH_CONF_MODE=direct
  return 0
}

# 直接改主配置时：注释掉与加固相关的旧指令（幂等，大小写不敏感）
ssh_direct_comment_conflicts() {
  local conf="$1" tmp
  [ "$SSH_CONF_MODE" = direct ] || return 0
  tmp=$(mktemp) || return 1
  awk '
    { low = tolower($0); sub(/^[ \t]+/, "", low) }
    low ~ /^#/ { print; next }
    low ~ /^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|pubkeyauthentication|maxauthtries|logingracetime|allowusers|x11forwarding|permitemptypasswords)[ \t]/ { print "# vps-hardening: " $0; next }
    { print }
  ' "$conf" > "$tmp" && cat "$tmp" > "$conf" && rm -f "$tmp"
}

# 语法检查；输出写入 SSHD_TEST_OUT
sshd_test() {
  [ -n "$SSHD_BIN" ] || return 2
  SSHD_TEST_OUT=$("$SSHD_BIN" -t 2>&1)
  local rc=$?
  return $rc
}

# 生效值查询：sshd -T 可用时返回其输出，否则回退为读取我们管理的配置片段
sshd_effective_dump() {
  if [ "$SSHD_T_OK" = "1" ]; then
    "$SSHD_BIN" -T 2>/dev/null
  else
    printf '%s\n' "# sshd -T 不可用（OpenSSH < 6.8），以下为配置文件中的相关行："
    grep -Ei '^[[:space:]]*(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|pubkeyauthentication|maxauthtries|logingracetime|allowusers|x11forwarding|permitemptypasswords)' "$SSH_CONF" 2>/dev/null
  fi
}

# 校验某个生效值（key value）；sshd -T 不可用时退化为检查我们写入的配置文件
ssh_effective_is() {
  local key="$1" want="$2"
  if [ "$SSHD_T_OK" = "1" ]; then
    "$SSHD_BIN" -T 2>/dev/null | grep -qi "^${key} ${want}\$"
  else
    grep -Eiq "^[[:space:]]*${key}[[:space:]]+${want}[[:space:]]*\$" "$SSH_CONF" 2>/dev/null
  fi
}

ssh_effective_has_user() {
  local user="$1"
  if [ "$SSHD_T_OK" = "1" ]; then
    "$SSHD_BIN" -T 2>/dev/null | awk -v u="$user" '$1=="allowusers"{for(i=2;i<=NF;i++) if($i==u) f=1} END{exit !f}'
  else
    grep -Ei "^[[:space:]]*AllowUsers[[:space:]]" "$SSH_CONF" 2>/dev/null \
      | awk -v u="$user" '{for(i=2;i<=NF;i++) if($i==u) f=1} END{exit !f}'
  fi
}

# 当 sshd -T 不可用（OpenSSH < 6.8）时，额外检查有没有“比我们更早生效”的 drop-in 覆盖我们的设置
ssh_conf_conflict_scan() {
  [ "$SSH_CONF_MODE" = "dropin" ] || return 0
  [ "$SSHD_T_OK" = "1" ] && return 0
  local keys="PermitRootLogin|PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PubkeyAuthentication|MaxAuthTries|LoginGraceTime|AllowUsers|X11Forwarding|PermitEmptyPasswords"
  local dir base f conflicts=""
  dir=$(dirname "$SSH_CONF"); base=$(basename "$SSH_CONF")
  for f in $(ls -1 "$dir"/*.conf 2>/dev/null | sort); do
    [ "$(basename "$f")" = "$base" ] && break      # 到达我们的文件即停止（我们是第一个生效者）
    if grep -Eq "^[[:space:]]*(${keys})[[:space:]]" "$f" 2>/dev/null; then
      conflicts="$conflicts $f"
    fi
  done
  if [ -n "$conflicts" ]; then
    err "以下配置文件的字典序在本脚本之前，会优先于我们的设置（且本机 sshd 不支持 -T 校验）："
    printf '%s\n' $conflicts | sed 's/^/  /'
    info "请手工处理（改名/删除/合并）后重试。"
    return 1
  fi
  return 0
}

# 应用配置：重新加载/重启监听进程，然后验证端口仍在监听
ssh_apply_and_verify() {
  local ports="$1" unit="" p listening=0 probe=0 rc=0
  svc_daemon_reload

  if [ "$INIT" = "systemd" ]; then
    if [ -n "$SSH_SOCKET" ] && systemctl is-enabled --quiet "$SSH_SOCKET" 2>/dev/null; then
      systemctl restart "$SSH_SOCKET" 2>/dev/null && unit="$SSH_SOCKET"
    fi
    if [ -z "$unit" ] || systemctl is-enabled --quiet "${SSH_SVC}.service" 2>/dev/null; then
      systemctl try-restart "${SSH_SVC}.service" >/dev/null 2>&1 || true
      [ -z "$unit" ] && unit="${SSH_SVC}.service"
    fi
    if [ -z "$unit" ]; then
      if systemctl restart "${SSH_SVC}.service" >/dev/null 2>&1; then unit="${SSH_SVC}.service"; fi
    fi
    # 兜底：socket 激活场景下 service 平时是 inactive，别把它当成失败
    [ -n "$unit" ] || unit="$SSH_SVC"
  else
    if svc_restart "$SSH_SVC" >/dev/null 2>&1; then
      unit="$SSH_SVC"
      rc=0
    else
      rc=1
      unit="$SSH_SVC"
    fi
  fi

  sleep 2
  [ -n "$ports" ] || ports=$(all_ssh_ports)

  for p in $ports; do
    listen_port_ok "$p"
    case $? in
      0) listening=1 ;;
      2) probe=1 ;;      # 无法探测
    esac
  done

  if [ "$listening" = "1" ]; then
    ok "配置已应用：${unit:-$SSH_SVC} 正在监听 $(printf '%s' "$ports" | tr '\n' ' ')"
    return 0
  fi

  # 探测不到时：用服务状态兜底，但必须确实与重启结果一致，不能“当作成功”
  if [ "$probe" = "1" ] && [ "$rc" = "0" ] && svc_active "$SSH_SVC"; then
    warn "本机缺少 ss/netstat/sockstat，无法验证端口监听；已确认 $SSH_SVC 处于运行状态。"
    return 0
  fi

  err "未检测到 SSH 端口在监听（可能是重启失败或端口探测工具缺失）！"
  err "请勿断开当前连接，立即用厂商 Console 检查："
  case "$INIT" in
    systemd) err "  journalctl -u ${SSH_SVC} --no-pager | tail -n 20" ;;
    openrc)  err "  rc-service $SSH_SVC status" ;;
    bsd)     err "  service $SSH_SVC status   （OpenBSD 用 rcctl check sshd）" ;;
    *)       err "  $SSHD_BIN -t 以及系统日志（/var/log/auth.log 或 /var/log/secure）" ;;
  esac
  return 1
}

# 应用失败后的自愈：确保 sshd（及其 socket 单元）真的被拉起来，并再次验证
ssh_recover_after_failure() {
  svc_start "$SSH_SVC" >/dev/null 2>&1 || true
  if [ "$INIT" = "systemd" ] && [ -n "$SSH_SOCKET" ]; then
    systemctl start "$SSH_SOCKET" >/dev/null 2>&1 || true
  fi
  sleep 2
  local p ports
  ports=$(all_ssh_ports)
  for p in $ports; do
    if listen_port_ok "$p"; then ok "SSH 已恢复监听端口 $p。"; return 0; fi
  done
  if svc_active "$SSH_SVC"; then warn "SSH 服务状态为运行中，但端口未探测到（可能缺少探测工具）。"; return 0; fi
  err "SSH 仍未恢复：请立即使用厂商 Console 登录，执行 $SSHD_BIN -t 检查配置，并查看 $SSH_CONF 与 ${SSH_CONF}.failed"
  return 1
}

#------------------------------ 重启需求 / 自动更新 ------------------------------#

# 返回 yes / no / unknown
reboot_required() {
  case "$PLAT_FAMILY" in
    debian)
      [ -f /var/run/reboot-required ] && { echo yes; return; }
      echo no; return ;;
    rhel)
      if need_cmd needs-restarting; then
        if needs-restarting -r >/dev/null 2>&1; then echo no; else echo yes; fi
      else echo unknown; fi
      return ;;
    suse)
      # zypper needs-rebooting 的退出码在不同版本/语言下不可靠，这里不猜测
      echo unknown; return ;;
    arch)
      local running newest
      running=$(uname -r)
      newest=$(ls -1 /usr/lib/modules 2>/dev/null | sort -V | tail -n1)
      if [ -n "$newest" ] && [ "$running" != "$newest" ]; then echo yes; else echo no; fi
      return ;;
    bsd)
      if [ "$PLAT_ID" = "freebsd" ] && need_cmd freebsd-version; then
        if [ "$(freebsd-version -k 2>/dev/null)" != "$(uname -r)" ]; then echo yes; else echo no; fi
      else echo unknown; fi
      return ;;
    *) echo unknown; return ;;
  esac
}

# 配置自动安全更新；返回 0 表示已配置，1 表示该平台需手工处理
auto_updates_setup() {
  case "$PLAT_FAMILY" in
    debian)
      pkg_has unattended-upgrades || pkg_install unattended-upgrades || return 1
      printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
        > /etc/apt/apt.conf.d/20auto-upgrades
      if need_cmd dpkg-reconfigure; then dpkg-reconfigure -f noninteractive -plow unattended-upgrades >/dev/null 2>&1 || true; fi
      if svc_exists unattended-upgrades; then svc_enable_now unattended-upgrades >/dev/null 2>&1 || true; fi
      return 0 ;;
    rhel)
      if [ "$PKG" = "dnf" ]; then
        pkg_has dnf-automatic || pkg_install dnf-automatic || return 1
        local conf=/etc/dnf/automatic.conf
        [ -f "$conf" ] && [ ! -f "${conf}.vps-hardening.bak" ] && cp -a "$conf" "${conf}.vps-hardening.bak"
        if [ -f "$conf" ]; then
          awk '{ if ($0 ~ /^[[:space:]]*upgrade_type[[:space:]]*=/) print "upgrade_type = security";
                 else if ($0 ~ /^[[:space:]]*apply_updates[[:space:]]*=/) print "apply_updates = yes";
                 else print }' "$conf" > "${conf}.tmp" && mv "${conf}.tmp" "$conf"
        fi
        svc_enable_now dnf-automatic.timer >/dev/null 2>&1 || svc_enable_now dnf-automatic >/dev/null 2>&1 || return 1
        return 0
      fi
      pkg_has yum-cron || pkg_install yum-cron || return 1
      [ -f /etc/yum/yum-cron.conf ] && awk '{ if ($0 ~ /^[[:space:]]*apply_updates[[:space:]]*=/) print "apply_updates = yes"; else print }' /etc/yum/yum-cron.conf > /etc/yum/yum-cron.conf.tmp && mv /etc/yum/yum-cron.conf.tmp /etc/yum/yum-cron.conf
      svc_enable_now yum-cron >/dev/null 2>&1 || return 1
      return 0 ;;
    alpine)
      mkdir -p /etc/periodic/daily
      cat > /etc/periodic/daily/vps-security-update <<'EOF'
#!/bin/sh
# 由 vps-hardening 生成：每日应用 Alpine 安全更新
apk update && apk upgrade --available
EOF
      chmod 755 /etc/periodic/daily/vps-security-update
      if svc_exists crond; then svc_enable_now crond >/dev/null 2>&1 || true; fi
      return 0 ;;
    suse)
      if install_systemd_timer vps-security-update "daily" "/usr/bin/zypper --non-interactive patch"; then
        return 0
      fi
      mkdir -p /etc/cron.daily
      cat > /etc/cron.daily/vps-security-update <<'EOF'
#!/bin/sh
# 由 vps-hardening 生成：每日应用 SUSE 补丁
zypper --non-interactive patch
EOF
      chmod 755 /etc/cron.daily/vps-security-update
      return 0 ;;
    arch|void|gentoo|bsd)
      return 1 ;;   # 这些平台不提供“无人值守自动升级”官方机制，由调用方提示手工方案
    *) return 1 ;;
  esac
}

auto_updates_manual_hint() {
  case "$PLAT_FAMILY" in
    arch)
      info "Arch 不支持无人值守全量升级（容易造成部分升级）。建议你定期手动执行："
      info "  sudo pacman -Syu"
      info "  或安装 arch-audit 关注安全公告：sudo pacman -S arch-audit && arch-audit" ;;
    void)
      info "Void 建议手工定期执行：sudo xbps-install -Su" ;;
    gentoo)
      info "Gentoo 建议手工定期执行：sudo emerge -uDN @world（升级前先 eselect news read）" ;;
    bsd)
      if [ "$PLAT_ID" = "freebsd" ]; then
        info "FreeBSD 建议："
        info "  sudo freebsd-update fetch install      # 系统补丁"
        info "  sudo pkg upgrade -y                    # 软件包"
        info "  可用 cron 定期执行：freebsd-update cron"
      else
        info "OpenBSD 建议：sudo syspatch && sudo pkg_add -u"
      fi ;;
    *) info "该平台未实现自动安全更新，请按发行版文档手工配置。" ;;
  esac
}
