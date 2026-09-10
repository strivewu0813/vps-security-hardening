#!/usr/bin/env bash
#=============================================================================
# vps-hardening.sh — 新 VPS 基础安全一键加固（跨 Linux 发行版 / BSD）
#
# 支持两种登录模式：
#   --mode key        使用 SSH Key 登录，关闭密码认证（默认，最安全）
#   --mode password   保持“用户名 + 密码”登录（等价于旧的 no-key 版本）
#   别名：--key / --no-key
#
# 支持的平台（自动检测，逐步降级）：
#   Debian/Ubuntu/Mint/Kali、RHEL/CentOS/Rocky/Alma/Fedora/Amazon、openSUSE/SLES、
#   Arch/Manjaro、Alpine、Gentoo、Void、FreeBSD/OpenBSD/NetBSD/DragonFly
#   包管理器：apt/dnf/yum/zypper/pacman/apk/emerge/xbps/pkg/pkg_add
#   init：systemd/openrc/sysv/runit/BSD rc
#   防火墙：ufw/firewalld/nftables/iptables（BSD 的 pf 给出手工指引）
#
# 用法：
#   sudo bash vps-hardening.sh                      # 交互式菜单（Key 模式）
#   sudo bash vps-hardening.sh --mode password       # 密码登录模式
#   sudo bash vps-hardening.sh --auto                # 顺序执行第 2~8 项
#   sudo bash vps-hardening.sh --step N              # 只执行某项（N=2..10）
#   sudo bash vps-hardening.sh --fail2ban            # 只执行第 8 项
#   sudo bash vps-hardening.sh --setup-only          # 只安装 lib 等依赖后退出
#
# 环境变量：
#   DEBUG=1        打印每条命令（排查“卡住/没有回显”）
#   FORCE=1        跳过第 5 项“新窗口已验证”的人工确认（谨慎）
#   VPS_FW=ufw|firewalld|nftables|iptables|none   强制指定防火墙后端
#   VPS_REPO / VPS_REF                            指定脚本仓库与分支（自建镜像时用）
#
# ⚠️ 安全原则（务必遵守）：
#   1. 第 1 项（厂商 Console / MFA / 快照）必须在服务商后台手动完成，脚本只提醒。
#   2. 先保留旧连接，再用【新窗口】验证新登录方式；验证通过前不要关闭旧方式。
#   3. 任何校验不通过都会中止并自动撤下未生效的配置，绝不带着坏配置重启 SSH。
#=============================================================================

set -uo pipefail

MODE="${MODE:-key}"          # key（默认，关闭密码认证）| password（保留密码登录）

REPO="${VPS_REPO:-strivewu0813/vps-security-hardening}"
REF="${VPS_REF:-main}"
CTX_FILE=/root/.vps-hardening-ctx
LOG_FILE=/var/log/vps-hardening.log

#------------------------------ 用法（放最前：即使平台层缺失 --help 也能用）------------------------------#

print_usage() {
  cat <<'EOF'
用法：
  sudo bash vps-hardening.sh                      # 交互式菜单（SSH Key 模式）
  sudo bash vps-hardening.sh --mode password      # 密码登录模式（等价 --no-key）
  sudo bash vps-hardening.sh --mode key           # SSH Key 模式（等价 --key，默认）
  sudo bash vps-hardening.sh --auto               # 顺序执行第 2~8 项（逐步确认）
  sudo bash vps-hardening.sh --step N             # 只执行某项（N=2..10，可与 --mode 组合）
  sudo bash vps-hardening.sh --fail2ban           # 只执行第 8 项
  sudo bash vps-hardening.sh --setup-only         # 只打印平台/能力报告，不修改系统

环境变量：
  DEBUG=1      打印执行的每条命令（排查“卡住/没有回显”）
  FORCE=1      跳过第 5 项“新窗口已验证”的人工确认（谨慎）
  MODE         默认模式：key 或 password
  VPS_FW=ufw|firewalld|iptables|manual|none   强制指定防火墙后端
               （nftables 会映射为 manual：脚本不自动改写全局规则集，避免破坏 Docker 规则）
  VPS_REPO / VPS_REF                 指定仓库与分支（自建镜像时用）

支持平台：Debian/Ubuntu 系、RHEL/CentOS/Rocky/Alma/Fedora/Amazon/Oracle、openSUSE/SLES、
          Arch/Manjaro、Alpine、Gentoo、Void、FreeBSD/OpenBSD/NetBSD/DragonFly
EOF
}

# -h/--help：不要求 root，也不要求平台层可用
for _a in "$@"; do
  case "$_a" in
    -h|--help) print_usage; exit 0 ;;
  esac
done
unset _a

#------------------------------ 加载平台适配层 ------------------------------#

_lib_ok() { [ -r "$1" ] && grep -q 'plat_detect' "$1" 2>/dev/null; }

load_platform_lib() {
  local self="${BASH_SOURCE[0]:-}" dir="" cand
  if [ -n "$self" ] && [ -f "$self" ]; then dir=$(cd -- "$(dirname -- "$self")" >/dev/null 2>&1 && pwd); fi
  for cand in \
    "${dir:-/nonexistent}/lib/platform.sh" \
    "${dir:-/nonexistent}/platform.sh" \
    /usr/local/lib/vps-hardening/platform.sh \
    /usr/local/lib/vps-hardening.sh
  do
    if _lib_ok "$cand"; then . "$cand"; return 0; fi
  done

  printf '%s\n' "未找到 lib/platform.sh（跨发行版适配层），尝试从 GitHub 下载……"
  local dest_dir=/usr/local/lib/vps-hardening
  local dest="$dest_dir/platform.sh"
  local tmp base url
  mkdir -p "$dest_dir" 2>/dev/null || dest=/tmp/platform.sh
  tmp=$(mktemp) || { printf '%s\n' "无法创建临时文件，请手动放置 lib/platform.sh"; exit 1; }
  for base in "https://raw.githubusercontent.com/$REPO/$REF" "https://cdn.jsdelivr.net/gh/$REPO@$REF"; do
    url="$base/lib/platform.sh"
    printf '%s\n' "下载: $url"
    if need_dl "$url" "$tmp" && _lib_ok "$tmp"; then
      cat "$tmp" > "$dest" && rm -f "$tmp" && . "$dest" && return 0
    fi
    printf '%s\n' "该来源不可用，尝试下一个……"
  done
  rm -f "$tmp"
  printf '%s\n' "无法获取 lib/platform.sh。"
  printf '%s\n' "请用 install.sh 安装，或手动下载后放在脚本同目录的 lib/ 下："
  printf '%s\n' "  curl -fsSL $REPO 的 lib/platform.sh  →  $(dirname "$0")/lib/platform.sh"
  exit 1
}

need_dl() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 15 --max-time 120 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -T 30 -O "$2" "$1"
  else return 127; fi
}

load_platform_lib

#------------------------------ 脚本级辅助 ------------------------------#

log() { printf '%s  %s\n' "$(date '+%F %T')" "$*" >> "$LOG_FILE" 2>/dev/null || true; }

abort_conf() {
  local conf="${1:-}" main_conf=/etc/ssh/sshd_config bak=""
  # 优先用本次运行的时间戳备份；兼容旧的固定名备份
  if [ -n "${SSH_BACKUP:-}" ] && [ -f "${SSH_BACKUP}" ]; then
    bak="$SSH_BACKUP"
  elif [ -f "${main_conf}.vps-hardening.bak" ]; then
    bak="${main_conf}.vps-hardening.bak"
  fi

  # 1) 如果注入过 Include，先恢复主配置（否则重启后可能因不支持的指令导致 sshd 起不来）
  if [ "${SSH_INCLUDE_INJECTED:-0}" = "1" ]; then
    if [ -n "$bak" ] && cp -a "$bak" "$main_conf"; then
      warn "已移除注入的 Include 行并恢复加固前的 $main_conf"
      SSH_INCLUDE_INJECTED=0
      if [ -n "$SSHD_BIN" ] && ! sshd_test; then
        warn "恢复后 sshd -t 仍报错，请手工检查 $main_conf："
        printf '%s\n' "${SSHD_TEST_OUT:-}" | sed 's/^/  /'
      fi
    else
      err "无法恢复 $main_conf（没有可用备份）：请立即手工检查该文件！"
      return 1
    fi
  fi

  # 2) 直改模式：从备份恢复
  if [ "${SSH_CONF_MODE:-}" = "direct" ]; then
    if [ -n "$bak" ]; then
      if cp -a "$bak" "$main_conf"; then
        warn "已恢复加固前的 $main_conf（备份: $bak）"
      else
        err "恢复 $main_conf 失败，请立即手工检查！"
        return 1
      fi
    else
      err "没有可用备份可恢复 $main_conf，请立即手工检查！"
      return 1
    fi
    return 0
  fi

  # 3) drop-in 模式：把我们写进去的文件挪走
  if [ -n "$conf" ] && [ -f "$conf" ]; then
    if mv "$conf" "${conf}.failed" 2>/dev/null; then
      warn "已把未采用的配置移到 ${conf}.failed（sshd 不再读取；确认无误后可删除）"
    else
      warn "注意：$conf 仍在原处，请手动检查或删除。"
    fi
  fi
}

pick_user() {
  NEW_USER=""
  if [ -s "$CTX_FILE" ]; then
    # shellcheck disable=SC1090
    . "$CTX_FILE"
    if [ -n "${NEW_USER:-}" ]; then
      info "上次记录的管理员用户: $NEW_USER"
      local ans=""
      printf '%b' "${C_YEL}?${C_N} 就操作该用户？[Y/n]:\n"
      read -r ans || ans=n        # EOF 一律按“否”，避免非交互场景自动接受
      case "${ans,,}" in n|no) NEW_USER="" ;; esac
    fi
  fi
  if [ -z "${NEW_USER:-}" ]; then
    ask "输入管理员用户名:" NEW_USER || return 1
  fi
  if ! printf '%s' "$NEW_USER" | grep -qE '^[a-z_][a-z0-9_-]*$'; then
    err "用户名不合法（只能用 a-z0-9_- 且以字母/下划线开头）：'$NEW_USER'"
    return 1
  fi
  if [ "$(id -u "$NEW_USER" 2>/dev/null)" = "0" ]; then
    err "不允许对 root 账户执行本流程（会让所有 SSH 登录被拒）。请先创建普通用户。"
    return 1
  fi
  return 0
}

user_shell() {
  if need_cmd getent; then getent passwd "$1" | awk -F: '{print $7}'
  else awk -F: -v u="$1" '$1==u{print $7}' /etc/passwd; fi
}

user_exists() { id "$1" >/dev/null 2>&1; }

# 0=有可用密码 1=无/锁定 2=无法判定
password_status() {
  local u="$1" st="" h=""
  if need_cmd passwd; then
    st=$(passwd -S "$u" 2>/dev/null | awk '{print $2}')
    case "$st" in
      P) return 0 ;;
      L|LK|NP) return 1 ;;
    esac
  fi
  if [ -r /etc/shadow ]; then h=$(awk -F: -v u="$u" '$1==u{print $2}' /etc/shadow)
  elif [ -r /etc/master.passwd ]; then h=$(awk -F: -v u="$u" '$1==u{print $2}' /etc/master.passwd); fi
  case "$h" in
    '') return 2 ;;
    '*'|'!'*|'*LK*'|'*LOCKED*') return 1 ;;
    \$*) return 0 ;;
    *) return 2 ;;
  esac
}

create_admin_user() {
  local u="$1" shell="/bin/bash" rc=0
  [ -x /bin/bash ] || shell=/bin/sh
  case "$PLAT_FAMILY" in
    bsd)
      if [ "$PLAT_ID" = "freebsd" ] || [ "$PLAT_ID" = "dragonfly" ]; then
        pw useradd "$u" -m -s "$shell" ${SUDO_GROUP:+-G "$SUDO_GROUP"} || rc=1
      else
        useradd -m -s "$shell" ${SUDO_GROUP:+-G "$SUDO_GROUP"} "$u" || rc=1
      fi ;;
    *)
      useradd -m -s "$shell" "$u" || rc=1 ;;
  esac
  return $rc
}

add_to_admin_group() {
  local u="$1"
  [ -n "$SUDO_GROUP" ] || { warn "未找到 sudo/wheel 组，将只依赖 sudoers 文件授权。"; return 0; }
  case "$PLAT_FAMILY" in
    bsd)
      if [ "$PLAT_ID" = "freebsd" ] || [ "$PLAT_ID" = "dragonfly" ]; then pw groupmod "$SUDO_GROUP" -m "$u" || true
      else usermod -G "$SUDO_GROUP" "$u" 2>/dev/null || true; fi ;;
    *)
      usermod -aG "$SUDO_GROUP" "$u" || true ;;
  esac
}

# 统一用 sudoers.d 授权，避免各发行版组配置差异导致 sudo 不可用
grant_sudo_via_sudoers() {
  local u="$1" f="/etc/sudoers.d/10-vps-hardening-${u}"
  mkdir -p /etc/sudoers.d 2>/dev/null || true
  printf '# 由 vps-hardening 生成\n%s ALL=(ALL:ALL) ALL\n' "$u" > "$f" || return 1
  chmod 440 "$f" 2>/dev/null || true
  if need_cmd visudo; then
    if ! visudo -cf "$f" >/dev/null 2>&1; then
      err "sudoers 语法检查失败，已删除 $f"
      rm -f "$f"
      return 1
    fi
  fi
  return 0
}

#------------------------------ 预检 ------------------------------#

os_check() {
  hdr "0. 系统与平台预检"
  plat_detect
  info "[1/5] 平台信息"
  plat_report

  if ! plat_is_supported; then
    warn "未识别的平台（$PLAT_NAME）：脚本会尽量按通用方式执行，但包管理/防火墙/自动更新可能无法自动处理。"
    confirm_timed "仍然继续？（无输入默认退出）" 20 n || { err "已退出（未做任何修改）。"; exit 0; }
  else
    if [ "$PLAT_FAMILY" = "debian" ] && [ "${PLAT_VER:-}" != "24.04" ] && [ "${PLAT_ID:-}" = "ubuntu" ]; then
      info "提示：本项目主要在 Ubuntu 24.04 上验证；您当前是 ${PLAT_NAME}，已按 Debian 系通用方式处理。"
    fi
  fi

  if [ -z "$PKG" ]; then
    warn "未识别包管理器：第 2/8 项的软件安装需要你手工完成（脚本会打印对应命令）。"
  fi
  if [ -z "$SSHD_BIN" ]; then
    err "未找到 sshd 二进制：无法加固 SSH（本机可能没装 openssh-server）。"
  fi
  if [ "$INIT" = "none" ]; then
    warn "未识别 init 系统：服务启停需要你手工执行（脚本会打印对应命令）。"
  fi

  info "[2/5] 公网 IP / 地区 / ASN（不通自动跳过，最多 8 秒）"
  if need_cmd curl; then
    curl -s --connect-timeout 4 --max-time 8 ipinfo.io || warn "ipinfo.io 不可达，已跳过。"
  else
    warn "未安装 curl，已跳过。可手动执行: curl -s ipinfo.io"
  fi

  info "[3/5] 网络地址"
  run_timed 10 net_addrs 2>/dev/null | sed 's/^/  /' || warn "无 ip/ifconfig 可用"

  info "[4/5] SSH 端口与监听端口（最多 10 秒）"
  info "  检测到的 SSH 端口: $(all_ssh_ports | tr '\n' ' ')"
  run_timed 10 net_listen 2>/dev/null | sed 's/^/  /' || warn "无 ss/netstat 可用"

  info "[5/5] 需要你手动完成的事项"
  warn "请现在就在服务商后台实际登录一次 Console / VNC，并确认快照与云防火墙入口存在。"
  ok "预检完成。"
}

#------------------------------ 第 2 项：系统更新 ------------------------------#

step2_update() {
  hdr "第 2 项：更新系统安全补丁"
  if [ -z "$PKG" ]; then
    warn "未识别包管理器，请手工更新系统后继续。"
    return 1
  fi
  info "使用包管理器: $PKG（先刷新索引，再升级；可能需要几分钟）"
  pkg_update || warn "刷新索引返回非 0（部分发行版允许），继续尝试升级……"
  if [ "$PKG" = "emerge" ]; then
    warn "Gentoo 全量升级耗时可能很长，且可能触发配置合并（etc-update）。"
    confirm "确认现在执行 emerge -uDN @world ？" || { info "已跳过系统升级，请稍后手工执行: emerge -uDN @world"; return 0; }
  fi
  pkg_upgrade_all || { err "系统升级失败，请手工处理后重试。"; return 1; }
  ok "系统软件包已更新。"

  local rr
  rr=$(reboot_required)
  case "$rr" in
    yes)
      warn "检测到需要重启（依据本发行版的判定方式）。"
      if confirm "现在重启？(重启后重新运行本脚本继续)"; then
        info "重启中……重启后重新运行: sudo bash $0 --auto"
        if [ "$INIT" = "systemd" ]; then systemctl reboot; else reboot; fi
        exit 0
      else
        warn "已选择暂不重启：部分内核/库补丁要重启后才生效。"
      fi ;;
    no) ok "当前无需重启。" ;;
    *)  info "无法自动判定是否需要重启，请自行确认（部分平台无对应机制）。" ;;
  esac

  info "配置自动安全更新……"
  if auto_updates_setup; then
    ok "已配置自动安全更新。"
  else
    warn "本平台未自动配置自动安全更新。"
    auto_updates_manual_hint
  fi
  info "注意：3X-UI / Xray 等业务程序的大版本升级，仍建议先备份 → 再升级 → 再验证。"
  info "顺带提醒：自动安全更新只覆盖系统补丁，不覆盖业务程序。"
}

#------------------------------ 第 3 项：普通 sudo 用户 ------------------------------#

step3_user() {
  hdr "第 3 项：创建普通管理员用户"
  local NEW_USER=""
  if ! need_cmd useradd && ! need_cmd pw; then
    err "系统缺少 useradd/pw，请手工创建用户后继续。"
    return 1
  fi
  while :; do
    ask "输入要创建的管理员用户名(小写字母/数字，如 alex):" NEW_USER || return 1
    if printf '%s' "$NEW_USER" | grep -qE '^[a-z_][a-z0-9_-]*$'; then break; fi
    err "用户名不合法，只能用小写字母、数字、下划线、连字符。"
  done
  if [ "$NEW_USER" = "root" ]; then
    err "不要使用 root：后续会写入 PermitRootLogin no，会导致无法登录。"
    return 1
  fi

  if user_exists "$NEW_USER"; then
    warn "用户 $NEW_USER 已存在，跳过创建（密码可在第 4 项设置）。"
  else
    create_admin_user "$NEW_USER" || { err "创建用户失败"; return 1; }
    ok "用户 $NEW_USER 已创建。"
  fi
  add_to_admin_group "$NEW_USER"

  if ! need_cmd sudo; then
    info "未安装 sudo，尝试安装……"
    if pkg_install sudo; then ok "sudo 已安装。"; else
      warn "sudo 安装失败，请手工安装（$PKG install sudo）。"
    fi
  fi
  if need_cmd sudo; then
    grant_sudo_via_sudoers "$NEW_USER" && ok "已写入 sudoers 授权: /etc/sudoers.d/10-vps-hardening-$NEW_USER" \
      || warn "sudoers 授权失败，请手工确认 $NEW_USER 有 sudo 权限。"
  fi

  info "检查: $(id "$NEW_USER" 2>&1 | sed 's/^/  /')"
  ok "第 3 项完成。"
  printf 'NEW_USER=%s\n' "$NEW_USER" > "$CTX_FILE" 2>/dev/null
  chmod 600 "$CTX_FILE" 2>/dev/null || true
}

#------------------------------ 第 4 项：登录通道 ------------------------------#

step4_password() {
  hdr "第 4 项（密码模式）：设置强密码并验证密码登录"
  GEN_PW_SAVE=""
  local NEW_USER=""
  pick_user || return 1
  user_exists "$NEW_USER" || { err "用户 $NEW_USER 不存在，请先执行第 3 项。"; return 1; }

  # 只读地查看当前生效值，不触发任何配置改动（ssh_conf_prepare 会注入 Include，放到第 5 项再做）
  info "当前 sshd 密码相关生效值:"
  if [ "$SSHD_T_OK" = "1" ]; then
    "$SSHD_BIN" -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|maxauthtries|port) ' | sed 's/^/  /'
  else
    grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|MaxAuthTries|Port)' /etc/ssh/sshd_config 2>/dev/null | sed 's/^/  /'
  fi

  local mode=""
  ask "密码设置方式: [1] 自动生成 32 位随机密码(推荐)  [2] 手动输入（默认 1）:" mode || mode=1
  case "$mode" in
    2)
      info "请为 $NEW_USER 设置密码:"
      passwd "$NEW_USER" || { err "设置密码失败"; return 1; } ;;
    *)
      [ -t 0 ] || { err "非交互终端，无法确认随机密码已保存，已中止。请选择 [2] 手动输入。"; return 1; }
      local GENPW=""
      if need_cmd openssl; then GENPW=$(openssl rand -hex 16)
      else GENPW=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32); fi
      [ -n "$GENPW" ] || { err "生成密码失败，请改用手动输入。"; return 1; }
      printf '%b' "\n${C_BLD}${C_GRN}  即将为 $NEW_USER 设置的密码: $GENPW${C_N}\n\n"
      warn "该密码只显示这一次，脚本不写入任何文件。"
      if ! confirm "已把该密码保存到密码管理器？(未保存将中止)"; then
        printf '%b' "\n${C_BLD}${C_GRN}  再显示一次: $GENPW${C_N}\n\n"
        confirm "现在已保存？(仍选 N 将中止)" || { err "已中止，密码未修改。"; return 1; }
      fi
      if need_cmd chpasswd; then
        printf '%s:%s\n' "$NEW_USER" "$GENPW" | chpasswd || { err "设置密码失败"; return 1; }
      else
        err "缺少 chpasswd，请手动执行 passwd $NEW_USER 设置上面显示的密码。"
        return 1
      fi
      GEN_PW_SAVE="$GENPW"
      ok "密码已设置。" ;;
  esac

  # 闸门：密码必须可用
  password_status "$NEW_USER"
  case $? in
    0) ok "该账户已设置可用密码。" ;;
    1) err "账户没有可用密码（锁定/无密码），密码登录必定失败，已中止。"; return 1 ;;
    *) warn "无法自动判定密码状态，请自行确认。"; confirm "仍要继续？" || return 1 ;;
  esac

  # 附加检查：登录 shell、账户有效期（能查则查）
  local sh
  sh=$(user_shell "$NEW_USER")
  case "$sh" in
    */nologin|*/false|'') err "登录 shell 是 '${sh:-空}'，无法密码登录，已中止。"; return 1 ;;
    *) info "登录 shell: $sh" ;;
  esac
  if need_cmd chage; then
    info "账户有效期 (chage -l):"
    chage -l "$NEW_USER" 2>/dev/null | sed 's/^/  /' || true
  fi

  printf 'NEW_USER=%s\n' "$NEW_USER" > "$CTX_FILE" 2>/dev/null
  chmod 600 "$CTX_FILE" 2>/dev/null || true

  ok "请在【第二个终端窗口】用【用户名 + 密码】登录验证（本窗口不要关闭！）:"
  echo "  ssh $NEW_USER@<你的服务器IP>"
  warn "第 5 项会关闭 root 的 SSH 登录，必须先确认这个普通账户能用密码登录。"
  confirm "第二个窗口已用【用户名+密码】成功登录？(未验证请选 N 中止)" || { err "已中止：请先完成密码登录验证。"; return 1; }
  ok "第 4 项完成。"
}

step4_sshkey() {
  hdr "第 4 项（Key 模式）：安装 SSH 公钥并验证"
  local NEW_USER=""
  pick_user || return 1
  user_exists "$NEW_USER" || { err "用户 $NEW_USER 不存在，请先执行第 3 项。"; return 1; }

  local homedir="" keydir="" keyfile=""
  if need_cmd getent; then homedir=$(getent passwd "$NEW_USER" | awk -F: '{print $6}')
  else homedir=$(awk -F: -v u="$NEW_USER" '$1==u{print $6}' /etc/passwd); fi
  [ -n "$homedir" ] || homedir="/home/$NEW_USER"
  keydir="$homedir/.ssh"; keyfile="$keydir/authorized_keys"
  if ! mkdir -p "$keydir" || ! chmod 700 "$keydir"; then
    err "无法创建/设置权限: $keydir（已中止，避免把公钥写到错误位置）"
    return 1
  fi

  local PUBKEY=""
  ask "请把【本机】生成的公钥【完整一行】粘贴到这里（ssh-ed25519 / ssh-rsa / ecdsa-sha2 开头）:" PUBKEY || return 1
  PUBKEY=${PUBKEY%$'\r'}
  case "$PUBKEY" in
    '') err "公钥为空。若已手工配置过公钥，可直接跳到第 5 项。"; return 1 ;;
    ssh-ed25519\ AAAA*|ssh-rsa\ AAAA*|ecdsa-sha2-*\ AAAA*|sk-*\ AAAA*) : ;;
    *)  err "不是有效的 OpenSSH 公钥行（应形如: 类型 AAAA... [注释]），已中止。"; return 1 ;;
  esac
  case "$PUBKEY" in
    ssh-rsa\ *) warn "提示：新版 OpenSSH（>=8.8）默认拒绝老式 ssh-rsa(SHA-1) 签名，RSA 密钥需客户端支持 rsa-sha2。" ;;
  esac

  if ! touch "$keyfile" || ! chmod 600 "$keyfile"; then
    err "无法创建 $keyfile（检查磁盘空间与权限后重试）"
    return 1
  fi
  if grep -qF "$PUBKEY" "$keyfile" 2>/dev/null; then
    ok "该公钥已存在，跳过写入。"
  else
    if ! printf '%s\n' "$PUBKEY" >> "$keyfile"; then
      err "写入 $keyfile 失败，已中止（不会关闭密码登录）。"
      return 1
    fi
    ok "公钥已写入 $keyfile"
  fi
  # 复核：公钥确实在文件里、权限正确，否则不允许继续（否则第 5 项可能把密码登录关掉却没有可用 Key）
  if ! grep -qF "$PUBKEY" "$keyfile" 2>/dev/null; then
    err "复核失败：$keyfile 中未找到刚写入的公钥，已中止。"
    return 1
  fi
  chmod 700 "$keydir"; chmod 600 "$keyfile"
  local grp=""
  if need_cmd id; then grp=$(id -gn "$NEW_USER" 2>/dev/null); fi
  if [ -n "$grp" ]; then
    if ! chown -R "$NEW_USER:$grp" "$keydir"; then
      err "chown $keydir 失败：属主不对会导致 sshd 的 StrictModes 拒绝该密钥，已中止。"
      return 1
    fi
  fi
  ls -la "$keydir" | sed 's/^/  /'

  ok "请在【第二个终端窗口】验证（本窗口不要关闭！）:"
  echo "  ssh $NEW_USER@<你的服务器IP>    → 登录后 whoami 应返回 $NEW_USER，sudo whoami 应返回 root"
  warn "在第二个窗口验证成功前，绝对不要继续第 5 项。"
  confirm "第二个窗口已用 SSH Key 成功登录？(未验证请选 N 中止)" || { err "已中止：请先完成新窗口验证。"; return 1; }
  printf 'NEW_USER=%s\n' "$NEW_USER" > "$CTX_FILE" 2>/dev/null
  chmod 600 "$CTX_FILE" 2>/dev/null || true
  ok "第 4 项完成。"
}

#------------------------------ 第 5 项：SSH 加固 ------------------------------#

build_ssh_block() {
  local user="$1"
  if [ "$MODE" = "password" ]; then
    cat <<EOF
# 由 vps-hardening 生成（密码登录模式）
PermitRootLogin no
PasswordAuthentication yes
${SSH_KBD_KEY} no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 60
AllowUsers $user
X11Forwarding no
EOF
  else
    cat <<EOF
# 由 vps-hardening 生成（SSH Key 模式）
PermitRootLogin no
PasswordAuthentication no
${SSH_KBD_KEY} no
PubkeyAuthentication yes
PermitEmptyPasswords no
AllowUsers $user
X11Forwarding no
EOF
  fi
}

write_ssh_conf() {
  local conf="$1" user="$2" tmp block
  if [ "$SSH_CONF_MODE" = "dropin" ]; then
    tmp=$(mktemp) || return 1
    build_ssh_block "$user" > "$tmp" && cat "$tmp" > "$conf" && rm -f "$tmp"
    return $?
  fi
  # 直改模式：注释冲突项 + 在第一个 Match 之前插入/替换我们带标记的块
  ssh_direct_comment_conflicts "$conf" || return 1
  local marker_b="vps-hardening begin" marker_e="vps-hardening end"
  tmp=$(mktemp) || return 1
  block=$(mktemp) || { rm -f "$tmp"; return 1; }
  { echo ""; echo "# ===== ${marker_b} ====="; build_ssh_block "$user"; echo "# ===== ${marker_e} ====="; } > "$block"
  # 先删除旧块（幂等）
  awk -v b="$marker_b" -v e="$marker_e" '
    index($0,b) {skip=1}
    skip!=1 {print}
    index($0,e) {skip=0}
  ' "$conf" > "$tmp" && cat "$tmp" > "$conf" || { rm -f "$tmp" "$block"; return 1; }
  # 插入到第一个 Match 之前；没有 Match 则追加到末尾（Match 段会“吞掉”后面所有指令）
  awk -v bf="$block" '
    BEGIN { while ((getline l < bf) > 0) blk = blk l "\n" }
    !done && /^[[:space:]]*Match[[:space:]]/ { printf "%s", blk; done=1 }
    { print }
    END { if (!done) printf "%s", blk }
  ' "$conf" > "$tmp" && cat "$tmp" > "$conf"
  local rc=$?
  rm -f "$tmp" "$block"
  return $rc
}

step5_sshd() {
  if [ "$MODE" = "password" ]; then
    hdr "第 5 项：关闭 root 登录 + 加固密码登录"
  else
    hdr "第 5 项：关闭 root 登录 + 关闭密码认证"
  fi
  [ -n "$SSHD_BIN" ] || { err "未找到 sshd，无法继续。"; return 1; }
  local NEW_USER=""
  pick_user || return 1
  user_exists "$NEW_USER" || { err "用户 $NEW_USER 不存在，请先执行第 3、4 项。"; return 1; }

  # 闸门 0：登录 shell 必须可用（两种模式都查；nologin 账户即使有密码/公钥也登不上）
  local sh=""
  sh=$(user_shell "$NEW_USER")
  case "$sh" in
    */nologin|*/false|'')
      err "用户 $NEW_USER 的登录 shell 是 '${sh:-空}'，无法通过 SSH 登录，已中止（避免关掉 root 登录后无人能登）。"
      return 1 ;;
    *) info "登录 shell: $sh" ;;
  esac

  # 闸门 1：登录通道必须已经可用
  if [ "$MODE" = "password" ]; then
    password_status "$NEW_USER"
    case $? in
      0) : ;;
      1) err "用户 $NEW_USER 没有可用密码，禁止继续（否则关闭 root 登录后会锁死）。请先执行第 4 项。"; return 1 ;;
      2) warn "无法自动判定密码状态（本平台不支持 passwd -S，且 shadow 记录不可读）。"
         confirm "你已经确认过该账户可以用密码登录？" || { err "已中止。"; return 1; } ;;
    esac
  else
    local homedir=""
    if need_cmd getent; then homedir=$(getent passwd "$NEW_USER" | awk -F: '{print $6}'); else homedir="/home/$NEW_USER"; fi
    [ -s "$homedir/.ssh/authorized_keys" ] || { err "未找到 $NEW_USER 的公钥，禁止关闭密码登录。请先执行第 4 项。"; return 1; }
  fi
  # 闸门 2：人工确认新窗口验证过
  if [ "${FORCE:-0}" != "1" ]; then
    if [ "$MODE" = "password" ]; then
      confirm "再次确认：$NEW_USER 已在【新窗口】用密码登录成功？" || { err "已中止。"; return 1; }
    else
      confirm "再次确认：$NEW_USER 已在【新窗口】用 SSH Key 登录成功？" || { err "已中止。"; return 1; }
    fi
  fi

  ssh_conf_prepare || { err "无法安全地管理 sshd 配置，已中止。"; return 1; }
  info "将写入: $SSH_CONF （模式: $SSH_CONF_MODE）"
  if ! write_ssh_conf "$SSH_CONF" "$NEW_USER"; then
    err "写入配置失败，已中止。"
    abort_conf "$SSH_CONF"
    return 1
  fi
  sed 's/^/  /' "$SSH_CONF" | tail -n 20

  info "检查配置语法 (sshd -t)……"
  if ! sshd_test; then
    if printf '%s' "${SSHD_TEST_OUT:-}" | grep -qi 'bad configuration option'; then
      warn "当前 OpenSSH 不认识 ${SSH_KBD_KEY}，改用旧关键字重试……"
      if [ "$SSH_KBD_KEY" = "KbdInteractiveAuthentication" ]; then
        SSH_KBD_KEY=ChallengeResponseAuthentication
      else
        SSH_KBD_KEY=KbdInteractiveAuthentication
      fi
      write_ssh_conf "$SSH_CONF" "$NEW_USER" || { err "写入配置失败。"; abort_conf "$SSH_CONF"; return 1; }
      if ! sshd_test; then
        err "sshd 配置语法仍不正确，已中止（不会重启 SSH）："
        printf '%s\n' "${SSHD_TEST_OUT:-}" | sed 's/^/  /'
        abort_conf "$SSH_CONF"
        return 1
      fi
      ok "已改用 ${SSH_KBD_KEY} 并通过语法检查。"
    else
      err "sshd 配置语法错误，已中止（不会重启 SSH）："
      printf '%s\n' "${SSHD_TEST_OUT:-}" | sed 's/^/  /'
      abort_conf "$SSH_CONF"
      return 1
    fi
  fi

  info "生效值检查:"
  sshd_effective_dump | grep -Ei '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|logingracetime|allowusers|x11forwarding) ' | sed 's/^/  /' || true

  # 老版本 OpenSSH 无法用 -T 校验时，先扫描是否有更早生效的配置会覆盖我们
  if ! ssh_conf_conflict_scan; then
    err "存在会覆盖加固设置的更早配置，已中止（不会重启 SSH）。"
    abort_conf "$SSH_CONF"
    return 1
  fi

  local fail=0
  ssh_effective_is permitrootlogin no || { err "PermitRootLogin 未生效为 no"; fail=1; }
  ssh_effective_is pubkeyauthentication yes || { err "PubkeyAuthentication 未生效为 yes"; fail=1; }
  # 关键：PasswordAuthentication no 并不足以关闭密码登录（UsePAM 下键盘交互仍可能是密码）
  ssh_effective_is "${SSH_KBD_KEY,,}" no || { err "${SSH_KBD_KEY} 未生效为 no（UsePAM 下仍可能用密码登录）"; fail=1; }
  ssh_effective_is x11forwarding no || { err "X11Forwarding 未生效为 no"; fail=1; }
  if [ "$MODE" = "password" ]; then
    ssh_effective_is passwordauthentication yes || { err "PasswordAuthentication 未生效为 yes（密码模式必须保留）"; fail=1; }
    ssh_effective_is maxauthtries 3 || { err "MaxAuthTries 未生效为 3"; fail=1; }
  else
    ssh_effective_is passwordauthentication no || { err "PasswordAuthentication 未生效为 no"; fail=1; }
  fi
  if ! ssh_effective_has_user "$NEW_USER"; then err "AllowUsers 未包含 $NEW_USER"; fail=1; fi
  if [ "$fail" = "1" ]; then
    err "生效配置与预期不符，已中止（不会重启 SSH）。"
    abort_conf "$SSH_CONF"
    return 1
  fi

  warn "即将应用新 SSH 配置（$SSH_CONF_MODE 模式）。如果是传统 sshd 模式，重启可能短暂影响当前连接，请确保厂商 Console 可用。"
  confirm "确认应用？" || {
    abort_conf "$SSH_CONF"
    err "已取消并撤下该配置。"
    return 1
  }

  local ports
  ports=$(all_ssh_ports)
  if ssh_apply_and_verify "$ports"; then
    ok "第 5 项完成。请在【新窗口】验证："
    if [ "$MODE" = "password" ]; then
      echo "  1) ssh $NEW_USER@<你的服务器IP>   → 输入密码应能登录"
    else
      echo "  1) ssh $NEW_USER@<你的服务器IP>   → 用 Key 应能登录"
    fi
    echo "  2) ssh root@<你的服务器IP>        → 应被拒绝"
    info "以后新增管理员时，记得同步把用户名加入 AllowUsers（在 $SSH_CONF 中）。"
    [ -n "${GEN_PW_SAVE:-}" ] && printf '%b' "${C_BLD}${C_GRN}  再次提醒：$NEW_USER 的密码是 $GEN_PW_SAVE${C_N}\n"
    return 0
  fi
  abort_conf "$SSH_CONF"
  warn "已撤下新配置并尝试恢复；请在 Console 中确认 SSH 可用后再重试。"
  ssh_recover_after_failure || warn "自动恢复未成功，请按上面的提示用厂商 Console 处理。"
  return 1
}

#------------------------------ 第 6 项：防火墙 ------------------------------#

step6_firewall() {
  hdr "第 6 项：配置防火墙，只开放必要端口"
  fw_detect
  info "防火墙后端: $FW_BACKEND  ($FW_WHY)"
  case "$FW_BACKEND" in
    none|"")
      fw_manual_note
      FIREWALL_SKIPPED="未自动配置（$FW_WHY）"
      warn "第 6 项未自动完成：防火墙尚未配置，请按上面的手工命令处理。后续第 7、8 项继续执行。"
      return 0 ;;
    manual)
      fw_manual_note
      FIREWALL_SKIPPED="需手工配置（$FW_BACKEND：$FW_WHY）"
      warn "第 6 项需要手工完成（脚本不会改写 pf/nft 全局规则集）。后续第 7、8 项继续执行。"
      return 0 ;;
  esac

  # 安装防火墙工具（若需要）
  case "$FW_BACKEND" in
    ufw)
      if ! need_cmd ufw; then
        info "安装 ufw ……"
        pkg_install ufw || { err "ufw 安装失败，请手工安装后重试。"; fw_manual_note; return 1; }
      fi ;;
    firewalld)
      if ! need_cmd firewall-cmd; then
        info "安装 firewalld ……"
        pkg_install firewalld || { err "firewalld 安装失败。"; return 1; }
      fi ;;
  esac
  # 注意：firewalld 这里先“不”启动。它一旦启动就会按当前区域规则开始拦截，
  # 所以必须先放行 SSH（未运行时由 fw_allow_port 用 firewall-offline-cmd 预写配置），
  # 确认规则存在之后再启动/启用，避免放行之前把新连接挡掉。

  local SSH_PORTS SESS_PORT p
  SSH_PORTS=$(all_ssh_ports)
  SESS_PORT=$(current_session_port)
  if [ -z "$SSH_PORTS" ] && [ -z "$SESS_PORT" ]; then
    err "无法确定 SSH 端口（sshd -T、socket 单元、配置文件都没给出端口，也没有可用的会话端口）。"
    err "为避免开启默认拒绝后失联，已中止。请手工运行 'sshd -T | grep -i \"^port\"' 确认真实端口后重试。"
    return 1
  fi
  [ -n "$SSH_PORTS" ] || { warn "未能自动检测端口，使用当前会话端口 $SESS_PORT。"; SSH_PORTS="$SESS_PORT"; }
  case "$SSH_PORTS" in
    ''|*[!0-9[:space:]]*) err "无法确定 SSH 端口（得到: '$SSH_PORTS'），已中止。"; return 1 ;;
  esac
  info "SSH 端口: $(printf '%s' "$SSH_PORTS" | tr '\n' ' ')"
  [ -n "$SESS_PORT" ] && info "当前会话的服务端端口: $SESS_PORT"

  # 先放行 SSH（包含会话端口），确认规则存在后再开启防火墙
  for p in $SSH_PORTS; do fw_allow_port "$p" tcp || warn "放行 $p/tcp 失败"; done
  if [ -n "$SESS_PORT" ] && ! printf '%s\n' "$SSH_PORTS" | grep -qx "$SESS_PORT"; then
    warn "当前会话端口 $SESS_PORT 不在检测到的列表内，已单独放行。"
    fw_allow_port "$SESS_PORT" tcp >/dev/null 2>&1 || true
    SSH_PORTS=$(printf '%s\n%s\n' "$SSH_PORTS" "$SESS_PORT" | sort -un)
  fi
  local rules_ok=1
  for p in $SSH_PORTS; do fw_rule_has_port "$p" tcp || rules_ok=0; done
  if [ "$rules_ok" != "1" ]; then
    err "SSH 放行规则未全部生效，已中止（避免开启默认拒绝后被锁在门外）。"
    info "请手工放行 SSH 后重试。当前规则："
    fw_show 2>/dev/null | sed 's/^/  /' || true
    return 1
  fi
  ok "已确认放行 SSH: $(printf '%s' "$SSH_PORTS" | tr '\n' ' ')"

  if ! fw_defaults_deny_incoming; then
    err "设置“默认拒绝入站”失败，已中止（避免以为已防护实际没有）。"
    return 1
  fi
  if ! fw_defaults_ok; then
    err "校验失败：默认策略不是“拒绝入站”。请手工确认后重试。"
    return 1
  fi
  ok "默认策略已设为拒绝入站（已校验）。"

  if confirm "现在是否有需要放行的业务端口？(还没装 3X-UI/Reality/Hysteria2 就选 N)"; then
    local plist="" proto=""
    ask "输入端口列表，空格分隔，例如: 443/tcp 443/udp 8080/tcp :" plist || plist=""
    for p in $plist; do
      proto=${p##*/}
      case "$proto" in tcp|udp) : ;; *) proto=tcp ;; esac
      p=${p%%/*}
      printf '%s' "$p" | grep -qE '^[0-9]{1,5}$' || { warn "跳过非法端口: $p"; continue; }
      fw_allow_port "$p" "$proto" >/dev/null 2>&1 && ok "已放行 $p/$proto" || warn "放行 $p/$proto 失败"
    done
  fi

  info "启用/重载防火墙……"
  # firewalld：规则已预写，现在才启动/启用（启动后即按区域规则拦截）
  if [ "$FW_BACKEND" = "firewalld" ] && ! fw_is_active; then
    if ! svc_enable_now firewalld >/dev/null 2>&1; then
      err "firewalld 启动失败，请手工处理（systemctl enable --now firewalld）后重试。"
      return 1
    fi
    sleep 2
    fw_is_active || { err "firewalld 仍未处于运行状态，已中止。"; return 1; }
  fi
  fw_enable || { err "启用防火墙失败，请手工处理。"; return 1; }
  if ! fw_is_active; then
    err "防火墙未处于活动状态，请立即检查（避免误以为已防护）。"
    return 1
  fi
  ok "防火墙已启用。当前规则:"
  fw_show 2>/dev/null | sed 's/^/  /' || true

  local missing=0
  for p in $SSH_PORTS; do fw_rule_has_port "$p" tcp || missing=1; done
  if [ "$missing" = "1" ]; then
    err "启用后未看到全部 SSH 放行规则！请立即用厂商 Console 检查。"
    return 1
  fi

  if [ "$MODE" = "password" ]; then
    if confirm "是否把 SSH 限制为只允许你的固定管理 IP 访问？(动态 IP 请选 N)"; then
      ssh_ip_whitelist "$SSH_PORTS" "$SESS_PORT" || warn "IP 白名单步骤未完成，已保留原有放行规则。"
    fi
  fi

  # ufw 的 IPv6 支持需要单独确认（IPV6=no 时 v6 流量不受 UFW 管理）
  if [ "$FW_BACKEND" = "ufw" ] && [ -r /etc/default/ufw ]; then
    local ipv6
    ipv6=$(grep '^IPV6=' /etc/default/ufw | tail -n1)
    info "ufw IPv6 设置: ${ipv6:-未找到 IPV6= 行}"
    case "$ipv6" in
      IPV6=yes) info "IPV6=yes：若服务器有 IPv6，请同步检查服务商 IPv6 云防火墙。" ;;
      IPV6=no)  warn "IPV6=no：UFW 不管理 IPv6 流量。若服务器启用了 IPv6，请把 /etc/default/ufw 改为 IPV6=yes 后 ufw reload。" ;;
    esac
  else
    info "IPv6 提示：请确认防火墙与云端 IPv6 规则一致（不同后端对 IPv6 支持不同）。"
  fi
  case "$FW_BACKEND" in
    iptables)
      warn "iptables 后端只管理 IPv4 规则，且会把 FORWARD 默认策略设为 DROP（可能影响转发/NAT/容器网络）；如本机做路由转发请改用 ufw/firewalld。" ;;
  esac
  warn "Docker 用户注意：Docker 会自行写 iptables，可能绕过主机防火墙；请用 docker ps 检查 PORTS 列，仅本机访问的服务绑定 127.0.0.1。"
  ok "第 6 项完成。"
}

ssh_ip_whitelist() {
  local SSH_PORTS="$1" SESS_PORT="${2:-}"
  local TARGET_PORT ADMIN_IP="" CLIENT_IP="" answer=""
  TARGET_PORT=${SESS_PORT:-$(printf '%s' "$SSH_PORTS" | head -n1)}

  ask "要限制的 SSH 端口(默认 ${TARGET_PORT}):" answer || return 1
  [ -n "$answer" ] && TARGET_PORT=$answer
  printf '%s' "$TARGET_PORT" | grep -qE '^[0-9]{1,5}$' || { err "端口不合法，已跳过。"; return 1; }

  ask "输入你固定的公网 IP:" ADMIN_IP || return 1
  if valid_ipv4 "$ADMIN_IP"; then :; elif valid_ipv6 "$ADMIN_IP"; then :; else
    err "IP 格式不正确，已跳过。"; return 1
  fi

  if [ -n "${SSH_CONNECTION:-}" ]; then CLIENT_IP=${SSH_CONNECTION%% *}
  elif [ -n "${SSH_CLIENT:-}" ]; then CLIENT_IP=$(printf '%s' "$SSH_CLIENT" | awk '{print $1}'); fi
  if [ -z "$CLIENT_IP" ]; then
    warn "无法确定当前连接来源 IP，请自行确认 $ADMIN_IP 正确。"
  elif [ "$CLIENT_IP" != "$ADMIN_IP" ]; then
    warn "当前连接来源是 $CLIENT_IP，与白名单 $ADMIN_IP 不一致；填错会立刻失联。"
    confirm "确认仍以 $ADMIN_IP 作为唯一允许来源？" || { info "已跳过。"; return 0; }
  fi

  fw_allow_from "$ADMIN_IP" "$TARGET_PORT" tcp || { err "添加白名单失败，未删除任何规则。"; return 1; }
  ok "已添加白名单: $ADMIN_IP → ${TARGET_PORT}/tcp"

  local revert_ok=0
  if [ "$INIT" = "systemd" ] && need_cmd systemd-run && [ "$FW_BACKEND" = "ufw" ]; then
    if systemd-run --on-active=10min --unit=ssh-fw-revert ufw allow "${TARGET_PORT}/tcp" >/dev/null 2>&1; then
      revert_ok=1
      warn "已安排 10 分钟自动回滚（万一失联会自动恢复全放行）。"
    fi
  fi
  [ "$revert_ok" = "1" ] || warn "未安排自动回滚：若配置有误，只能通过厂商 Console 修复。"

  confirm "确认删除 ${TARGET_PORT}/tcp 的全局放行规则（仅保留上面的白名单）？" || {
    info "未删除全局规则。"; return 0; }

  fw_delete_port "$TARGET_PORT" tcp >>/dev/null 2>&1
  if fw_has_global_port "$TARGET_PORT" tcp; then
    warn "仍检测到 ${TARGET_PORT}/tcp 的全局放行规则，请手工核对后删除。"
  else
    ok "已删除全局放行：SSH ${TARGET_PORT} 现在仅允许 $ADMIN_IP。"
  fi
  if [ "$revert_ok" = "1" ]; then
    info "请立即用【新窗口】验证登录；成功后取消回滚："
    echo "  sudo systemctl stop ssh-fw-revert.timer 2>/dev/null || sudo systemctl stop ssh-fw-revert"
  else
    info "请立即用【新窗口】验证登录，并保持厂商 Console 可用。"
  fi
  return 0
}

#------------------------------ 第 7 项：监听端口检查 ------------------------------#

step7_listeners() {
  hdr "第 7 项：检查所有监听端口（只读）"
  info "监听端口:"
  run_timed 10 net_listen 2>/dev/null | sed 's/^/  /' || { err "无 ss/netstat/sockstat 可用"; return 1; }
  echo
  info "运行中的服务:"
  svc_list_running 2>/dev/null | sed 's/^/  /' | head -n 40
  echo
  info "常见需确认的端口: 21 FTP / 23 Telnet / 25 SMTP / 3306 MySQL / 5432 PostgreSQL / 6379 Redis / 2375 Docker API"
  info "判断三要素：程序是否监听 + 防火墙是否允许 + 是否有其它端口发布机制（如 Docker）。"
  info "确认无用且了解用途后可用: sudo $(case "$INIT" in systemd) echo 'systemctl disable --now <服务>';; openrc) echo 'rc-update del <服务> && rc-service <服务> stop';; *) echo 'service <服务> stop';; esac) 停用。"
}

#------------------------------ 第 8 项：Fail2ban ------------------------------#

step8_fail2ban() {
  hdr "第 8 项：安装并验证 Fail2ban"
  if ! pkg_has fail2ban; then
    info "安装 fail2ban ……"
    pkg_install_fail2ban || {
      err "fail2ban 安装失败。"
      info "手工命令参考："
      case "$PLAT_FAMILY" in
        rhel) info "  sudo dnf install -y epel-release && sudo dnf install -y fail2ban" ;;
        arch) info "  sudo pacman -S fail2ban" ;;
        alpine) info "  sudo apk add fail2ban（需启用 community 仓库）" ;;
        bsd) info "  sudo pkg install -y py311-fail2ban（FreeBSD）" ;;
        *) info "  用你的包管理器安装 fail2ban" ;;
      esac
      return 1
    }
  fi

  local maxretry=3 findtime=10m bantime=2h label="推荐值" choice=""
  if [ "$MODE" = "password" ]; then
    ask "Fail2ban 强度: [1] 密码模式推荐 maxretry=3/findtime=10m/bantime=2h (默认)  [2] 宽松 maxretry=5/findtime=10m/bantime=1h（默认 1）:" choice || choice=1
    case "$choice" in 2) maxretry=5; bantime=1h; label="宽松值" ;; esac
  else
    ask "Fail2ban 强度: [1] 默认 maxretry=5/findtime=10m/bantime=1h（默认 1）  [2] 严格 maxretry=3/findtime=10m/bantime=2h:" choice || choice=1
    case "$choice" in
      2) maxretry=3; bantime=2h; label="严格值" ;;
      *) maxretry=5; bantime=1h; label="默认值" ;;
    esac
  fi

  local IGNORE_LINE="" IGNORE_OPT=""
  if confirm "是否把自己的固定管理 IP 加入 fail2ban 白名单(ignoreip)？"; then
    ask "输入要加入白名单的 IP（多个用空格分隔，可留空跳过）:" IGNORE_LINE || IGNORE_LINE=""
    [ -n "$IGNORE_LINE" ] && IGNORE_OPT="ignoreip = 127.0.0.1/8 ::1 $IGNORE_LINE"
  fi

  # backend：systemd 平台用 journald，其它平台交给 fail2ban 自动识别日志
  local backend_opt=""
  if [ "$INIT" = "systemd" ]; then backend_opt="backend = systemd"; else backend_opt="backend = auto"; fi

  mkdir -p /etc/fail2ban/jail.d
  cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
$backend_opt
maxretry = $maxretry
findtime = $findtime
bantime = $bantime
$IGNORE_OPT
EOF
  ok "已写入 /etc/fail2ban/jail.d/sshd.local（$label: maxretry=$maxretry / findtime=$findtime / bantime=$bantime，$backend_opt）"

  if svc_enable_now fail2ban >/dev/null 2>&1; then
    sleep 2
  fi
  # 必须确认真的在运行并且 sshd jail 生效，否则不算完成
  local f2b_ok=0
  if svc_active fail2ban; then
    if need_cmd fail2ban-client; then
      if fail2ban-client status 2>/dev/null | grep -q 'sshd'; then f2b_ok=1; fi
    else
      f2b_ok=1
    fi
  fi
  if [ "$f2b_ok" != "1" ]; then
    err "fail2ban 未在运行或 sshd jail 未生效！配置已写入但当前不提供保护。"
    info "手工检查："
    case "$INIT" in
      systemd) info "  systemctl status fail2ban --no-pager; journalctl -u fail2ban -n 30" ;;
      openrc)  info "  rc-service fail2ban status" ;;
      bsd)     info "  service fail2ban status（OpenBSD 用 rcctl check fail2ban）" ;;
      *)       info "  用你的 init 工具启动 fail2ban，并查看 /var/log/fail2ban.log" ;;
    esac
    return 1
  fi
  ok "fail2ban 正在运行，sshd jail 已生效。"
  if need_cmd fail2ban-client; then
    info "jail 状态:"
    fail2ban-client status 2>/dev/null | sed 's/^/  /' || true
    fail2ban-client status sshd 2>/dev/null | sed 's/^/  /' || true
  fi
  ok "第 8 项完成。"
  warn "Fail2ban 是 SSH 加固的补充，不是替代品；不要故意输错密码测试，以免封掉自己。"
}

#------------------------------ 第 9 / 10 项：3X-UI ------------------------------#

xui_installed() {
  svc_exists x-ui || [ -f /etc/systemd/system/x-ui.service ] || [ -f /lib/systemd/system/x-ui.service ] || [ -f /usr/lib/systemd/system/x-ui.service ]
}

step9_xui_panel() {
  hdr "第 9 项：保护 3X-UI 管理入口"
  if ! xui_installed; then
    warn "未检测到 x-ui 服务（请先完成第 2~8 项，再安装 3X-UI / Reality / Hysteria2）。"
    info "安装后请检查：非默认用户名 + 独立长密码 + 随机 Web Base Path + HTTPS + 2FA。"
    return 0
  fi
  ok "检测到 x-ui 服务，监听情况:"
  net_listen 2>/dev/null | grep -i x-ui | sed 's/^/  /' || true
  cat <<'EOF' | sed 's/^/  /'
  面板安全检查项：
   1. 管理员账号：非默认用户名 + 独立长密码，不与其他网站共用
   2. Web Base Path：使用随机路径
   3. HTTPS：证书/私钥路径正确，浏览器无证书错误
   4. 2FA：版本支持时开启
   5. 不要公开：面板完整 URL / 账号密码 / API Token / 订阅链接 / UUID / Reality Private Key / TLS Private Key
EOF
  if confirm "有固定公网管理 IP，是否限制面板端口只允许该 IP 访问？"; then
    local ADMIN_IP="" PANEL_PORT=""
    ask "输入固定管理公网 IP:" ADMIN_IP || return 1
    ask "输入 3X-UI 面板端口:" PANEL_PORT || return 1
    if { valid_ipv4 "$ADMIN_IP" || valid_ipv6 "$ADMIN_IP"; } && printf '%s' "$PANEL_PORT" | grep -qE '^[0-9]{1,5}$'; then
      if fw_allow_from "$ADMIN_IP" "$PANEL_PORT" tcp; then
        ok "已添加白名单: $ADMIN_IP → $PANEL_PORT/tcp"
        warn "请确认新规则生效后，再删除该端口的全局放行规则。"
      else
        err "添加白名单失败（当前防火墙后端: $FW_BACKEND）。"
      fi
    else
      err "IP 或端口不合法，已跳过。"
    fi
  fi
}

step10_xui_backup() {
  hdr "第 10 项：备份 3X-UI 数据库并带离 VPS"
  if [ ! -f /etc/x-ui/x-ui.db ]; then
    warn "未找到 /etc/x-ui/x-ui.db（默认 SQLite）。若使用 PostgreSQL/Docker Volume，请勿照抄本步。"
    return 0
  fi
  ls -lh /etc/x-ui/x-ui.db | sed 's/^/  /'
  mkdir -p /root/backups
  local dest="/root/backups/x-ui-$(date +%F-%H%M).db"
  confirm "将短暂停止 x-ui 以生成一致副本，继续？" || return 0
  local stopped=0
  if svc_exists x-ui; then
    if svc_stop x-ui >/dev/null 2>&1 && ! svc_active x-ui; then
      stopped=1
      sleep 1
    else
      warn "无法确认 x-ui 已停止：数据库可能在写入中，副本不一定完全一致。"
    fi
  fi
  if ! cp /etc/x-ui/x-ui.db "$dest"; then
    err "备份失败：无法写入 $dest"
    [ "$stopped" = "1" ] && svc_start x-ui >/dev/null 2>&1
    return 1
  fi
  if [ ! -s "$dest" ]; then
    err "备份文件为空：$dest"
    [ "$stopped" = "1" ] && svc_start x-ui >/dev/null 2>&1
    return 1
  fi
  if [ "$stopped" = "1" ]; then svc_start x-ui >/dev/null 2>&1 || true; fi
  sleep 1
  if svc_exists x-ui; then
    if svc_active x-ui; then ok "x-ui 已重新运行"; else warn "x-ui 未运行，请检查"; fi
  fi
  ok "数据库副本已生成: $dest"
  ls -lh "$dest" | sed 's/^/  /'
  warn "本机副本不是最终备份，请立刻下载到 VPS 之外："
  echo "  scp root@<你的服务器IP>:$dest ."
  info "恢复点建议：基础加固后打厂商 Snapshot；3X-UI 配置完成后做配置外部备份。"
}

#------------------------------ 第 1 项 / 汇总 ------------------------------#

step1_manual() {
  hdr "第 1 项：Console / MFA / 恢复能力（服务商后台手动完成）"
  cat <<'EOF'
  [ ] 实际登录一次 Web Console / VNC / Serial Console（不要只看有没有按钮）
  [ ] 服务商账户开启 MFA，恢复码保存在 VPS 之外
  [ ] 确认 Snapshot（快照）与 Reinstall（重装）入口
  [ ] 确认 Cloud Firewall（云防火墙）入口与规则
  [ ] 记录：公网 IP / 系统版本 / SSH 端口 / Console 入口 / 快照位置
EOF
}

final_report() {
  hdr "汇总：请对照检查"
  local mode_txt="SSH Key 模式（密码认证已关闭）"
  [ "$MODE" = "password" ] && mode_txt="密码登录模式（保留密码认证）"
  info "本次模式: $mode_txt"
  cat <<'EOF'
  退路   [ ] 厂商账户 MFA    [ ] 恢复码已保存    [ ] Console 已实测    [ ] 快照入口已确认
  身份   [ ] sudo 用户已建    [ ] 新窗口验证通过  [ ] root SSH 登录已关闭
         [ ] sshd 生效值符合预期（PermitRootLogin / AllowUsers / 认证方式）
  边界   [ ] 防火墙已启用     [ ] SSH 端口已放行（或已限 IP）  [ ] 未提前开放无关端口
         [ ] IPv6 与云防火墙已检查   [ ] 监听端口均已确认用途
  入口   [ ] 3X-UI 独立账号/强密码/随机路径/HTTPS/2FA   [ ] 面板敏感信息未公开
  备份   [ ] x-ui 数据库已备份到 VPS 之外   [ ] 基础加固后已做 Snapshot

  三条铁律：
   1. 任何影响 SSH 登录的配置：先保留旧连接，再用新窗口验证。
   2. 任何防火墙配置：必须明确自己正在开放什么。
   3. 任何重要配置：不能只有服务器本机这一份副本。
EOF
  info "平台: $PLAT_NAME  防火墙: $FW_BACKEND  init: $INIT  日志: $LOG_FILE"
  if [ -n "${FIREWALL_SKIPPED:-}" ]; then
    warn "注意：本次未自动配置防火墙 —— $FIREWALL_SKIPPED"
  fi
  if [ -n "${GEN_PW_SAVE:-}" ]; then
    printf '%b' "${C_BLD}${C_GRN}  提醒：$NEW_USER 的密码是 $GEN_PW_SAVE ，请确认已保存。${C_N}\n"
  fi
}

#------------------------------ 菜单 / 入口 ------------------------------#

menu() {
  local step5_label
  if [ "$MODE" = "password" ]; then
    step5_label="第 5 项  SSH 加固（关闭 root 登录，保留密码）"
  else
    step5_label="第 5 项  SSH 加固（关闭 root 登录 + 关闭密码认证）"
  fi
  while true; do
    echo
    if [ "$MODE" = "password" ]; then
      hdr "VPS 基础安全加固（密码登录模式）"
    else
      hdr "VPS 基础安全加固（SSH Key 模式）"
    fi
    echo "  0) 预检（平台/网络/端口）"
    echo "  2) 第 2 项  更新系统 + 自动安全更新"
    echo "  3) 第 3 项  创建普通 sudo 管理员"
    if [ "$MODE" = "password" ]; then
      echo "  4) 第 4 项  设置强密码 + 验证密码登录"
    else
      echo "  4) 第 4 项  安装 SSH 公钥 + 验证"
    fi
    echo "  5) $step5_label"
    echo "  6) 第 6 项  配置防火墙（$FW_BACKEND）"
    echo "  7) 第 7 项  检查监听端口（只读）"
    echo "  8) 第 8 项  安装并验证 Fail2ban"
    echo "  9) 第 9 项  3X-UI 面板入口检查"
    echo " 10) 第 10 项 备份 3X-UI 数据库"
    echo "  a) 顺序执行 第 2→8 项（推荐）"
    echo "  r) 显示检查清单     q) 退出"
    local choice=""
    if ! ask "请选择（输入编号后回车，q 退出）:" choice; then echo; exit 0; fi
    case "$choice" in
      0) os_check; step1_manual ;;
      2) step2_update ;;
      3) step3_user ;;
      4) if [ "$MODE" = "password" ]; then step4_password; else step4_sshkey; fi ;;
      5) step5_sshd ;;
      6) step6_firewall ;;
      7) step7_listeners ;;
      8) step8_fail2ban ;;
      9) step9_xui_panel ;;
      10) step10_xui_backup ;;
      a) os_check; step1_manual
         run_chain=1
         step2_update || run_chain=0
         [ "$run_chain" = "1" ] && { step3_user || run_chain=0; }
         if [ "$run_chain" = "1" ]; then
           if [ "$MODE" = "password" ]; then step4_password || run_chain=0; else step4_sshkey || run_chain=0; fi
         fi
         [ "$run_chain" = "1" ] && { step5_sshd || run_chain=0; }
         [ "$run_chain" = "1" ] && { step6_firewall || run_chain=0; }
         [ "$run_chain" = "1" ] && { step7_listeners || run_chain=0; }
         [ "$run_chain" = "1" ] && { step8_fail2ban || run_chain=0; }
         if [ "$run_chain" = "1" ]; then
           final_report
         else
           err "流程中断：请按上面提示处理后，单独重跑该项（如 sudo bash $0 --step 5）。"
         fi ;;
      r) final_report ;;
      q) exit 0 ;;
      *) warn "无效选择: $choice" ;;
    esac
  done
}

usage() {
  cat <<'EOF'
用法：
  sudo bash vps-hardening.sh                      # 交互式菜单（SSH Key 模式）
  sudo bash vps-hardening.sh --mode password      # 密码登录模式（等价 --no-key）
  sudo bash vps-hardening.sh --mode key           # SSH Key 模式（等价 --key，默认）
  sudo bash vps-hardening.sh --auto               # 顺序执行第 2~8 项（逐步确认）
  sudo bash vps-hardening.sh --step N             # 只执行某项（N=2..10，可与 --mode 组合）
  sudo bash vps-hardening.sh --fail2ban           # 只执行第 8 项
  sudo bash vps-hardening.sh --setup-only         # 只做平台检测并打印平台/能力报告，不修改系统

环境变量：
  DEBUG=1      打印执行的每条命令（排查“卡住/没有回显”）
  FORCE=1      跳过第 5 项“新窗口已验证”的人工确认（谨慎）
  VPS_FW=ufw|firewalld|iptables|manual|none   强制指定防火墙后端
               （nftables 会映射为 manual：脚本不自动改写全局规则集，避免破坏 Docker 规则）
  VPS_REPO / VPS_REF                 指定仓库与分支（自建镜像时用）

支持平台：Debian/Ubuntu 系、RHEL/CentOS/Rocky/Alma/Fedora/Amazon、openSUSE/SLES、
          Arch/Manjaro、Alpine、Gentoo、Void、FreeBSD/OpenBSD/NetBSD/DragonFly
EOF
}

main() {
  # --help 不要求 root（方便只读查看）
  case "${1:-}" in
    -h|--help) usage; exit 0 ;;
  esac
  if [ "$(id -u)" -ne 0 ]; then
    if [ -f "${BASH_SOURCE[0]:-}" ]; then
      echo "需要 root 权限，使用 sudo 重新执行……"
      exec sudo -E bash "${BASH_SOURCE[0]}" "$@"
    fi
    err "需要 root 权限：请用 sudo 运行。"
    exit 1
  fi
  [ "${DEBUG:-0}" = "1" ] && set -x

  local action="" step=""
  set_action() { # 归一化动作参数：冲突直接报错，避免 --auto --setup-only 之类的歧义
    if [ -n "$action" ] && [ "$action" != "$1" ]; then
      err "参数冲突：--$action 与 --$1 不能同时使用"
      exit 1
    fi
    action="$1"
  }
  while [ $# -gt 0 ]; do
    case "$1" in
      --key) MODE=key ;;
      --no-key|--password) MODE=password ;;
      --mode)
        shift
        case "${1:-}" in
          key|password) MODE="$1" ;;
          *) err "--mode 需要 key 或 password"; exit 1 ;;
        esac ;;
      --auto)       set_action auto ;;
      --fail2ban)   set_action fail2ban ;;
      --setup-only) set_action setup ;;
      --step)
        shift; set_action step
        case "${1:-}" in
          2|3|4|5|6|7|8|9|10) step="$1" ;;
          *) err "--step 需要跟一个数字（2~10）"; exit 1 ;;
        esac ;;
      *) err "未知参数: $1"; print_usage; exit 1 ;;
    esac
    shift
  done

  # MODE 也可能来自环境变量：非法值一律拒绝（key 模式会关掉密码认证，不能猜）
  case "$MODE" in
    key|password) : ;;
    *) err "MODE 只能是 key 或 password（当前: '$MODE'）"; exit 2 ;;
  esac

  printf '%b' "${C_BLD}${C_GRN}vps-hardening.sh 已启动${C_N}  PID=$$  时间=$(date '+%F %T')  模式=$MODE  日志=$LOG_FILE\n"
  [ -t 0 ] || warn "标准输入不是终端：交互提示将无法输入，看起来会像“卡住”。请用 install.sh 或先下载再执行。"
  plat_detect
  log "=== 开始: mode=$MODE args=${args[*]:-} ==="

  if [ "$action" = "setup" ]; then
    ok "依赖与平台检测正常，未做任何修改。"
    plat_report
    exit 0
  fi

  local rc=0
  case "$action" in
    auto)    os_check; step1_manual
             run_chain=1
             step2_update || run_chain=0
             [ "$run_chain" = "1" ] && { step3_user || run_chain=0; }
             if [ "$run_chain" = "1" ]; then
               if [ "$MODE" = "password" ]; then step4_password || run_chain=0; else step4_sshkey || run_chain=0; fi
             fi
             [ "$run_chain" = "1" ] && { step5_sshd || run_chain=0; }
             [ "$run_chain" = "1" ] && { step6_firewall || run_chain=0; }
             [ "$run_chain" = "1" ] && { step7_listeners || run_chain=0; }
             [ "$run_chain" = "1" ] && { step8_fail2ban || run_chain=0; }
             if [ "$run_chain" = "1" ]; then
               final_report
             else
               err "流程中断：请按提示处理后单独重跑该项（如 sudo bash $0 --step 5）。"
               rc=1
             fi ;;
    fail2ban) os_check; step8_fail2ban || rc=1 ;;
    *)       if [ -n "$step" ]; then
               os_check
               case "$step" in
                 2) step2_update || rc=1 ;;
                 3) step3_user || rc=1 ;;
                 4) if [ "$MODE" = "password" ]; then step4_password || rc=1; else step4_sshkey || rc=1; fi ;;
                 5) step5_sshd || rc=1 ;;
                 6) step6_firewall || rc=1 ;;
                 7) step7_listeners || rc=1 ;;
                 8) step8_fail2ban || rc=1 ;;
                 9) step9_xui_panel || rc=1 ;;
                 10) step10_xui_backup || rc=1 ;;
                 *) err "未知步骤: $step（可用 2~10）"; exit 1 ;;
               esac
             else
               menu
             fi ;;
  esac
  log "=== 结束 (rc=$rc) ==="
  exit "$rc"
}

main "$@"
