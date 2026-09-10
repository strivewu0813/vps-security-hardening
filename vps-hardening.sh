#!/usr/bin/env bash
#=============================================================================
# vps-hardening.sh
# 新 VPS 基础安全一键加固脚本（SSH Key 版）
#
# 适用环境：Ubuntu 24.04 LTS / 初始 root 或具备 sudo 权限的管理员
# 适用场景：准备部署 3X-UI / VLESS Reality / Hysteria2 / Trojan 的节点 VPS
#
# 用法：
#   sudo bash vps-hardening.sh              # 交互式菜单
#   sudo bash vps-hardening.sh --auto       # 按推荐顺序执行第 2~8 项（逐步确认）
#   sudo bash vps-hardening.sh --step N     # 只执行某项（N=2..10）
#   sudo bash vps-hardening.sh --fail2ban   # 只执行第 8 项 Fail2ban
#
# 卡住 / 没有输出时：用 DEBUG=1 查看每条命令的执行进度
#   sudo DEBUG=1 bash vps-hardening.sh 2>&1 | tee /tmp/hardening-debug.log
#
# ⚠️ 重要安全提示（务必遵守）：
#   1. 第 1 项(厂商 Console / MFA / 快照)只能在服务商后台手动完成，本脚本只负责提醒。
#   2. 任何可能影响 SSH 登录的配置，都必须先保留旧连接，再使用【新窗口】完成验证；
#      在 SSH Key 未通过新窗口验证之前，不要关闭密码登录，不要退出当前 SSH 会话。
#   3. 其他 Linux 发行版请参考思路，不建议直接逐条复制本脚本。
#   4. 环境变量 FORCE=1 可跳过第 5 项的人工确认（仅用于已确认过新窗口验证的重复执行，请谨慎使用）。
#=============================================================================

set -uo pipefail

#---------------------------- 颜色 / 日志 ----------------------------#
C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
C_CYN=$'\e[36m'; C_BLD=$'\e[1m';   C_N=$'\e[0m'

LOG_FILE=/var/log/vps-hardening.log
CTX_FILE=/root/.vps-hardening-ctx

info() { printf '%b' "${C_CYN}[INFO]${C_N} $*\n"; }
ok()   { printf '%b' "${C_GRN}[ OK ]${C_N} $*\n"; }
warn() { printf '%b' "${C_YEL}[WARN]${C_N} $*\n" >&2; }
err()  { printf '%b' "${C_RED}[ERR ]${C_N} $*\n" >&2; }
hdr()  { printf '%b' "\n${C_BLD}${C_CYN}========== $* ==========${C_N}\n"; }

log()  { printf '%s  %s\n' "$(date '+%F %T')" "$*" | sudo tee -a "$LOG_FILE" >/dev/null 2>&1 || true; }

#---------------------------- 辅助函数 ----------------------------#
confirm() {
  local msg="$1" ans
  printf '%b' "${C_YEL}?${C_N} $msg [y/N]:\n"
  read -r ans || ans=n
  case "${ans,,}" in y|yes) return 0;; *) return 1;; esac
}

# 带超时的确认：无输入/EOF 时按默认值处理，避免“卡在预检”这类无限等待
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

# 读取一行输入：提示独占一行，避免某些终端（如厂商 VNC Console）不渲染无换行提示符
ask() {
  local prompt="$1" var="$2" ans=""
  printf '%s\n> ' "$prompt"
  IFS= read -r ans || return 1
  printf -v "$var" '%s' "$ans"
  return 0
}

# 带超时地运行命令：某些环境（网络被墙、ss -p 卡住等）可能长时间无输出
run_timed() {
  local secs="$1"; shift
  if need_cmd timeout; then timeout "$secs" "$@"; else "$@"; fi
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "需要 root 权限，尝试用 sudo 重新执行……"
    exec sudo -E bash "$0" "$@"
  fi
}

# 所有可能接受 SSH 连接的端口（sshd 配置 + ssh.socket 的 ListenStream），去重排序
all_ssh_ports() {
  {
    sshd -T 2>/dev/null | awk '/^port /{print $2}'
    systemctl show -p Listen --value ssh.socket 2>/dev/null | tr ' ' '\n' \
      | sed -n 's/.*:\([0-9]\{1,5\}\)$/\1/p'
  } | grep -E '^[0-9]+$' | sort -un
}

# 当前 SSH 会话连接的服务端端口（防火墙放行与校验都要覆盖它，避免换端口后失联）
current_session_port() {
  local p=""
  if [ -n "${SSH_CONNECTION:-}" ]; then
    p=${SSH_CONNECTION##* }
  fi
  if ! printf '%s' "$p" | grep -qE '^[0-9]+$'; then
    p=$(ss -tnp 2>/dev/null | awk '/sshd/{print $4}' | sed -n 's/.*:\([0-9]\{1,5\}\)$/\1/p' | head -n1)
  fi
  printf '%s' "$p"
}

# 校验失败/中止时把未采用的 SSH 配置挪走，防止后续连接读到未验证或不完整的配置
abort_conf() {
  local conf="$1"
  if [ -f "$conf" ]; then
    if mv "$conf" "${conf}.failed" 2>/dev/null; then
      warn "已把未采用的配置移到 ${conf}.failed（sshd 不再读取它；确认无误后可自行删除）"
    else
      warn "注意：$conf 仍在原处，请手动检查或删除，否则后续 SSH 连接可能受影响。"
    fi
  fi
}

os_check() {
  if [ -r /etc/os-release ]; then . /etc/os-release; fi
  hdr "0. 系统与 VPS 身份预检"
  info "[1/5] 系统信息"
  info "  ${PRETTY_NAME:-未知}  (ID=${ID:-未知} VERSION_ID=${VERSION_ID:-未知})"
  case "${ID:-}" in
    ubuntu|debian)
      if [ "${VERSION_ID:-}" != "24.04" ]; then
        warn "教程以 Ubuntu 24.04 LTS 为例。您当前是 ${PRETTY_NAME:-?}：命令大体通用，但请自行核对。"
        confirm_timed "是否继续？" 15 y || { err "已按要求退出（未做任何修改）。"; exit 0; }
      fi ;;
    *)
      warn "未识别到 Ubuntu / Debian（当前 ID=${ID:-未知}），本脚本命令可能不适用。"
      confirm_timed "仍然继续？" 20 n || { err "已退出（未做任何修改）。"; exit 0; }
      ;;
  esac

  info "[2/5] 公网 IP / 地区 / ASN（不通会自动跳过，最多等 8 秒）"
  if need_cmd curl; then
    curl -s --connect-timeout 4 --max-time 8 ipinfo.io \
      || warn "ipinfo.io 不可达，已跳过。可稍后手动执行: curl -s ipinfo.io"
  else
    warn "未安装 curl，已跳过。可稍后手动执行: curl -s ipinfo.io"
  fi

  info "[3/5] 本机网卡地址"
  run_timed 10 ip -br addr 2>/dev/null | sed 's/^/  /'

  info "[4/5] SSH 端口与监听端口（最多等 10 秒）"
  info "  SSH 实际端口: $(run_timed 5 sshd -T 2>/dev/null | awk '/^port /{print $2}' | head -n1)"
  run_timed 10 ss -lntup 2>/dev/null | sed 's/^/  /'

  info "[5/5] 需要你手动确认的事项"
  warn "请现在就在服务商后台实际登录一次 Console / VNC，并确认快照与云防火墙入口存在。"
  ok "预检完成。"
}

#---------------------------- 第 2 项：更新系统安全补丁 ----------------------------#
step2_update() {
  hdr "第 2 项：更新系统安全补丁"
  info "apt update && upgrade ……（可能需要几分钟）"
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
  apt-get update || { err "apt update 失败"; return 1; }
  apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade \
    || { err "apt upgrade 失败"; return 1; }
  ok "系统软件包已更新。"

  if [ -f /var/run/reboot-required ]; then
    warn "检测到需要重启（/var/run/reboot-required）:"
    cat /var/run/reboot-required 2>/dev/null | sed 's/^/  /'
    if confirm "现在重启？(重启后请重新执行本脚本继续)"; then
      info "重启中……重启完成后重新运行: sudo bash $0 --auto"
      systemctl reboot
      exit 0
    else
      warn "已选择暂不重启。部分安全补丁要重启后才生效，建议稍后手动重启。"
    fi
  fi

  info "配置自动安全更新 unattended-upgrades ……"
  if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
    apt-get install -y unattended-upgrades || { err "安装 unattended-upgrades 失败"; return 1; }
  fi
  printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
    > /etc/apt/apt.conf.d/20auto-upgrades
  dpkg-reconfigure -f noninteractive -plow unattended-upgrades >/dev/null 2>&1 || true
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  systemctl status unattended-upgrades --no-pager 2>/dev/null | head -n 5 | sed 's/^/  /'
  ok "自动安全更新已启用。"
  info "注意：3X-UI / Xray 等业务程序的大版本升级，仍建议先备份 → 再升级 → 再验证。"
}

# 选择要操作的管理员用户：若存在第 3 项的记录，先展示并要求确认，避免误操作到其它用户
pick_user() {
  NEW_USER=""
  if [ -s "$CTX_FILE" ]; then
    # shellcheck disable=SC1090
    . "$CTX_FILE"
    if [ -n "${NEW_USER:-}" ]; then
      info "第 3 项创建/记录的管理员用户: $NEW_USER"
      local ans=""
      printf '%b' "${C_YEL}?${C_N} 就操作该用户？[Y/n] "
      read -r ans || ans=y
      case "${ans,,}" in n|no) NEW_USER="" ;; esac
    fi
  fi
  if [ -z "${NEW_USER:-}" ]; then
    ask "输入管理员用户名:" NEW_USER || return 1
  fi
  # 关键闸门：绝不允许对 root 执行。第 5 项会写 PermitRootLogin no 且 AllowUsers 只保留该用户，
  # 若这里是 root，则 root 被 PermitRootLogin 拒绝、其他人被 AllowUsers 拒绝 → 所有 SSH 登录失败。
  if [ "$(id -u "$NEW_USER" 2>/dev/null)" = "0" ]; then
    err "不允许对 root 账户执行本流程（会导致所有 SSH 登录被拒绝）。请先用菜单 3 创建普通用户。"
    return 1
  fi
}

#---------------------------- 第 3 项：创建普通 sudo 管理用户 ----------------------------#
step3_user() {
  hdr "第 3 项：创建普通 sudo 管理用户"
  local NEW_USER=""
  while :; do
    ask "输入要创建的管理员用户名(小写字母/数字，如 alex):" NEW_USER || return 1
    if printf '%s' "$NEW_USER" | grep -qE '^[a-z_][a-z0-9_-]*$'; then break; fi
    err "用户名不合法，只能用小写字母、数字、下划线、连字符。"
  done

  if id "$NEW_USER" >/dev/null 2>&1; then
    warn "用户 $NEW_USER 已存在，跳过创建，仅确保 sudo 权限与 shell。"
  else
    useradd -m -s /bin/bash "$NEW_USER" || { err "创建用户失败"; return 1; }
    info "为 $NEW_USER 设置登录密码（输入不会显示，输两遍一致即可）:"
    passwd "$NEW_USER" || { err "设置密码失败"; return 1; }
    ok "用户 $NEW_USER 已创建。"
  fi
  usermod -aG sudo "$NEW_USER"
  usermod -s /bin/bash "$NEW_USER"
  chown "$NEW_USER:$(id -gn "$NEW_USER")" "/home/$NEW_USER" || true
  info "检查: $(id "$NEW_USER" 2>&1 | sed 's/^/  /')"
  info "sudo 组包含: $(id -nG "$NEW_USER" | sed 's/^/  /')"
  ok "第 3 项完成。"
  # 记录当前用户到 root 专属文件(0600)，供第 4/5 项引用并二次确认，避免误用其它用户
  printf 'NEW_USER=%s\n' "$NEW_USER" > "$CTX_FILE" 2>/dev/null
  chmod 600 "$CTX_FILE" 2>/dev/null || true
}

#---------------------------- 第 4 项：安装 SSH Key ----------------------------#
step4_sshkey() {
  hdr "第 4 项：把 SSH Key 公钥安装到普通用户"
  local NEW_USER=""
  pick_user || return 1
  id "$NEW_USER" >/dev/null 2>&1 || { err "用户 $NEW_USER 不存在，请先执行第 3 项。"; return 1; }

  local keydir="/home/$NEW_USER/.ssh"
  local keyfile="$keydir/authorized_keys"
  mkdir -p "$keydir" && chmod 700 "$keydir"

  local PUBKEY=""
  ask "请把【本机】生成的公钥【完整一行】粘贴到这里（ssh-ed25519 / ssh-rsa / ecdsa-sha2 开头，粘贴后回车即可）:" PUBKEY || return 1
  PUBKEY=${PUBKEY%$'\r'}   # 去掉 Windows 粘贴可能带来的结尾 \r
  case "$PUBKEY" in
    '')
      err "公钥为空。若已在教程 4.3 手动粘贴过公钥，可直接选择第 5 项继续。"
      return 1 ;;
    ssh-ed25519\ AAAA*|ssh-rsa\ AAAA*|ecdsa-sha2-*\ AAAA*|sk-*\ AAAA*) : ;;
    *)
      err "输入内容不是有效的 OpenSSH 公钥行（应为: 类型 AAAA... [注释]）。为避免向 authorized_keys 写入垃圾内容，已中止。"
      return 1 ;;
  esac
  case "$PUBKEY" in
    ssh-rsa\ *)
      warn "提示：Ubuntu 24.04 的 OpenSSH 9.6 默认拒绝老式 ssh-rsa(SHA-1) 签名，RSA 公钥需客户端支持 rsa-sha2 才能通过后续验证。" ;;
  esac

  touch "$keyfile" && chmod 600 "$keyfile"
  if grep -qF "$PUBKEY" "$keyfile" 2>/dev/null; then
    ok "该公钥已存在，跳过写入。"
  else
    printf '%s\n' "$PUBKEY" >> "$keyfile"
    ok "公钥已写入 $keyfile"
  fi
  chmod 700 "$keydir"; chmod 600 "$keyfile"
  chown -R "$NEW_USER:$(id -gn "$NEW_USER")" "$keydir"
  chmod 755 "/home/$NEW_USER" 2>/dev/null || true
  ls -la "$keydir" | sed 's/^/  /'

  ok "公钥安装完成。请立即验证（本窗口不要关闭！）:"
  printf '%b' "${C_BLD}  验证步骤:${C_N}\n"
  echo "  1) 打开电脑上【第二个终端窗口】执行:  ssh $NEW_USER@<你的服务器IP>"
  echo "  2) 登录后执行 whoami ，应返回 $NEW_USER"
  echo "  3) 再执行 sudo whoami ，应返回 root"
  warn "在第二个窗口验证 SSH Key 能正常登录之前，绝对不要继续下一步（会关闭密码登录）。"
  confirm "第二个窗口已用 SSH Key 成功登录？(未验证请选 N 中止)" || { err "请先完成新窗口验证再回来重跑第 5 项。"; return 1; }
  # 验证通过后把用户名写入 root 专属上下文，供第 5 项引用同一用户
  printf 'NEW_USER=%s\n' "$NEW_USER" > "$CTX_FILE" 2>/dev/null
  chmod 600 "$CTX_FILE" 2>/dev/null || true
  ok "第 4 项完成。"
}

#---------------------------- 第 5 项：关闭 root 与密码登录 ----------------------------#
step5_sshd() {
  hdr "第 5 项：关闭 root 直接 SSH 登录 + 关闭密码登录"
  local NEW_USER=""
  pick_user || return 1
  id "$NEW_USER" >/dev/null 2>&1 || { err "用户 $NEW_USER 不存在，请先执行第 3、4 项。"; return 1; }

  # 安全闸门：没有 authorized_keys 时禁止继续，防止把自己锁在门外
  if [ ! -s "/home/$NEW_USER/.ssh/authorized_keys" ]; then
    err "未在 $NEW_USER 的 authorized_keys 中找到公钥，禁止关闭密码登录（教程原则：先验证再关闭）。"
    return 1
  fi
  if [ "${FORCE:-0}" != "1" ] && ! confirm "再次确认：将针对用户 $NEW_USER 关闭 root/密码登录，且其 SSH Key 已在【新窗口】验证通过？"; then
    err "已中止。请先完成新窗口验证。"; return 1
  fi

  local conf=/etc/ssh/sshd_config.d/00-vps-hardening.conf
  mkdir -p /etc/ssh/sshd_config.d
  cat > "$conf" <<EOF
# 由 vps-hardening.sh 生成，对应教程第 5 项
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers $NEW_USER
X11Forwarding no
EOF
  ok "已写入 $conf :"
  sed 's/^/  /' "$conf"

  info "检查配置语法 (sshd -t)……"
  if ! sshd -t; then
    err "sshd 配置语法错误，已中止（不会重启 SSH）。"
    abort_conf "$conf"
    return 1
  fi

  info "最终生效值检查 (sshd -T):"
  sshd -T | grep -E 'permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|x11forwarding|allowusers' | sed 's/^/  /'

  local fail=0
  sshd -T | grep -q '^permitrootlogin no$' || { err "permitrootlogin 不是 no"; fail=1; }
  sshd -T | grep -q '^passwordauthentication no$' || { err "passwordauthentication 不是 no"; fail=1; }
  sshd -T | grep -q '^kbdinteractiveauthentication no$' || { err "kbdinteractiveauthentication 不是 no"; fail=1; }
  sshd -T | grep -q '^pubkeyauthentication yes$' || { err "pubkeyauthentication 不是 yes"; fail=1; }
  sshd -T | grep -q '^x11forwarding no$' || { err "x11forwarding 不是 no"; fail=1; }
  # AllowUsers 按词精确匹配（顺序无关，也避免把“allowusers alex bob”这类多用户误判为通过）
  if ! sshd -T | awk -v u="$NEW_USER" '$1=="allowusers"{for(i=2;i<=NF;i++) if($i==u) f=1} END{exit !f}'; then
    err "AllowUsers 未包含 $NEW_USER"; fail=1
  fi
  if [ "$fail" = "1" ]; then
    err "生效配置与预期不符，已中止（不会重启 SSH）。"
    abort_conf "$conf"
    return 1
  fi

  # Ubuntu 24.04 默认 ssh.socket(socket 激活)：先 daemon-reload，
  # 只重启“已启用”的监听单元，最后用端口监听状态验证（不用 is-active ssh 判断）
  warn "即将应用新 SSH 配置。Ubuntu 24.04 默认 socket 激活；若是传统 sshd 模式，重启服务可能影响当前连接，请确保厂商 Console 可用。"
  confirm "确认应用？" || {
    abort_conf "$conf"
    err "已取消并撤下该配置。可稍后手动执行: systemctl daemon-reload && systemctl try-restart ssh ssh.socket"
    return 1
  }

  systemctl daemon-reload
  local unit=""
  if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
    systemctl restart ssh.socket 2>/dev/null && unit="ssh.socket"
  fi
  if [ -z "$unit" ] || systemctl is-enabled --quiet ssh.service 2>/dev/null; then
    systemctl try-restart ssh.service >/dev/null 2>&1 || true
    [ -z "$unit" ] && unit="ssh.service"
  fi
  if [ -z "$unit" ]; then
    systemctl restart ssh.service >/dev/null 2>&1 && unit="ssh.service"
  fi
  sleep 2

  # 端口监听校验：覆盖 sshd 配置与 ssh.socket 的所有监听端口
  local SSH_PORTS listening=0 p
  SSH_PORTS=$(all_ssh_ports)
  [ -n "$SSH_PORTS" ] || SSH_PORTS=$(sshd -T 2>/dev/null | awk '/^port /{print $2}' | head -n1)
  for p in $SSH_PORTS; do
    if ss -ltn | grep -Eq ":${p}[[:space:]]"; then listening=1; fi
  done
  if [ "$listening" = "1" ]; then
    ok "配置已应用：${unit:-ssh} 正在监听端口 $(printf '%s' "$SSH_PORTS" | tr '\n' ' ')。"
  else
    err "未检测到 SSH 端口在监听！请勿断开当前连接，立即用厂商 Console 检查: journalctl -u ssh --no-pager | tail -n 20"
    abort_conf "$conf"
    systemctl daemon-reload 2>/dev/null || true
    systemctl try-restart ssh.service >/dev/null 2>&1 || true
    warn "已撤下新配置并尝试恢复原配置，请在 Console 中确认 SSH 恢复后再重试。"
    return 1
  fi

  ok "第 5 项完成。请在【新窗口】验证："
  echo "  1) ssh $NEW_USER@<你的服务器IP>       → 应能正常登录"
  echo "  2) ssh root@<你的服务器IP>            → 应被拒绝"
  info "以后新增管理员时，记得同步把用户名加入 AllowUsers，否则公钥正确也登录不了。"
}

#---------------------------- 第 6 项：UFW 防火墙 ----------------------------#
step6_ufw() {
  hdr "第 6 项：配置 UFW，只开放必要端口"
  if ! dpkg -s ufw >/dev/null 2>&1; then
    info "安装 ufw ……"
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y ufw || { err "安装 ufw 失败"; return 1; }
  fi

  local SSH_PORTS
  SSH_PORTS=$(all_ssh_ports)
  [ -n "$SSH_PORTS" ] || SSH_PORTS=$(sshd -T 2>/dev/null | awk '/^port /{print $2}' | head -n1)
  case "$SSH_PORTS" in
    ''|*[!0-9[:space:]]*) err "无法确定有效的 SSH 端口（得到: '$SSH_PORTS'），已中止。"; return 1 ;;
  esac
  local SESS_PORT p
  SESS_PORT=$(current_session_port)
  info "检测到的 SSH 监听端口: $(printf '%s' "$SSH_PORTS" | tr '\n' ' ')"
  [ -n "$SESS_PORT" ] && info "当前会话的服务端端口: $SESS_PORT"

  # 顺序：先允许 SSH、确认规则已加入，再开启 UFW（不要反过来）
  for p in $SSH_PORTS; do ufw allow "$p/tcp"; done
  # 会话端口必须被覆盖，否则断线重连时会被默认拒绝挡在门外
  if [ -n "$SESS_PORT" ] && ! printf '%s\n' "$SSH_PORTS" | grep -qx "$SESS_PORT"; then
    warn "当前会话端口 $SESS_PORT 不在监听列表内，已单独放行以防断线后失联。"
    ufw allow "${SESS_PORT}/tcp"
    SSH_PORTS=$(printf '%s\n%s\n' "$SSH_PORTS" "$SESS_PORT" | sort -un)
  fi
  local rules_ok=1
  for p in $SSH_PORTS; do
    ufw show added 2>/dev/null | grep -q "^ufw allow ${p}/tcp" || rules_ok=0
  done
  if [ "$rules_ok" != "1" ]; then
    err "SSH 端口放行规则未全部加入，已中止（避免开启默认拒绝后被锁在门外）。"
    return 1
  fi
  ok "已确认放行 SSH: $(printf '%s' "$SSH_PORTS" | tr '\n' ' ')"
  ufw default deny incoming
  ufw default allow outgoing

  if confirm "现在是否有需要放行的业务端口？(还没有装 3X-UI/Reality/Hysteria2 就选 N，以后用到再放)"; then
    read -r -p "输入端口列表，空格分隔，例如: 443/tcp 443/udp 8080/tcp : " -a PORTS || { echo; return 1; }
    for p in "${PORTS[@]:-}"; do
      [ -z "$p" ] && continue
      if ufw allow "$p" >/dev/null 2>&1; then
        ok "已放行 $p"
      else
        warn "放行 $p 失败，请检查格式（如 443/tcp）"
      fi
    done
  fi

  # 允许 SSH 之后再 enable，防止把自己挡在门外
  ufw --force enable
  if ! ufw status | grep -q 'Status: active'; then
    err "UFW 未进入 active 状态，请立即用厂商 Console 检查。"
    return 1
  fi
  ok "UFW 已启用（默认拒绝入站，放行出站）"
  local missing=0
  for p in $SSH_PORTS; do
    ufw status | grep -Eq "^${p}/tcp" || missing=1
  done
  if [ -n "$SESS_PORT" ] && ! ufw status | grep -Eq "^${SESS_PORT}/tcp"; then missing=1; fi
  if [ "$missing" = "1" ]; then
    err "启用后未看到全部 SSH 放行规则！请立即用厂商 Console 检查。"
    return 1
  fi
  ufw status numbered | sed 's/^/  /'

  local ipv6
  ipv6=$(grep '^IPV6=' /etc/default/ufw 2>/dev/null | tail -n1)
  info "IPv6 设置: ${ipv6:-未找到 IPV6= 行}"
  case "$ipv6" in
    IPV6=yes) info "IPV6=yes，若服务器有 IPv6 请同步检查服务商 IPv6 云防火墙。" ;;
    IPV6=no)  warn "IPV6=no：UFW 不管理 IPv6 流量，请确认服务器是否使用 IPv6，必要时手动改 /etc/default/ufw 为 IPV6=yes。" ;;
  esac
  warn "Docker 用户注意：Docker 的端口发布会绕过部分 UFW 规则，请用 docker ps 检查 PORTS 列；仅本机访问的服务建议绑定 127.0.0.1。"
  ok "第 6 项完成。"
}

#---------------------------- 第 7 项：检查所有监听端口（报告） ----------------------------#
step7_listeners() {
  hdr "第 7 项：检查所有监听端口（只读报告，不修改任何配置）"
  info "当前监听端口与进程:"
  run_timed 10 ss -lntup 2>/dev/null | sed 's/^/  /' || { err "ss 不可用或超时，请安装 iproute2"; return 1; }
  echo
  info "当前运行中的服务:"
  systemctl --type=service --state=running 2>/dev/null | sed 's/^/  /'
  echo
  info "常见需确认的端口（不代表有问题，需确认程序/用途/是否需公网）:"
  cat <<'EOF' | sed 's/^/  /'
  21      FTP
  23      Telnet
  25      SMTP
  3306    MySQL
  5432    PostgreSQL
  6379    Redis
  2375    Docker API
EOF
  info "判断三要素：程序是否监听 + 防火墙是否允许 + 是否存在其它端口发布机制"
  info "防火墙允许某端口 ≠ 一定有程序监听；有程序监听 ≠ 公网一定能访问。"
  info "确认无用且明确了解的服务可执行: systemctl disable --now <服务名>（不要乱关 SSH/网络/DNS/Docker/Xray/3X-UI）"
}

#---------------------------- 第 8 项：Fail2ban ----------------------------#
step8_fail2ban() {
  hdr "第 8 项：安装并验证 Fail2ban"
  if ! dpkg -s fail2ban >/dev/null 2>&1; then
    info "安装 fail2ban ……"
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y fail2ban || { err "安装 fail2ban 失败"; return 1; }
  fi
  mkdir -p /etc/fail2ban/jail.d
  cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF
  ok "已写入 /etc/fail2ban/jail.d/sshd.local（maxretry=5 / findtime=10m / bantime=1h）"
  systemctl enable --now fail2ban >/dev/null 2>&1 || { err "启动 fail2ban 失败"; return 1; }
  sleep 2
  ok "fail2ban 服务状态:"
  systemctl is-active fail2ban | sed 's/^/  /'
  info "jail 列表:"
  fail2ban-client status 2>/dev/null | sed 's/^/  /'
  info "sshd jail 状态:"
  fail2ban-client status sshd 2>/dev/null | sed 's/^/  /'
  ok "第 8 项完成。"
  warn "Fail2ban 是 SSH Key + UFW + 关闭密码登录的补充，不是替代品。"
  warn "不要故意输错密码测试，以免把自己的公网 IP 封掉。"
}

#---------------------------- 第 9 项：3X-UI 面板入口（检查 + 可选白名单） ----------------------------#
step9_xui_panel() {
  hdr "第 9 项：保护 3X-UI 管理入口"
  # 正确探测 x-ui 单元是否存在（list-unit-files <name> 即使不存在也返回 0）
  if ! { systemctl list-unit-files 2>/dev/null | grep -q '^x-ui\.service[[:space:]]' \
         || [ -f /etc/systemd/system/x-ui.service ] \
         || [ -f /lib/systemd/system/x-ui.service ]; }; then
    warn "未检测到 x-ui 服务。请先完成第 2~8 项后再安装 3X-UI / Reality / Hysteria2。"
    info "安装并配置完 3X-UI 后，请手动检查：非默认用户名 + 独立长密码 + 随机 Web Base Path + HTTPS + 2FA。"
    return 0
  fi
  ok "检测到 x-ui 服务，当前监听端口:"
  ss -lntup 2>/dev/null | grep -i x-ui | sed 's/^/  /' || ss -lntup | sed 's/^/  /'
  info "面板安全检查项（请到 3X-UI 面板 / x-ui 命令里逐项核对）:"
  cat <<'EOF' | sed 's/^/  /'
  1. 管理员账号：非默认用户名 + 独立长密码，不与其他网站共用
  2. Web Base Path：使用随机路径（降低被扫描命中的概率）
  3. HTTPS：域名 / TLS 证书 / 私钥路径正确，浏览器无证书错误
  4. 2FA：当前版本支持时开启两步验证
  5. 不要在公开渠道泄漏：面板完整 URL / 账号密码 / API Token / 订阅链接 / UUID / Reality Private Key / TLS Private Key
EOF
  if confirm "有固定公网管理 IP，是否现在就限制面板端口只允许该 IP 访问？"; then
    local ADMIN_IP="" PANEL_PORT=""
    read -r -p "输入您的固定管理公网 IP: " ADMIN_IP
    read -r -p "输入 3X-UI 面板端口: " PANEL_PORT
    [ -n "$ADMIN_IP" ] && [ -n "$PANEL_PORT" ] || { err "IP 或端口为空，已跳过。"; return 1; }
    ufw allow from "$ADMIN_IP" to any port "$PANEL_PORT" proto tcp
    ok "已添加白名单规则。请确认规则后再删除旧的全局放行规则:"
    ufw status numbered | sed 's/^/  /'
    warn "若原规则里有类似 \`Anywhere ALLOW <面板端口>\` 的全局放行，确认新规则生效后用: ufw delete <规则编号> 删除。"
    warn "固定 IP 经常变化的用户请不要使用 IP 白名单。"
  fi
}

#---------------------------- 第 10 项：备份 3X-UI 数据库 ----------------------------#
step10_xui_backup() {
  hdr "第 10 项：备份 3X-UI 数据库并带离 VPS"
  if [ ! -f /etc/x-ui/x-ui.db ]; then
    warn "未找到 /etc/x-ui/x-ui.db（默认 SQLite 数据库）。"
    info "若使用 PostgreSQL / Docker Volume 等方案，请勿照抄本步 SQLite 方法。"
    return 0
  fi
  ls -lh /etc/x-ui/x-ui.db | sed 's/^/  /'
  mkdir -p /root/backups
  local dest="/root/backups/x-ui-$(date +%F-%H%M).db"
  confirm "将短暂停止 x-ui 服务以生成一致副本，继续？" || return 0
  systemctl stop x-ui
  cp /etc/x-ui/x-ui.db "$dest"
  systemctl start x-ui
  sleep 1
  systemctl is-active x-ui >/dev/null 2>&1 && ok "x-ui 已重新运行" || err "x-ui 未运行，请检查"
  ok "数据库副本已生成: $dest"
  ls -lh "$dest" | sed 's/^/  /'
  echo
  warn "本机副本不是最终备份——服务器被删，本机备份也会消失。请立刻下载到 VPS 之外:"
  echo "  本机执行:  scp root@<你的服务器IP>:$dest ."
  echo "  或保存到另一台独立 VPS / 加密存储；含 x-ui.db、私钥、Token 的备份一律视为敏感数据。"
  info "恢复点建议：基础加固完成后打一个厂商 Snapshot；3X-UI 配置完成后做应用配置外部备份。"
}

#---------------------------- 第 1 项（手动清单提醒） ----------------------------#
step1_manual() {
  hdr "第 1 项：Console / MFA / 恢复能力（服务商后台手动完成，脚本无法代劳）"
  cat <<'EOF'
  请在 VPS 服务商后台完成以下事项，再开始第 2 项：
  [ ] 实际登录一次 Web Console / VNC / Serial Console（不要只看有没有按钮）
  [ ] 服务商账户开启 MFA（Authenticator / Passkey / 硬件密钥），恢复码保存在 VPS 之外
  [ ] 确认 Snapshot（快照）与 Reinstall（重装）入口
  [ ] 确认 Cloud Firewall（云防火墙）入口并了解其规则
  [ ] 记录：公网 IP / Ubuntu 版本 / 当前 SSH 端口 / Console 入口 / 快照位置
EOF
}

#---------------------------- 汇总报告 ----------------------------#
final_report() {
  hdr "汇总：请对照检查（教程『最终检查清单』节选）"
  cat <<'EOF'
  退路   [ ] 厂商账户已开 MFA    [ ] 恢复码已保存    [ ] Console 已实测    [ ] 快照入口已确认
  身份   [ ] sudo 用户已建        [ ] SSH Key 新窗口已验证    [ ] root SSH 登录已关闭    [ ] 密码认证已关闭
         [ ] AllowUsers 填写正确  [ ] sshd -T 生效值符合预期
  边界   [ ] UFW 已开启           [ ] SSH 端口已放行           [ ] 未提前开放无关端口     [ ] IPv6 已检查
         [ ] 云防火墙已检查       [ ] ss -lntup 监听服务均确认用途
  入口   [ ] 3X-UI 独立账号/强密码/随机路径/HTTPS/2FA    [ ] 面板敏感信息未公开
  备份   [ ] x-ui 数据库已备份并保存到 VPS 之外          [ ] 基础加固后已做 Snapshot

  三条铁律（教程原文）：
   1. 任何影响 SSH 登录的配置：先保留旧连接，再用新窗口验证。
   2. 任何防火墙配置：必须明确自己正在开放什么。
   3. 任何重要配置：不能只有服务器本机这一份副本。
EOF
  info "完整清单见教程页底部。本脚本操作日志: $LOG_FILE"
}

#---------------------------- 菜单 ----------------------------#
menu() {
  while true; do
    echo
    hdr "新 VPS 基础安全一键脚本"
    echo "  0) 预检（系统/身份/端口，+ 第 1 项手动清单）"
    echo "  2) 第 2 项  更新系统 + 启用自动安全更新"
    echo "  3) 第 3 项  创建普通 sudo 管理用户"
    echo "  4) 第 4 项  安装 SSH Key 到普通用户"
    echo "  5) 第 5 项  关闭 root / 密码登录（SSH 加固）"
    echo "  6) 第 6 项  配置 UFW 防火墙"
    echo "  7) 第 7 项  检查监听端口（只读报告）"
    echo "  8) 第 8 项  安装并验证 Fail2ban"
    echo "  9) 第 9 项  3X-UI 面板入口检查（已安装时可用）"
    echo " 10) 第 10 项 备份 3X-UI 数据库（已安装时可用）"
    echo "  a) 顺序执行 第 2→8 项（推荐，逐步确认）"
    echo "  r) 显示最终检查清单"
    echo "  q) 退出"
    local choice
    if ! ask "请选择（输入上面的编号后回车，q 退出）:" choice; then echo; exit 0; fi
    case "$choice" in
      0) os_check; step1_manual ;;
      2) step2_update ;;
      3) step3_user ;;
      4) step4_sshkey ;;
      5) step5_sshd ;;
      6) step6_ufw ;;
      7) step7_listeners ;;
      8) step8_fail2ban ;;
      9) step9_xui_panel ;;
      10) step10_xui_backup ;;
      a) os_check; step1_manual
         if step2_update && step3_user && step4_sshkey && step5_sshd && step6_ufw && step7_listeners && step8_fail2ban; then
           final_report
         else
           err "流程中断：请按上面的提示处理后，单独重跑该项（如 sudo bash $0 --step 5）再继续后续项。"
         fi ;;
      r) final_report ;;
      q) exit 0 ;;
      *) warn "无效选择: $choice" ;;
    esac
  done
}

#---------------------------- 入口 ----------------------------#
main() {
  ensure_root "$@"
  [ "${DEBUG:-0}" = "1" ] && set -x
  printf '%b' "${C_BLD}${C_GRN}vps-hardening.sh 已启动${C_N}  PID=$$  时间=$(date '+%F %T')  日志=$LOG_FILE\n"
  if [ ! -t 0 ]; then
    warn "标准输入不是终端（管道或重定向）：交互提示将无法输入，脚本可能看起来“卡住”。"
    warn "请改用 install.sh，或先下载脚本再执行：sudo bash vps-hardening.sh"
  fi
  log "=== vps-hardening.sh 开始: $* ==="
  case "${1:-}" in
    --auto)      os_check; step1_manual
                 if step2_update && step3_user && step4_sshkey && step5_sshd \
                      && step6_ufw && step7_listeners && step8_fail2ban; then
                   final_report
                 else
                   err "流程中断：请按上面的提示处理后，单独重跑该项（如 sudo bash $0 --step 5）再继续后续项。"
                 fi ;;
    --step)      shift
                 case "${1:-}" in
                   2) os_check; step2_update ;;
                   3) step3_user ;;
                   4) step4_sshkey ;;
                   5) step5_sshd ;;
                   6) step6_ufw ;;
                   7) step7_listeners ;;
                   8) os_check; step8_fail2ban ;;
                   9) step9_xui_panel ;;
                   10) step10_xui_backup ;;
                   *) err "未知步骤: ${1:-}（可用 2~10）"; exit 1 ;;
                 esac ;;
    --fail2ban)  os_check; step8_fail2ban ;;
    --help|-h)   grep -E '^#   ' "$0" | sed 's/^#   //'; exit 0 ;;
    *)           menu ;;
  esac
  log "=== vps-hardening.sh 结束 ==="
}

main "$@"
