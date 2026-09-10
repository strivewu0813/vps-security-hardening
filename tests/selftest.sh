#!/usr/bin/env bash
#=============================================================================
# tests/selftest.sh — 不修改系统、不联网的自检/回归测试
#
# 用法：
#   bash tests/selftest.sh              # 默认以脚本所在仓库根目录为目标
#   bash tests/selftest.sh /path/to/repo
#
# 覆盖：语法检查、适配层函数是否齐全（曾丢掉 confirm 导致所有确认变“否”）、
#       确认函数行为（y/n/EOF）、IP 校验、发行版家族映射、
#       各家族包管理器命令是否齐备、引擎参数处理、封装脚本的模式保护。
#=============================================================================
set -uo pipefail

ROOT="${1:-$(cd -- "$(dirname -- "$0")/.." >/dev/null 2>&1 && pwd)}"
cd "$ROOT" || exit 1
TMPIN="${TMPDIR:-/tmp}/vh-selftest-input.$$"
: > "$TMPIN"

pass=0; fail=0
chk() { # $1=描述 $2=期望 $3=实际
  if [ "$2" = "$3" ]; then printf 'ok   %s\n' "$1"; pass=$((pass + 1))
  else printf 'FAIL %s (期望 %s, 实际 %s)\n' "$1" "$2" "$3"; fail=$((fail + 1)); fi
}
yn() { # 把“成功/失败”转成 0/1 便于比较
  if "$@" >/dev/null 2>&1; then echo 0; else echo 1; fi
}

echo "目标目录: $ROOT"
echo "== 1. bash -n 语法 =="
for f in vps-hardening.sh vps-hardening-no-key.sh install.sh lib/platform.sh tests/selftest.sh tests/integration.sh; do
  if out=$(bash -n "$f" 2>&1); then echo "ok   $f 语法"; pass=$((pass + 1))
  else echo "FAIL $f 语法:"; printf '%s\n' "$out" | sed 's/^/     /'; fail=$((fail + 1)); fi
done

echo "== 2. 适配层关键函数是否齐全 =="
# shellcheck disable=SC1091
. ./lib/platform.sh
FN_LIST="confirm confirm_timed ask info ok warn err hdr need_cmd run_timed plat_detect plat_report plat_is_supported plat_detect_ssh \
  pkg_update pkg_upgrade_all pkg_install pkg_has pkg_install_fail2ban \
  svc_exists svc_active svc_is_enabled svc_enable_now svc_restart svc_start svc_stop svc_try_restart \
  svc_enable_only svc_daemon_reload svc_status_text svc_list_running bsd_ctl install_systemd_timer \
  fw_detect fw_allow_port fw_delete_port fw_allow_from fw_rule_has_port fw_has_global_port \
  fw_enable fw_is_active fw_defaults_deny_incoming fw_defaults_ok fw_show fw_manual_note fw_iptables_persist \
  ssh_conf_prepare ssh_conf_conflict_scan sshd_test sshd_effective_dump ssh_effective_is ssh_effective_has_user \
  ssh_direct_comment_conflicts ssh_apply_and_verify ssh_recover_after_failure \
  all_ssh_ports current_session_port net_listen net_addrs listen_port_ok \
  reboot_required auto_updates_setup auto_updates_manual_hint valid_ipv4 valid_ipv6"
fn_missing=0; fn_total=0
for fn in $FN_LIST; do
  fn_total=$((fn_total + 1))
  if declare -F "$fn" >/dev/null; then pass=$((pass + 1))
  else echo "FAIL $fn 未定义"; fail=$((fail + 1)); fn_missing=$((fn_missing + 1)); fi
done
if [ "$fn_missing" = "0" ]; then echo "ok   适配层 $fn_total 个函数全部存在"; fi

echo "== 3. confirm 行为（y / n / EOF）=="
# 注意：不能把断言放进管道子 shell，否则 pass/fail 计数会丢失（曾经的假绿）
printf 'y\n' > "$TMPIN"
confirm "t" < "$TMPIN" >/dev/null 2>&1; chk "confirm y -> 0" 0 $?
printf 'n\n' > "$TMPIN"
confirm "t" < "$TMPIN" >/dev/null 2>&1; chk "confirm n -> 1" 1 $?
confirm "t" </dev/null >/dev/null 2>&1; chk "confirm EOF -> 1（安全）" 1 $?

echo "== 4. confirm_timed 默认值（EOF 时按默认，不再无限等待）=="
confirm_timed "t" 1 y </dev/null >/dev/null 2>&1; chk "confirm_timed 默认 y -> 0" 0 $?
confirm_timed "t" 1 n </dev/null >/dev/null 2>&1; chk "confirm_timed 默认 n -> 1" 1 $?

echo "== 5. IP 校验 =="
chk "valid_ipv4 1.2.3.4 接受" 0 "$(yn valid_ipv4 1.2.3.4)"
chk "valid_ipv4 999.1.1.1 拒绝" 1 "$(yn valid_ipv4 999.1.1.1)"
chk "valid_ipv4 08.1.1.1 接受" 0 "$(yn valid_ipv4 08.1.1.1)"
chk "valid_ipv4 abc 拒绝" 1 "$(yn valid_ipv4 abc)"
chk "valid_ipv6 2001:db8::1 接受" 0 "$(yn valid_ipv6 2001:db8::1)"
chk "valid_ipv6 :::: 拒绝" 1 "$(yn valid_ipv6 ::::)"
chk "valid_ipv6 1:2:3:4:5:6:7:8 接受" 0 "$(yn valid_ipv6 1:2:3:4:5:6:7:8)"
chk "valid_ipv6 12345::1 拒绝" 1 "$(yn valid_ipv6 12345::1)"
chk "valid_ipv6 1:2:3 拒绝" 1 "$(yn valid_ipv6 1:2:3)"

echo "== 6. 发行版家族映射（直接提取 lib 中的真实 case 块）=="
block=$(awk '/^  case "\$PLAT_ID" in/{f=1} f{print} f&&/^  esac$/{c++; if(c==1) exit}' lib/platform.sh)
mapfamily() {
  PLAT_ID="$1"; PLAT_LIKE="$2"; PLAT_FAMILY=""
  eval "$block" 2>/dev/null
  printf '%s' "$PLAT_FAMILY"
}
chk "ubuntu" debian "$(mapfamily ubuntu '')"
chk "debian" debian "$(mapfamily debian '')"
chk "linuxmint/ubuntu" debian "$(mapfamily linuxmint ubuntu)"
chk "kali/debian" debian "$(mapfamily kali debian)"
chk "raspbian" debian "$(mapfamily raspbian '')"
chk "linuxmint" debian "$(mapfamily linuxmint ubuntu)"
chk "rocky/rhel centos fedora" rhel "$(mapfamily rocky 'rhel centos fedora')"
chk "fedora" rhel "$(mapfamily fedora '')"
chk "almalinux" rhel "$(mapfamily almalinux 'rhel centos fedora')"
chk "amzn" rhel "$(mapfamily amzn '')"
chk "ol(oracle)" rhel "$(mapfamily ol '')"
chk "ol fedora" rhel "$(mapfamily ol fedora)"
chk "opensuse-leap/suse" suse "$(mapfamily opensuse-leap suse)"
chk "sles" suse "$(mapfamily sles '')"
chk "arch" arch "$(mapfamily arch '')"
chk "manjaro/arch" arch "$(mapfamily manjaro arch)"
chk "alpine" alpine "$(mapfamily alpine '')"
chk "gentoo" gentoo "$(mapfamily gentoo '')"
chk "void" void "$(mapfamily void '')"
chk "freebsd" bsd "$(mapfamily freebsd '')"
chk "openbsd" bsd "$(mapfamily openbsd '')"
chk "darwin" darwin "$(mapfamily darwin '')"
chk "solus 不应误判为 rhel" unknown "$(mapfamily solus '')"
chk "mageia 未识别" unknown "$(mapfamily mageia mandriva)"

echo "== 7. 各家族包管理器分支是否真的存在（锚定到 case 分支，避免被别处字符串蒙混）=="
# $1=描述 $2=正则
chk_branch() { # 用“函数体内该分支行”做断言
  if grep -qE -- "$2" lib/platform.sh; then echo "ok   $1"; pass=$((pass + 1))
  else echo "FAIL $1（未匹配: $2）"; fail=$((fail + 1)); fi
}
chk_branch "apt 安装分支"           '^[[:space:]]*apt\)[[:space:]]+DEBIAN_FRONTEND=noninteractive apt-get install'
chk_branch "dnf 安装分支"           '^[[:space:]]*dnf\)[[:space:]]+dnf -y install'
chk_branch "yum 安装分支"           '^[[:space:]]*yum\)[[:space:]]+yum -y install'
chk_branch "zypper 安装分支"        '^[[:space:]]*zypper\)[[:space:]]+zypper --non-interactive install'
chk_branch "pacman 安装分支"        '^[[:space:]]*pacman\)[[:space:]]+pacman -S'
chk_branch "apk 安装分支"           '^[[:space:]]*apk\)[[:space:]]+apk add'
chk_branch "emerge 安装分支"        '^[[:space:]]*emerge\)[[:space:]]+emerge'
chk_branch "xbps 安装分支"          '^[[:space:]]*xbps\)[[:space:]]+xbps-install'
chk_branch "pkg 安装分支"           '^[[:space:]]*pkg\)[[:space:]]+pkg install'
chk_branch "pkg_add 安装分支"       '^[[:space:]]*pkg_add\)[[:space:]]+pkg_add'
chk_branch "apt 更新分支"           '^[[:space:]]*apt\)[[:space:]]+DEBIAN_FRONTEND=noninteractive apt-get update'
chk_branch "pacman 全量升级(-Syu 等价)" '^[[:space:]]*pacman\)[[:space:]]+pacman -Su '
chk_branch "apk 升级分支"           '^[[:space:]]*apk\)[[:space:]]+apk upgrade'
chk_branch "FreeBSD pkg 升级"       '^[[:space:]]*pkg\)[[:space:]]+pkg upgrade'
chk_branch "DragonFly 归入 pkg"     'freebsd\|dragonfly\) PKG=pkg'

echo "== 8. init 抽象覆盖（锚定到分支）=="
chk_branch "systemd 启用"           'systemd\) systemctl enable --now'
chk_branch "openrc 启用"            'rc-update add "\$n" default'
chk_branch "sysv 启用"              'update-rc.d "\$n" defaults'
chk_branch "runit 启用"             'sv up "\$n"'
chk_branch "BSD rcctl"              'rcctl start "\$n"'
chk_branch "BSD sysrc"              'sysrc "\$\{rcvar\}=YES"'
chk_branch "OpenBSD rcctl enable"   'rcctl enable "\$n"'

echo "== 9. 引擎参数处理（用假 id 通过 root 检查；并捕获真实退出码）=="
mkdir -p tests/fakebin
trap 'rm -rf "$ROOT/tests/fakebin" "$TMPIN"' EXIT INT TERM HUP
printf '#!/bin/sh\necho 0\n' > tests/fakebin/id
chmod +x tests/fakebin/id
# 屏蔽网络工具，保证本套件“不联网”
for t in curl wget; do
  printf '#!/bin/sh\nexit 1\n' > "tests/fakebin/$t"; chmod +x "tests/fakebin/$t"
done
chk "主引擎文件存在（否则后续断言无意义）" 0 "$([ -f vps-hardening.sh ] && echo 0 || echo 1)"
chk "封装文件存在" 0 "$([ -f vps-hardening-no-key.sh ] && echo 0 || echo 1)"
run_engine() { PATH="$PWD/tests/fakebin:$PATH" bash ./vps-hardening.sh "$@"; }

out=$(run_engine --help 2>&1); rc=$?
chk "--help 打印用法" 0 "$(printf '%s' "$out" | grep -q '用法：' && echo 0 || echo 1)"
chk "--help 退出码 0" 0 "$rc"
out=$(run_engine --step 2>&1); rc=$?
chk "--step 缺参数报错" 0 "$(printf '%s' "$out" | grep -q '需要跟一个数字' && echo 0 || echo 1)"
chk "--step 缺参数退出码非 0" 1 "$([ "$rc" = 0 ] && echo 0 || echo 1)"
out=$(run_engine --step 99 2>&1)
chk "--step 99 报错" 0 "$(printf '%s' "$out" | grep -q '需要跟一个数字' && echo 0 || echo 1)"
out=$(run_engine --step 5 --auto 2>&1)
chk "--step 与 --auto 互斥" 0 "$(printf '%s' "$out" | grep -q '不能同时使用' && echo 0 || echo 1)"
out=$(run_engine --auto --setup-only 2>&1)
chk "--auto 与 --setup-only 互斥（不再静默跑全流程）" 0 "$(printf '%s' "$out" | grep -q '不能同时使用' && echo 0 || echo 1)"
out=$(run_engine --bogus 2>&1)
chk "未知参数报错" 0 "$(printf '%s' "$out" | grep -q '未知参数' && echo 0 || echo 1)"
out=$(run_engine --setup-only 2>&1); rc=$?
chk "--setup-only 正常结束（退出码 0）" 0 "$rc"
chk "--setup-only 打印平台报告" 0 "$(printf '%s' "$out" | grep -q '系统     :' && echo 0 || echo 1)"
out=$(run_engine --mode password --setup-only 2>&1); rc=$?
chk "--mode password 可解析" 0 "$rc"
out=$(run_engine --mode bogus 2>&1)
chk "--mode 非法值报错" 0 "$(printf '%s' "$out" | grep -q '需要 key 或 password' && echo 0 || echo 1)"
out=$(MODE=bogus run_engine --setup-only 2>&1)
chk "环境变量 MODE 非法值被拒绝" 0 "$(printf '%s' "$out" | grep -q 'MODE 只能是 key 或 password' && echo 0 || echo 1)"

echo "== 10. 封装脚本的模式保护 =="
out=$(PATH="$PWD/tests/fakebin:$PATH" bash ./vps-hardening-no-key.sh --key 2>&1)
chk "wrapper 拒绝 --key" 0 "$(printf '%s' "$out" | grep -q '固定为密码登录模式' && echo 0 || echo 1)"
out=$(PATH="$PWD/tests/fakebin:$PATH" bash ./vps-hardening-no-key.sh --mode key 2>&1)
chk "wrapper 拒绝 --mode" 0 "$(printf '%s' "$out" | grep -q '不接受 --mode' && echo 0 || echo 1)"
out=$(PATH="$PWD/tests/fakebin:$PATH" bash ./vps-hardening-no-key.sh --mode=password --help 2>&1)
chk "wrapper 接受 --mode=password（等同固定模式）" 0 "$(printf '%s' "$out" | grep -qv '固定为密码登录模式' && echo 0 || echo 1)"

echo "== 11. install.sh 的内容校验（真正调用 valid_script，而非 grep 源码）=="
# 从 install.sh 中提取 valid_script 与 fetch 定义后在当前 shell 求值，然后真实校验各产物
VS_SRC=$(awk '/^valid_script\(\) \{/,/^\}/' install.sh)
if [ -n "$VS_SRC" ]; then
  eval "$VS_SRC"
  chk "valid_script 接受主引擎" 0 "$(valid_script vps-hardening.sh '^step5_sshd\(\)' '^build_ssh_block\(\)' && echo 0 || echo 1)"
  chk "valid_script 接受平台层" 0 "$(valid_script lib/platform.sh '^plat_detect\(\) \{' '^ssh_apply_and_verify\(\)' && echo 0 || echo 1)"
  chk "valid_script 接受封装（曾经被误拒）" 0 "$(valid_script vps-hardening-no-key.sh '^is_engine\(\)' '^exec bash "\$engine" --mode password' && echo 0 || echo 1)"
  chk "valid_script 拒绝 HTML 错误页" 1 "$(printf '<html><body>404</body></html>\n' > "$TMPIN"; valid_script "$TMPIN" '^step5_sshd\(\)' && echo 0 || echo 1)"
  chk "valid_script 拒绝截断的主引擎" 1 "$(head -n 20 vps-hardening.sh > "$TMPIN"; valid_script "$TMPIN" '^step5_sshd\(\)' '^build_ssh_block\(\)' && echo 0 || echo 1)"
  chk "valid_script 拒绝把 install.sh 当引擎" 1 "$(valid_script install.sh '^step5_sshd\(\)' '^build_ssh_block\(\)' && echo 0 || echo 1)"
  chk "valid_script 拒绝把封装当引擎" 1 "$(valid_script vps-hardening-no-key.sh '^step5_sshd\(\)' '^build_ssh_block\(\)' && echo 0 || echo 1)"
else
  echo "FAIL 未能从 install.sh 提取 valid_script"; fail=$((fail + 1))
fi
chk "install 会安装 lib/platform.sh" 0 "$(grep -qF 'lib/platform.sh' install.sh && echo 0 || echo 1)"
chk "install 先装平台层再装引擎" 0 "$(awk '/acquire "lib\/platform.sh"/{l=NR} /acquire "vps-hardening.sh"/{e=NR} END{exit !(l && e && l<e)}' install.sh && echo 0 || echo 1)"

rm -rf tests/fakebin

echo "== 12. install.sh / 封装 不得调用未加载的辅助函数（need_cmd 曾经漏定义）=="
LIB_FNS=$(grep -oE '^[a-z_]+\(\)' lib/platform.sh | tr -d '()' | sort -u)
MISSING_LOCAL=""
for f in install.sh vps-hardening-no-key.sh; do
  LOCAL_FNS=$(grep -oE '^[a-z_]+\(\)' "$f" | tr -d '()' | sort -u)
  for fn in $LIB_FNS; do
    # 只看“被当作命令调用”的形态（名字后跟空白或 $），避免把字符串里的标记误判
    if grep -qE "(^|[^[:alnum:]_])${fn}[[:space:]$]" "$f"; then
      printf '%s\n' "$LOCAL_FNS" | grep -qx "$fn" || MISSING_LOCAL="$MISSING_LOCAL $f:$fn"
    fi
  done
  chk "$f 未调用未定义的平台层函数" "" "$(printf '%s' "$MISSING_LOCAL" | grep -o "$f:[a-z_]*" | tr '\n' ' ')"
done

echo "== 13. install.sh 在沙箱里真的能跑（本地目录快路径，不联网）=="
SBX="${TMPDIR:-/tmp}/vh-install-test.$$"
mkdir -p "$SBX/bin" "$SBX/lib" "$SBX/stub"
printf '#!/bin/sh\nexit 1\n' > "$SBX/stub/curl"; chmod +x "$SBX/stub/curl"
printf '#!/bin/sh\nexit 1\n' > "$SBX/stub/wget"; chmod +x "$SBX/stub/wget"
printf '#!/bin/sh\necho 0\n' > "$SBX/stub/id";   chmod +x "$SBX/stub/id"
chk "未定义函数静态检查（need_cmd 类问题）" "" "$MISSING_LOCAL"
out=$(PATH="$SBX/stub:$PATH" VPS_LIB_DIR="$SBX/lib" bash ./install.sh --dir "$SBX/bin" --install-only 2>&1); rc=$?
chk "install.sh --install-only 退出码 0（本地快路径）" 0 "$rc"
chk "输出里没有 'command not found'" 1 "$(printf '%s' "$out" | grep -q 'command not found' && echo 0 || echo 1)"
chk "输出里没有 '未找到命令'（中文 locale）" 1 "$(printf '%s' "$out" | grep -q '未找到命令' && echo 0 || echo 1)"
chk "没有误报「未找到 curl 或 wget」" 1 "$(printf '%s' "$out" | grep -q '未找到 curl 或 wget' && echo 0 || echo 1)"
chk "装上了主引擎" 0 "$([ -s "$SBX/bin/vps-hardening" ] && echo 0 || echo 1)"
chk "装上了封装" 0 "$([ -s "$SBX/bin/vps-hardening-no-key" ] && echo 0 || echo 1)"
chk "装上了平台层（VPS_LIB_DIR 可覆盖）" 0 "$([ -s "$SBX/lib/platform.sh" ] && echo 0 || echo 1)"
# 装出来的脚本要能真的跑起来（引擎能通过 VPS_LIB_DIR 找到平台层）
out2=$(PATH="$SBX/stub:$PATH" VPS_LIB_DIR="$SBX/lib" bash "$SBX/bin/vps-hardening" --setup-only 2>&1); rc2=$?
chk "装好的引擎可运行（--setup-only 退出码 0）" 0 "$rc2"
chk "装好的引擎打印平台报告" 0 "$(printf '%s' "$out2" | grep -q '系统     :' && echo 0 || echo 1)"
rm -rf "$SBX"

echo
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" = "0" ]
