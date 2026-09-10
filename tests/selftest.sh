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
for f in vps-hardening.sh vps-hardening-no-key.sh install.sh lib/platform.sh; do
  if out=$(bash -n "$f" 2>&1); then echo "ok   $f 语法"; pass=$((pass + 1))
  else echo "FAIL $f 语法:"; printf '%s\n' "$out" | sed 's/^/     /'; fail=$((fail + 1)); fi
done

echo "== 2. 适配层关键函数是否齐全 =="
# shellcheck disable=SC1091
. ./lib/platform.sh
for fn in confirm confirm_timed ask info ok warn err hdr need_cmd run_timed plat_detect plat_report plat_is_supported \
  pkg_update pkg_upgrade_all pkg_install pkg_has pkg_install_fail2ban \
  svc_exists svc_active svc_is_enabled svc_enable_now svc_restart svc_start svc_stop svc_try_restart bsd_ctl \
  fw_detect fw_allow_port fw_delete_port fw_allow_from fw_rule_has_port fw_has_global_port \
  fw_enable fw_is_active fw_defaults_deny_incoming fw_show fw_manual_note \
  ssh_conf_prepare ssh_conf_conflict_scan sshd_test sshd_effective_dump ssh_effective_is ssh_effective_has_user \
  ssh_apply_and_verify ssh_recover_after_failure all_ssh_ports current_session_port net_listen net_addrs listen_port_ok \
  reboot_required auto_updates_setup auto_updates_manual_hint valid_ipv4 valid_ipv6; do
  if declare -F "$fn" >/dev/null; then pass=$((pass + 1))
  else echo "FAIL $fn 未定义"; fail=$((fail + 1)); fi
done
echo "ok   已检查 $(printf '%s' "$(declare -F | wc -l)") 个函数定义（详见上方 FAIL）"

echo "== 3. confirm 行为（y / n / EOF）=="
printf 'y\n' | { confirm "t" >/dev/null 2>&1; chk "confirm y -> 0" 0 $?; }
printf 'n\n' | { confirm "t" >/dev/null 2>&1; chk "confirm n -> 1" 1 $?; }
{ confirm "t" </dev/null >/dev/null 2>&1; chk "confirm EOF -> 1（安全）" 1 $?; }

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

echo "== 7. 各家族包管理器命令齐备（静态检查）=="
for pair in "apt:apt-get install -y" "dnf:dnf -y install" "yum:yum -y install" "zypper:zypper --non-interactive install" \
  "pacman:pacman -S --noconfirm" "apk:apk add" "emerge:emerge --quiet" "xbps:xbps-install -y" \
  "pkg:pkg install -y" "pkg_add:pkg_add"; do
  fam="${pair%%:*}"; needle="${pair#*:}"
  if grep -qF -- "$needle" lib/platform.sh; then echo "ok   $fam 分支含 '$needle'"; pass=$((pass + 1))
  else echo "FAIL $fam 分支缺少 '$needle'"; fail=$((fail + 1)); fi
done

echo "== 8. init 抽象覆盖 =="
for needle in 'systemctl enable --now' 'rc-update add' 'update-rc.d' 'sv up' 'sysrc' 'rcctl'; do
  if grep -qF -- "$needle" lib/platform.sh; then echo "ok   init 抽象含 '$needle'"; pass=$((pass + 1))
  else echo "FAIL init 抽象缺少 '$needle'"; fail=$((fail + 1)); fi
done

echo "== 9. 引擎参数处理（用假 id 通过 root 检查）=="
mkdir -p tests/fakebin
printf '#!/bin/sh\necho 0\n' > tests/fakebin/id
chmod +x tests/fakebin/id
run_engine() { PATH="$PWD/tests/fakebin:$PATH" bash ./vps-hardening.sh "$@"; }

out=$(run_engine --help 2>&1)
chk "--help 打印用法" 0 "$(printf '%s' "$out" | grep -q '用法：' && echo 0 || echo 1)"
out=$(run_engine --step 2>&1)
chk "--step 缺参数报错" 0 "$(printf '%s' "$out" | grep -q '需要跟一个数字' && echo 0 || echo 1)"
out=$(run_engine --step 99 2>&1)
chk "--step 99 报错" 0 "$(printf '%s' "$out" | grep -q '需要跟一个数字' && echo 0 || echo 1)"
out=$(run_engine --step 5 --auto 2>&1)
chk "--step 与 --auto 互斥" 0 "$(printf '%s' "$out" | grep -q '不能同时使用' && echo 0 || echo 1)"
out=$(run_engine --bogus 2>&1)
chk "未知参数报错" 0 "$(printf '%s' "$out" | grep -q '未知参数' && echo 0 || echo 1)"
out=$(run_engine --setup-only 2>&1)
chk "--setup-only 不因 MODE 未定义而崩" 0 "$(printf '%s' "$out" | grep -q 'unbound variable' && echo 1 || echo 0)"
chk "--setup-only 打印平台报告" 0 "$(printf '%s' "$out" | grep -q '系统     :' && echo 0 || echo 1)"
out=$(run_engine --mode password --setup-only 2>&1)
chk "--mode password 可解析" 0 "$(printf '%s' "$out" | grep -q 'unbound variable' && echo 1 || echo 0)"
out=$(run_engine --mode bogus 2>&1)
chk "--mode 非法值报错" 0 "$(printf '%s' "$out" | grep -q '需要 key 或 password' && echo 0 || echo 1)"

echo "== 10. 封装脚本的模式保护 =="
out=$(PATH="$PWD/tests/fakebin:$PATH" bash ./vps-hardening-no-key.sh --key 2>&1)
chk "wrapper 拒绝 --key" 0 "$(printf '%s' "$out" | grep -q '固定为密码登录模式' && echo 0 || echo 1)"

echo "== 11. install.sh 内容校验 =="
chk "valid_script 能识别平台层(plat_detect 分支)" 0 "$(grep -q "grep -q '\^plat_detect()'" install.sh && echo 0 || echo 1)"
chk "install 会安装 lib/platform.sh" 0 "$(grep -q 'lib/platform.sh' install.sh && echo 0 || echo 1)"

rm -rf tests/fakebin
echo
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" = "0" ]
