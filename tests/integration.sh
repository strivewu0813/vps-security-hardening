#!/usr/bin/env bash
#=============================================================================
# tests/integration.sh — 执行级集成测试（不修改真实系统）
#
# 做法：把引擎与平台层复制到沙箱，并把这些绝对路径前缀重写到沙箱内：
#         /etc/  /run/systemd/system  /var/log/vps-hardening.log
#         /root/.vps-hardening-ctx    /var/run/reboot-required
#       再用桩命令模拟 Ubuntu + systemd + ufw + sshd，真实执行引擎的第 5、6 项。
#
# 验证最容易“把自己锁在门外”的路径：
#   * 校验通过 → 配置真正写入并成功应用
#   * 校验失败 → 中止，并且把未生效的配置撤下（不留坏配置给下一次连接）
#   * 防火墙必须先成功放行 SSH 才允许 enable；放行失败就不许 enable
#   * 端口未知时中止，不能瞎猜 22 后开默认拒绝
#   * 密码模式下密码被锁定时拒绝继续；root 不能作为目标用户
#
# 用法：bash tests/integration.sh [仓库根目录]
#=============================================================================
set -uo pipefail

ROOT="${1:-$(cd -- "$(dirname -- "$0")/.." >/dev/null 2>&1 && pwd)}"
SANDBOX="${TMPDIR:-/tmp}/vh-integration.$$"
STUB="$SANDBOX/bin"
BUILD="$SANDBOX/build"
SAND_ETC="$SANDBOX/etc"
WORK="$SANDBOX/work"
export WORK SANDBOX            # 桩脚本里会引用这两个变量
pass=0; fail=0

chk() { if [ "$2" = "$3" ]; then printf 'ok   %s\n' "$1"; pass=$((pass + 1)); else printf 'FAIL %s (期望 %s, 实际 %s)\n' "$1" "$2" "$3"; fail=$((fail + 1)); fi; }
has() { printf '%s' "$1" | grep -q -- "$2" && echo 0 || echo 1; }

rm -rf "$SANDBOX"
mkdir -p "$STUB" "$BUILD/lib" "$WORK" "$SAND_ETC/ssh/sshd_config.d" "$SANDBOX/run/systemd/system" "$SANDBOX/var/log" "$SANDBOX/root"
trap 'rm -rf "$SANDBOX"' EXIT

#------------------------------ 构建“沙箱版”脚本 ------------------------------#

rewrite() { # $1=源文件 $2=目标文件
  sed -e "s|/etc/|$SAND_ETC/|g" \
    -e "s|/run/systemd/system|$SANDBOX/run/systemd/system|g" \
    -e "s|/var/log/vps-hardening.log|$SANDBOX/var/log/vps-hardening.log|g" \
    -e "s|/root/\.vps-hardening-ctx|$SANDBOX/root/.vps-hardening-ctx|g" \
    -e "s|/var/run/reboot-required|$SANDBOX/var/run/reboot-required|g" \
    "$1" > "$2"
}
rewrite "$ROOT/vps-hardening.sh" "$BUILD/vps-hardening.sh"
rewrite "$ROOT/lib/platform.sh" "$BUILD/lib/platform.sh"
chmod +x "$BUILD/vps-hardening.sh"
ENGINE="$BUILD/vps-hardening.sh"

# 模拟 Ubuntu
cat > "$SAND_ETC/os-release" <<'EOF'
ID=ubuntu
ID_LIKE=debian
VERSION_ID="24.04"
PRETTY_NAME="Ubuntu 24.04 LTS (simulated)"
EOF
printf 'root:x:0:\nsudo:x:27:alex\nusers:x:100:\n' > "$SAND_ETC/group"

ssh_main="$SAND_ETC/ssh/sshd_config"
ssh_dropin="$SAND_ETC/ssh/sshd_config.d/00-vps-hardening.conf"
cat > "$ssh_main" <<'EOF'
Include /etc/ssh/sshd_config.d/*.conf
Port 22
#PermitRootLogin prohibit-password
PasswordAuthentication yes
EOF
# 上面的 Include 行也指向沙箱
sed -i.bak "s|/etc/ssh/sshd_config.d|$SAND_ETC/ssh/sshd_config.d|" "$ssh_main" 2>/dev/null || true
rm -f "${ssh_main}.bak"

#------------------------------ 桩命令 ------------------------------#

mkstub() { printf '%s\n' "$2" > "$STUB/$1"; chmod +x "$STUB/$1"; }

mkstub id '#!/usr/bin/env bash
case "${1:-}" in
  -u) if [ -z "${2:-}" ]; then echo 0; elif [ "$2" = root ]; then echo 0; else echo 1000; fi ;;
  -gn) echo users ;;
  -nG) echo "${2:-alex} sudo" ;;
  "") echo 0 ;;
  *) echo "uid=1000($1) gid=1000(users) groups=1000(users),27(sudo)" ;;
esac
exit 0'

# uname：让平台检测认为是 Linux（否则会按未知平台处理）
mkstub uname '#!/usr/bin/env bash
case "${1:-}" in
  -s) echo Linux ;;
  -m) echo x86_64 ;;
  -r) echo 6.8.0-generic ;;
  *)  echo Linux ;;
esac
exit 0'

mkstub getent '#!/usr/bin/env bash
case "${1:-}" in
  passwd) if [ "${2:-}" = root ]; then echo "root:x:0:0:root:/root:/bin/bash"; else echo "${2:-alex}:x:1000:1000::$WORK/home/${2:-alex}:/bin/bash"; fi ;;
  shadow) echo "${2:-alex}:\$6\$hash:19000:0:99999:7:::" ;;
  group)  echo "${2:-sudo}:x:27:" ;;
  *) exit 2 ;;
esac'

mkstub passwd '#!/usr/bin/env bash
if [ "${1:-}" = "-S" ]; then
  if [ "${PASSWD_LOCKED:-0}" = "1" ]; then echo "${2:-alex} L 01/01/2026 0 99999 7 -1"; else echo "${2:-alex} P 01/01/2026 0 99999 7 -1"; fi
  exit 0
fi
exit 0'

mkstub useradd '#!/usr/bin/env bash
exit 0'
mkstub usermod '#!/usr/bin/env bash
exit 0'
mkstub visudo '#!/usr/bin/env bash
exit 0'

# sshd：-V 版本 / -t 语法检查 / -T 输出“生效值”（可模拟某个键没生效或完全无输出）
mkstub sshd "#!/usr/bin/env bash
case \"\${1:-}\" in
  -V) echo 'OpenSSH_9.6p1, OpenSSL 3.0.13'; exit 0 ;;
  -t) exit 0 ;;
  -T)
    [ \"\${SSHD_STUB_EMPTY:-0}\" = '1' ] && exit 0
    f='$ssh_dropin'
    [ -f \"\$f\" ] || f='$ssh_main'
    awk -v drop=\"\${SSHD_STUB_DROP:-}\" '
      { line=\$0; sub(/^[ \\t]+/,\"\",line); split(line, a, /[ \\t]+/); k=tolower(a[1]); v=a[2];
        if (k ~ /^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|pubkeyauthentication|maxauthtries|logingracetime|allowusers|x11forwarding|permitemptypasswords|port)\$/ && v != \"\") {
          if (drop != \"\" && k == drop) next;
          print k \" \" v;
        } }' \"\$f\"
    exit 0 ;;
esac
exit 0"

mkstub systemctl "#!/usr/bin/env bash
echo \"systemctl \$*\" >> '$SANDBOX/calls.log'
case \"\${1:-}\" in
  list-unit-files) printf 'ssh.service enabled\nssh.socket enabled\n'; exit 0 ;;
  show) [ \"\${SS_NO_LISTEN:-0}\" = '1' ] && exit 0; echo ':22'; exit 0 ;;
  is-enabled) exit 0 ;;
  is-active) exit 0 ;;
  *) exit 0 ;;
esac"

mkstub ss "#!/usr/bin/env bash
[ \"\${SS_NO_LISTEN:-0}\" = '1' ] && exit 0
case \"\$*\" in
  *-ltn*) printf 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 [::]:22 [::]:*\n' ;;
  *-tnp*) printf 'ESTAB 0 0 10.0.0.5:22 203.0.113.9:51000 users:((sshd,pid=1,fd=3))\n' ;;
  *) printf 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n' ;;
esac
exit 0"

mkstub ip "#!/usr/bin/env bash
echo 'lo UNKNOWN 127.0.0.1/8'
echo 'eth0 UP 10.0.0.5/24'"

mkstub curl '#!/usr/bin/env bash
exit 1'

mkstub ufw "#!/usr/bin/env bash
echo \"ufw \$*\" >> '$SANDBOX/calls.log'
state='$SANDBOX/ufw.state'; touch \"\$state\"
case \"\${1:-}\" in
  allow) shift
         if [ \"\${1:-}\" = from ]; then echo \"from \$*\" >> \"\$state\"; else echo \"\${1:-}\" >> \"\$state\"; fi
         echo 'Rule added' ;;
  delete) echo \"deleted \$*\" >> \"\$state\"; echo 'Rule deleted' ;;
  show) [ \"\${UFW_NO_SHOW:-0}\" = '1' ] && exit 0
        grep -qx '22/tcp' \"\$state\" 2>/dev/null && echo 'ufw allow 22/tcp' ;;
  status) if [ \"\${2:-}\" = numbered ]; then printf 'Status: active\n\n     To       Action      From\n[ 1] 22/tcp   ALLOW IN    Anywhere\n'
          elif [ \"\${2:-}\" = verbose ]; then printf 'Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\nTo       Action      From\n22/tcp   ALLOW IN    Anywhere\n'
          else printf 'Status: active\n\nTo       Action      From\n22/tcp   ALLOW IN    Anywhere\n'; fi ;;
  default|--force) echo 'ok' ;;
esac
exit 0"

mkstub firewall-cmd '#!/usr/bin/env bash
exit 1'
mkstub iptables '#!/usr/bin/env bash
exit 1'
mkstub nft '#!/usr/bin/env bash
exit 0'

export PATH="$STUB:$PATH"

run_engine() { # $1=输入(printf 格式串)，其余=引擎参数
  local input="$1"; shift
  printf '%b' "$input" | bash "$ENGINE" "$@" 2>&1
}
reset_calls() { rm -f "$SANDBOX/calls.log" "$SANDBOX/ufw.state"; }
clean_dropin() { rm -f "$ssh_dropin" "$ssh_dropin.failed"; }

#------------------------------ 用例 ------------------------------#

echo "=== 用例 1：Key 模式第 5 项 —— 校验通过应写入并应用 ==="
clean_dropin
mkdir -p "$WORK/home/alex/.ssh"
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEY alex@test\n' > "$WORK/home/alex/.ssh/authorized_keys"
out=$(run_engine 'alex\ny\ny\n' --mode key --step 5); rc=$?
[ "${IT_DEBUG:-0}" = "1" ] && { echo "--- 引擎输出 ---"; printf '%s\n' "$out"; echo "--- 结束 ---"; }
chk "退出码 0" 0 "$rc"
chk "写入了 PermitRootLogin no" 0 "$(has "$(cat "$ssh_dropin" 2>/dev/null)" 'PermitRootLogin no')"
chk "关闭了密码认证" 0 "$(has "$(cat "$ssh_dropin" 2>/dev/null)" 'PasswordAuthentication no')"
chk "限制 AllowUsers alex" 0 "$(has "$(cat "$ssh_dropin" 2>/dev/null)" 'AllowUsers alex')"
chk "提示已应用" 0 "$(has "$out" '配置已应用')"
chk "配置保留（未误撤）" 0 "$([ -f "$ssh_dropin" ] && echo 0 || echo 1)"

echo "=== 用例 2：Key 模式 —— 生效值不符应中止并撤下配置 ==="
clean_dropin
out=$(SSHD_STUB_DROP=permitrootlogin run_engine 'alex\ny\ny\n' --mode key --step 5); rc=$?
chk "退出码非 0" 1 "$([ "$rc" = 0 ] && echo 0 || echo 1)"
chk "提示已中止" 0 "$(has "$out" '已中止')"
chk "drop-in 已撤下" 0 "$([ -f "$ssh_dropin" ] && echo 1 || echo 0)"
chk "留下 .failed 供排查" 0 "$([ -f "$ssh_dropin.failed" ] && echo 0 || echo 1)"

echo "=== 用例 3：密码模式第 5 项 —— 必须保留密码认证 ==="
clean_dropin
out=$(run_engine 'alex\ny\ny\n' --mode password --step 5); rc=$?
chk "退出码 0" 0 "$rc"
chk "保留 PasswordAuthentication yes" 0 "$(has "$(cat "$ssh_dropin" 2>/dev/null)" 'PasswordAuthentication yes')"
chk "加入 MaxAuthTries 3" 0 "$(has "$(cat "$ssh_dropin" 2>/dev/null)" 'MaxAuthTries 3')"
chk "仍关闭 root 登录" 0 "$(has "$(cat "$ssh_dropin" 2>/dev/null)" 'PermitRootLogin no')"

echo "=== 用例 4：密码模式 —— 密码被锁定必须拒绝继续 ==="
clean_dropin
out=$(PASSWD_LOCKED=1 run_engine 'alex\ny\n' --mode password --step 5)
chk "提示没有可用密码" 0 "$(has "$out" '没有可用密码')"
chk "未写入配置" 0 "$([ -f "$ssh_dropin" ] && echo 1 || echo 0)"

echo "=== 用例 5：第 6 项 —— 必须先放行 SSH 再 enable ==="
reset_calls
out=$(run_engine '' --step 6); rc=$?
calls=$(cat "$SANDBOX/calls.log" 2>/dev/null)
chk "退出码 0" 0 "$rc"
chk "调用了 ufw allow 22/tcp" 0 "$(has "$calls" 'ufw allow 22/tcp')"
chk "调用了 ufw --force enable" 0 "$(has "$calls" 'ufw --force enable')"
al=$(printf '%s\n' "$calls" | grep -n 'ufw allow 22/tcp' | head -n1 | cut -d: -f1)
el=$(printf '%s\n' "$calls" | grep -n 'ufw --force enable' | head -n1 | cut -d: -f1)
chk "allow 在 enable 之前" 0 "$([ -n "$al" ] && [ -n "$el" ] && [ "$al" -lt "$el" ] && echo 0 || echo 1)"

echo "=== 用例 6：第 6 项 —— 放行规则没生效时禁止 enable ==="
reset_calls
out=$(UFW_NO_SHOW=1 run_engine '' --step 6)
calls=$(cat "$SANDBOX/calls.log" 2>/dev/null)
chk "提示已中止" 0 "$(has "$out" '已中止')"
chk "没有执行 enable" 1 "$(has "$calls" 'ufw --force enable')"

echo "=== 用例 7：第 6 项 —— 端口未知时必须中止（不能猜 22）==="
reset_calls
# 让 sshd -T 无输出、配置里也没有 Port、ss 不显示监听、且没有 SSH_CONNECTION
cp "$ssh_main" "$SANDBOX/ssh_main.keep"
grep -v '^Port ' "$SANDBOX/ssh_main.keep" > "$ssh_main"
out=$(SSHD_STUB_EMPTY=1 SS_NO_LISTEN=1 run_engine '' --step 6)
cp "$SANDBOX/ssh_main.keep" "$ssh_main"
calls=$(cat "$SANDBOX/calls.log" 2>/dev/null)
chk "提示无法确定端口" 0 "$(has "$out" '无法确定 SSH 端口')"
chk "没有放行任何端口" 1 "$(has "$calls" 'ufw allow')"
chk "没有 enable" 1 "$(has "$calls" 'ufw --force enable')"

echo "=== 用例 8：root 不能作为目标用户 ==="
clean_dropin
out=$(run_engine 'root\n' --mode key --step 5)
chk "拒绝 root" 0 "$(has "$out" '不允许对 root')"
chk "未写入配置" 0 "$([ -f "$ssh_dropin" ] && echo 1 || echo 0)"

echo
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" = "0" ]
