# 新 VPS 基础安全一键加固脚本（跨发行版 / 双模式）

面向准备部署 **3X-UI / VLESS Reality / Hysteria2 / Trojan** 的节点 VPS，把"新机器到手后的基础安全底座"做成可重复执行的一键流程：**退路 → 身份 → 边界 → 入口 → 备份**。

- 支持 **两套登录模式**：SSH Key 模式（关闭密码认证）与 密码登录模式（保留密码）
- 支持 **主流 Linux 发行版与 BSD**，按平台自动适配包管理器 / init / 防火墙 / sshd 配置布局
- 每个会"锁死自己"的步骤都有**闸门**：先验证新通道、再关闭旧通道；校验不通过就中止并撤下未生效的配置

## 支持的平台

| 家族 | 发行版示例 | 包管理器 | 服务管理 | 防火墙（自动） | 自动安全更新 |
|---|---|---|---|---|---|
| Debian 系 | Debian / **Ubuntu** / Mint / Kali / Raspbian / Devuan | apt | systemd / sysv | ufw | unattended-upgrades ✅ |
| RHEL 系 | RHEL / CentOS / Rocky / AlmaLinux / Fedora / Amazon Linux | dnf / yum | systemd | firewalld | dnf-automatic / yum-cron ✅ |
| SUSE 系 | openSUSE Leap / Tumbleweed / SLES | zypper | systemd | firewalld | zypper patch（timer/cron）✅ |
| Arch 系 | Arch / Manjaro / EndeavourOS / CachyOS | pacman | systemd | ufw / firewalld | ⚠️ 无官方无人值守，给出手工方案 |
| Alpine | Alpine / postmarketOS | apk | OpenRC | ufw（community） | apk + /etc/periodic ✅ |
| Gentoo / Void | Gentoo / Funtoo / Void | emerge / xbps | OpenRC / runit | 视已装工具 | ⚠️ 给出手工方案 |
| BSD | FreeBSD / OpenBSD / NetBSD / DragonFly | pkg / pkg_add | rc.d | ⚠️ pf 需手工配置（脚本给指引） | ⚠️ freebsd-update cron 指引 |

> 未在真机逐发行版实测：Ubuntu/Debian 路径是主要开发目标，其它平台按各自机制实现并做了能力检测；遇到不支持的项会打印手工命令并跳过，而不是假装成功。
> 不支持的平台（如 macOS）：明确告警后按通用方式尽力执行。

## 两种模式

| 模式 | 命令 | 登录方式 | 第 5 项写入的认证策略 |
|---|---|---|---|
| **SSH Key 模式**（默认，推荐） | `--mode key` / `--key` | 公钥登录 | `PasswordAuthentication no`（关闭密码认证） |
| **密码登录模式** | `--mode password` / `--no-key` | 用户名 + 密码 | `PasswordAuthentication yes` + `MaxAuthTries 3` + `LoginGraceTime 60` |

密码模式额外提供：自动生成 32 位随机密码、可选 Fail2ban `ignoreip` 白名单、可选把 SSH 限制为固定管理 IP（含 10 分钟自动回滚）。

## 文件说明

| 文件 | 说明 |
|---|---|
| `install.sh` | 一键安装：把主脚本、封装、平台适配层装到 `/usr/local/bin` 与 `/usr/local/lib/vps-hardening/` |
| `vps-hardening.sh` | **主引擎**：所有加固逻辑 + 平台适配调用，支持 `--mode key\|password` |
| `vps-hardening-no-key.sh` | 薄封装：找到主引擎后以 `--mode password` 执行（两种模式共用同一套逻辑，不会走样） |
| `lib/platform.sh` | **跨发行版适配层**：发行版/包管理器/init/防火墙/sshd/自动更新 的检测与抽象 |
| `tests/selftest.sh` | 自检/回归测试：`bash tests/selftest.sh`（不联网、不改动系统，124 项检查） |
| `LICENSE` | MIT |
| `.gitattributes` / `.gitignore` | 强制 `*.sh` 用 LF；排除 `node_modules` 等 |

## 一键安装

```bash
# 方式一：先下载、看一眼内容再执行（更安全）
curl -fsSLO https://raw.githubusercontent.com/strivewu0813/vps-security-hardening/main/install.sh
sudo bash install.sh                 # 安装并运行 SSH Key 模式
sudo bash install.sh --no-key        # 安装并运行 密码登录模式
sudo bash install.sh --install-only  # 只安装，不立即运行

# 方式二：一行直通（管道方式会自动把交互输入切到 /dev/tty）
curl -fsSL https://raw.githubusercontent.com/strivewu0813/vps-security-hardening/main/install.sh | sudo bash
curl -fsSL https://raw.githubusercontent.com/strivewu0813/vps-security-hardening/main/install.sh | sudo bash -s -- --no-key
```

安装后：

```bash
sudo /usr/local/bin/vps-hardening                  # SSH Key 模式
sudo /usr/local/bin/vps-hardening-no-key           # 密码登录模式
sudo /usr/local/bin/vps-hardening --step 5         # 只重跑某一项（2~10）
sudo /usr/local/bin/vps-hardening --setup-only     # 只做平台检测，不改动系统
```

`install.sh` 参数：`--key` / `--no-key`、`--install-only`、`--auto`、`--step N`、`--fail2ban`（透传）、`--ref REF`、`--mirror URL`、`--dir DIR`、`-h`。
下载源默认回退 `raw.githubusercontent.com` → `cdn.jsdelivr.net`；若当前目录已有仓库文件（本地克隆）则直接用本地文件、不联网。

## 直接运行

```bash
sudo bash vps-hardening.sh                     # 交互式菜单
sudo bash vps-hardening.sh --auto              # 顺序执行第 2~8 项（逐步确认）
sudo bash vps-hardening.sh --step 8            # 只执行某项
sudo bash vps-hardening-no-key.sh              # 密码登录模式（自动找到主引擎）
```

> 主脚本需要 `lib/platform.sh`。若同目录没有，它会先尝试下载到 `/usr/local/lib/vps-hardening/`；完全离线时请把 `lib/` 与脚本放在一起。

## 十项流程

| 菜单 | 内容 | 自动化程度 |
|---|---|---|
| 0 / 1 | 平台预检 + Console / MFA / 快照清单 | 预检自动；厂商后台部分**必须手动** |
| 2 | 更新系统补丁 + 配置自动安全更新 | 按发行版自动；无机制的平台给出命令 |
| 3 | 创建普通管理员（自动装 sudo、写 `sudoers.d`、加入 wheel/sudo 组） | ✅ |
| 4 | 登录通道：安装 SSH 公钥 / 设置强密码并**要求新窗口验证** | ✅（公钥粘贴 / 密码生成） |
| 5 | SSH 加固：关闭 root 登录（Key 模式再关闭密码认证） | ✅（语法 + 生效值双校验） |
| 6 | 防火墙：只开放必要端口（ufw / firewalld / iptables 自动；pf 给指引） | 大部分 ✅ |
| 7 | 监听端口与运行服务检查 | 只读报告 |
| 8 | Fail2ban（按 init 自动选 backend，systemd 用 journald，其它用日志） | ✅ |
| 9 | 3X-UI 面板入口核对 + 可选面板 IP 白名单 | 检查项手动核对 |
| 10 | 3X-UI SQLite 数据库一致备份（多 init 兼容） | ✅ |

## 安全设计（重要）

1. **拒绝 root 作为目标用户**：否则会写出 `PermitRootLogin no` + `AllowUsers root`，导致**所有** SSH 登录被拒。
2. **先验证再关闭**：第 4 项强制"第二个终端窗口验证通过"才能进第 5 项（Key 模式查 `authorized_keys`，密码模式查 `passwd -S`/shadow 状态 + 登录 shell 是否可用）。
3. **双校验后重启**：第 5 项先 `sshd -t` 语法检查，再核对生效值（`PermitRootLogin no`、认证方式、`AllowUsers` 含该用户、`MaxAuthTries`）。老版本 OpenSSH 不支持 `sshd -T` 时降级为校验我们写入的配置并明确告警；配置关键字随版本自动切换（`KbdInteractiveAuthentication` / `ChallengeResponseAuthentication`）。
4. **中止即撤下**：任何校验失败、取消应用、或重启后端口未监听，都会撤下刚写入的配置（drop-in 改名 `*.failed`；直改模式从 `sshd_config.vps-hardening.bak` 恢复）。
5. **ssh 配置布局自适应**：优先用 `sshd_config.d/00-vps-hardening.conf`（首值生效）；若主配置没有 `Include` 且目录里已有别人的 drop-in，会**先征求确认**（注入 Include 会改变那些文件的优先级），否则退回"直改主配置 + 标记块"模式（幂等、可恢复）。
6. **防火墙顺序**：先放行 SSH 并确认规则存在，再设置默认拒绝入站并启用；启用后再次校验规则与"确实处于活动状态"，否则明确报错（避免"以为开了其实没开"）。
7. **端口覆盖完整**：同时考虑 `sshd -T`、`ssh.socket`/`sshd.socket` 的监听端口、BSD 配置里的 `Port`，以及**当前会话的服务端端口**。
8. **不硬改全局 nftables**：检测到只有 nftables 时改为给出精确的手工命令 —— 直接整表 `flush` 会清掉 Docker 等程序写的规则。iptables 后端会提示与 Docker 的兼容性。
9. **用户上下文防串号**：用户名记录在 root 专属 `/root/.vps-hardening-ctx`（0600），复用时先显示并确认。
10. **不支持的项如实降级**：打印手工命令并跳过，绝不伪装成功。

## 自检 / 回归测试

改动脚本后建议先跑一遍（纯 bash，不需要联网，也不会改动系统）：

```bash
bash tests/selftest.sh          # 在仓库根目录执行
```

它会检查：四个脚本的语法、适配层函数是否齐全（曾经漏掉 `confirm` 导致所有确认都变成"否"）、`confirm`/`confirm_timed` 在 y / n / EOF 下的行为、IPv4/IPv6 校验、**发行版家族映射**（ubuntu/debian/rocky/fedora/amzn/ol/opensuse/arch/manjaro/alpine/gentoo/void/freebsd/openbsd/darwin/solus/mageia）、各家族包管理器命令与 init 抽象是否齐备、引擎参数处理（`--step`/`--auto` 互斥、非法值）、封装脚本的模式保护。

## 卡住 / 没有输出怎么办

脚本已对可能长时间等待的环节加了超时与进度标记（预检 `[1/5]`~`[5/5]`、`confirm_timed` 无输入按默认继续、`ipinfo.io` 最多 8 秒、`ss`/`netstat`/`sshd -T` 用 `timeout` 包裹）。

```bash
# 1) DEBUG 模式重跑，直接看到卡在哪条命令（最有用）
sudo DEBUG=1 bash /usr/local/bin/vps-hardening 2>&1 | tee /tmp/hardening-debug.log
tail -n 20 /tmp/hardening-debug.log      # 卡住时在另一个窗口看

# 2) 确认脚本进程在跑，以及它卡在哪个系统调用
pgrep -af 'vps-hardening' || echo "进程不存在（已退出）"
pid=$(pgrep -f 'vps-hardening' | head -n1); [ -n "$pid" ] && [ -r /proc/$pid/wchan ] && cat /proc/$pid/wchan; echo

# 3) 确认标准输入是不是终端
[ -t 0 ] && echo "stdin 是终端" || echo "stdin 不是终端：请用 install.sh 或先下载再执行"
```

| 现象 | 原因 | 处理 |
|---|---|---|
| 完全没有输出 | `curl \| bash` 时 GitHub 被墙，脚本还没下载下来 | 用 `install.sh`（自动回退 jsDelivr）、加 `--mirror`，或先下载再执行 |
| 停在 `? ... [y/N]` | 提示在等输入（新版 15 秒无输入按默认处理） | 输入 `y` 回车；或升级到最新版 |
| 停在 `[INFO] 公网 IP / 地区 / ASN` | `ipinfo.io` 被墙 | 新版最多 8 秒自动跳过 |
| 菜单"请选择"后无反应 | stdin 不是终端（管道执行），输入被丢弃 | 改用 `sudo /usr/local/bin/vps-hardening` |
| 敲 `y` 屏幕没反应 | 厂商 VNC Console 对无换行提示符渲染异常 | 新版提示符独占一行；建议改用 SSH |

## 完整手动清单（菜单 `r` 也会显示）

- 退路：厂商账户 MFA、恢复码、Console 实测、快照/云防火墙入口
- 身份：普通管理员、**新窗口验证**、root SSH 登录关闭、认证方式符合预期、`AllowUsers` 正确
- 边界：防火墙已启用、SSH 端口放行（或限 IP）、未提前开放无关端口、IPv6 与云防火墙、监听服务确认
- 入口：3X-UI 独立账号 + 强密码 + 随机路径 + HTTPS + 2FA（+ 可选 IP 白名单）
- 备份：x-ui 数据库备份并保存到 VPS 之外；基础加固完成后打厂商 Snapshot

## 日志

所有操作写入 `/var/log/vps-hardening.log`。

## 免责声明

脚本会修改 SSH、防火墙与软件包配置。请先确认厂商 Console / 快照可用，并在**保留当前会话**的前提下用**新窗口**验证每一步；因误操作导致的失联或数据丢失，作者不承担责任。

## License

[MIT](LICENSE) © 2026 strivewu0813
