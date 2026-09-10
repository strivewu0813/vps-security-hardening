# 新 VPS 基础安全一键脚本（两个版本）

依据 Notion 教程《[VPS入门篇：新 VPS 入手后必须先做的 10 项安全设置](https://toothsome-package-7ce.notion.site/VPS-VPS-10-3b537d2f12398104b317ce58cfc9ac30)》（Ubuntu 24.04 LTS）整理的自动化加固脚本，面向准备部署 **3X-UI / VLESS Reality / Hysteria2 / Trojan** 的节点 VPS。

## 两个版本怎么选

| 版本 | 脚本 | 登录方式 | 适合谁 |
|---|---|---|---|
| **SSH Key 版**（推荐） | `vps-hardening.sh` | 公钥登录，关闭密码认证 | 愿意配置 SSH Key 的用户；安全性最高 |
| **无 Key / 密码版** | `vps-hardening-no-key.sh` | 保持"用户名 + 密码"登录 | 暂时不想配置 SSH Key、习惯密码登录的用户 |

密码版会用这些手段弥补没有 Key 的风险：自动生成 20 位随机密码、关闭 root 直接登录、`MaxAuthTries 3` + `LoginGraceTime 30`、`AllowUsers` 限定用户、Fail2ban 默认更严格（3 次/2 小时）、可选把 SSH 限制为固定管理 IP。

> 两个脚本共用操作日志 `/var/log/vps-hardening.log`，并会在第 5 项自动检测、备份另一个版本留下的 SSH 配置，避免互相覆盖。

## 快速开始

SSH Key 版：

```bash
sudo bash vps-hardening.sh              # 交互式菜单
sudo bash vps-hardening.sh --auto       # 顺序执行第 2~8 项（每步确认）
sudo bash vps-hardening.sh --step 8     # 只执行某项（N=2..10）
sudo bash vps-hardening.sh --fail2ban   # 只执行第 8 项 Fail2ban
```

无 Key / 密码版：

```bash
sudo bash vps-hardening-no-key.sh              # 交互式菜单
sudo bash vps-hardening-no-key.sh --auto       # 顺序执行第 2~8 项（每步确认）
sudo bash vps-hardening-no-key.sh --step 4     # 只重设密码/验证密码通道
sudo bash vps-hardening-no-key.sh --fail2ban   # 只执行第 8 项 Fail2ban
```

## 各项与教程对应关系

| 菜单 | 教程章节 | 内容 | Key 版 | 密码版 |
|---|---|---|:--:|:--:|
| 0 / 1 | 部署前 / 第 1 项 | 系统与身份预检 + Console / MFA / 快照提醒 | 预检自动，其余**必须服务商后台手动** | 同左（并额外显示密码相关生效值） |
| 2 | 第 2 项 | `apt` 更新、`unattended-upgrades` | ✅ | ✅ |
| 3 | 第 3 项 | 创建普通 sudo 管理用户 | ✅ | ✅ |
| 4 | 第 4 项 | **Key 版**：安装 SSH Key 并要求新窗口验证<br>**密码版**：设置强密码（可自动生成）+ `passwd -S` 校验 + 新窗口密码登录验证 | 公钥 | 密码 |
| 5 | 第 5 项 | SSH 加固：关闭 root 登录 | 并关闭密码认证 | 保留密码认证 + `MaxAuthTries 3` |
| 6 | 第 6 项 | UFW：先放行 SSH 再启用 | ✅ | ✅（可加 SSH 来源 IP 白名单） |
| 7 | 第 7 项 | 监听端口与运行服务只读报告 | ✅ | ✅ |
| 8 | 第 8 项 | Fail2ban（教程值 5/10m/1h） | ✅ | ✅（可选更严格 3/10m/2h） |
| 9 | 第 9 项 | 3X-UI 面板入口核对 + 可选面板 IP 白名单 | 已装 x-ui 时可用 | 同左 |
| 10 | 第 10 项 | `x-ui.db` 一致备份 + 提示下载离开 VPS | 已装 x-ui 时可用 | 同左 |
| a / r | — | 顺序执行第 2→8 项 / 最终检查清单 | ✅ | ✅ |

## 安全设计（重要）

1. **第 1 项不能自动完成**：厂商后台的 Console / MFA / 快照 / 云防火墙必须手动操作，脚本只提醒。
2. **先验证再关闭**（两个版本都强制）：
   - Key 版：第 4 项安装公钥后要求**第二个终端窗口**用 Key 登录成功；
   - 密码版：第 4 项设置密码后要求**第二个终端窗口**用"用户名+密码"登录成功；
   未验证前不得继续第 5 项（第 5 项会再次人工确认）。
3. **拒绝 root 作为目标用户**：第 3/4/5 项都会拦截 `root`，避免写出 `PermitRootLogin no` + `AllowUsers root` 这种组合（那会导致**所有** SSH 登录被拒绝）。
4. **安全闸门（不通过就中止，且不重启 SSH）**：
   - Key 版：`authorized_keys` 非空 + `sshd -t` + `sshd -T` 逐项核对（`permitrootlogin` / `passwordauthentication` / `kbdinteractiveauthentication` / `pubkeyauthentication` / `x11forwarding` / `AllowUsers`，AllowUsers 按词匹配、顺序无关）；
   - 密码版：`passwd -S` 必须是 `P`（`L`/`NP` 直接中止）+ 登录 shell 未被禁用 + 校验 `passwordauthentication yes`、`maxauthtries 3` 等。
5. **中止即撤下配置**：任何校验失败、你取消应用、或重启后端口未监听时，脚本都会把刚写入的 sshd 配置改名为 `*.failed`（sshd 不再读取），避免下一次 SSH 连接读到未验证的配置。
6. **端口覆盖完整**：同时考虑 `sshd -T` 与 `ssh.socket` 的 `ListenStream`（Ubuntu 24.04 socket 激活），并把**当前会话的服务端端口**一并放行，换端口场景也不会把自己挡在门外。
7. **UFW 顺序**：先放行 SSH 并用 `ufw show added` 确认加入，再 `enable`；启用后再次校验每个端口与 `Status: active`。
8. **Ubuntu 24.04 socket 激活已兼容**：`systemctl daemon-reload` → 只重启“已启用”的 `ssh.socket` / `ssh.service` → 用 `ss -ltn` 验证端口真的在监听。
9. **不会误操作其它用户**：第 3 项用户名记录在 root 专属文件 `/root/.vps-hardening-ctx`（0600），第 4/5 项复用时先显示并要求确认。
10. **两版配置不互相覆盖**：密码版发现 Key 版的 `00-vps-hardening.conf`（会按字典序优先生效）时会提示并备份为 `.bak`；改名失败会中止而不是假装成功。
11. **密码版专属**：
    - 随机密码先让你确认已保存、**然后**才真正设置（非交互终端会拒绝自动生成，避免密码只存在于被丢弃的输出里）；
    - 可选把常用 IP 写入 Fail2ban `ignoreip`，避免自己连错密码被封；
    - 可选把 SSH 限制为固定管理 IP：会先校验该 IP 与当前连接来源是否一致，添加白名单并**安排 10 分钟自动回滚**后才删除全局规则，校验残留时按 From 列判断（不会误报/误导你删掉最后一条放行规则）。
12. **不修改 SSH 端口**（与教程一致）；Docker 用户请自行检查容器端口发布（`docker ps` 的 PORTS 列）。
13. 其他发行版仅供参考思路，请以 Ubuntu 24.04 为准。

## 完整手动清单（脚本 `r` 选项也会显示）

- 退路：厂商账户 MFA、恢复码、Console 实测、快照/云防火墙入口
- 身份：sudo 用户、**新窗口验证**（Key 或密码）、root SSH 登录关闭、`AllowUsers` 正确
- 边界：UFW 开启、SSH 端口放行（或限 IP）、未提前开放无关端口、IPv6、云防火墙、监听服务确认
- 入口：3X-UI 独立账号 + 强密码 + 随机路径 + HTTPS + 2FA（+ 可选 IP 白名单）
- 备份：x-ui 数据库备份并保存到 VPS 之外；基础加固完成后打厂商 Snapshot
- 密码版追加：密码唯一且足够长、保存到密码管理器、Fail2ban 必须保持启用

## 操作日志

脚本会把每次操作写入 `/var/log/vps-hardening.log`。
