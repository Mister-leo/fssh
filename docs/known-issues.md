# fssh 已知问题清单

> 创建日期：2026-10-21
> 来源：产品评审（代码走查 + CI 构建验证）
> 状态标记：`[ ]` 待修复 · `[x]` 已修复
> 修复方案：[fix-plan.md](fix-plan.md)

## P0：核心承诺未兑现 / 安全漏洞

- [x] **P0-1 Touch ID 模式 TTL 缓存不生效**
  - 现象：`unlock_ttl_seconds` 在 Touch ID 模式下被忽略，每次签名都弹指纹；`git pull`、scp 循环、Ansible 批量连接会连续弹框
  - 位置：`internal/auth/touchid.go:21`（`TouchIDProvider` 无缓存，`GetAuthProvider` 传入的 TTL 未使用）

- [x] **P0-2 配置文件无法关闭 `require_touch_id_per_sign`**
  - 现象：`config.json` 中设为 `false` 会被强制改回 `true`，只能用命令行参数开启便捷模式
  - 位置：`internal/config/config.go:56`

- [ ] **P0-3 OTP 模式的双因素可被绕过**
  - 现象：OTP 初始化时 master key 也写入 Keychain；`import`/`export`/`remove`/`rekey` 走 Keychain 路径，在无 Touch ID 的 Mac 上回退为系统登录密码，只凭开机密码即可 `fssh export` 导出明文私钥
  - 位置：`cmd/fssh/otp_init.go:58`，`cmd/fssh/main.go`（各命令直接调用 `keychain.LoadMasterKey()`）

- [ ] **P0-4 OTP 模式与 LaunchAgent 自启冲突**
  - 现象：Agent 从自身 stdin 读取密码/验证码；launchd 启动时无 TTY，`preUnlockOTP` 失败退出，`KeepAlive` 导致反复重启。前台运行时验证码也只能在 Agent 终端输入，而非用户执行 ssh 的终端
  - 位置：`internal/agent/server.go:42`、`internal/otp/prompt.go`

- [ ] **P0-5 OTP 预解锁缓存未共享**
  - 现象：`preUnlockOTP` 使用临时 provider，安全 Agent 又创建新 provider，启动时输入的密码/验证码白输，首次 ssh 仍需重新输入
  - 位置：`internal/agent/server.go:113`、`internal/agent/server.go:58`

- [ ] **P0-6 OTP 模式下 `rekey` 导致全部密钥不可用**
  - 现象：`rekey` 用随机新 key 重新加密所有密钥并写入 Keychain，但 OTP Agent 从 seed 派生 master key，两者不一致，之后签名全部失败
  - 位置：`cmd/fssh/main.go:247`

- [ ] **P0-7 恢复码只生成不可用**
  - 现象：`VerifyRecoveryCode` 无任何调用方，没有使用恢复码重置密码的命令；README 承诺“可以用恢复码重置”
  - 位置：`internal/otp/recovery.go:67`

- [ ] **P0-8 认证弹窗不显示请求来源**
  - 现象：提示语固定，不显示密钥别名、目标主机、请求进程；开启 `ssh -A` 转发时远端可触发签名，用户无法判断是否该授权
  - 位置：`internal/keychain/keychain.go:99`

## P1：关键流程与体验

- [ ] **P1-1 导入后明文私钥仍留在 `~/.ssh`**
  - 现象：不提示删除/归档原文件，也不引导 `IdentitiesOnly`；ssh 可能直接读取明文 `id_*` 绕过 fssh
  - 位置：`cmd/fssh/setup_keys.go`

- [ ] **P1-2 向导“重新初始化”无效；`--force` 后旧密钥成孤儿**
  - 现象：确认重新初始化后 `force` 未传递，`initTouchIDMode` 打印 "master key already exists" 直接返回；使用 `--force` 时旧 `.enc` 文件无法解密且无提示
  - 位置：`cmd/fssh/setup.go:114`、`cmd/fssh/otp_init.go`

- [ ] **P1-3 Touch ID 可用性检测是假的**
  - 现象：只判断 `runtime.GOOS == "darwin"`，Mac mini 也显示 “✓ Your Mac supports Touch ID!” 并默认选 Touch ID
  - 位置：`cmd/fssh/setup.go:128`

- [ ] **P1-4 Agent 协议操作“假成功”**
  - 现象：`ssh-add -x`（Lock）、`ssh-add -D`（RemoveAll）返回成功但无效果；`ssh-add` 添加密钥不支持
  - 位置：`internal/agent/secure_agent.go:227-232`

- [ ] **P1-5 备份/换机路径缺失**
  - 现象：导出使用已废弃的 `x509.EncryptPEMBlock`（RFC1423 旧式加密），兼容性存疑；无整库备份/迁移
  - 位置：`internal/store/store.go:170`

- [ ] **P1-6 向导引导矛盾**
  - 现象：已写入 `IdentityAgent` 仍以 “⚠️ IMPORTANT” 要求设置 `SSH_AUTH_SOCK`；欢迎页列 6 步，实际 Step x/8
  - 位置：`cmd/fssh/setup.go`

- [ ] **P1-7 交互式 Shell 可用性**
  - 不支持 `Include`，拆分配置的用户看到空列表
  - 启动时串行 DNS 解析所有主机，主机多或 VPN 断开时卡顿（`cmd/fssh/shell.go:374`）
  - 数字 ID 依赖列表顺序，增删后变化

- [ ] **P1-8 `fssh status` 信息过少**
  - 现象：不显示认证模式、Agent 是否运行、密钥数量、TTL
  - 位置：`cmd/fssh/main.go`（`cmdStatus`）

- [ ] **P1-9 细节问题**
  - 中英文混杂（向导英文，错误多为中文）
  - 8 位验证码仍提示“请输入6位验证码”（`internal/auth/otp.go:145`）
  - 错误提示引用不存在的 `fssh switch-to-otp`（`internal/auth/auth.go:53`）
  - 日志 `/tmp/fssh-agent.log`、`auth_mode.json` 权限 0644（`cmd/fssh/setup_launchd.go`、`internal/auth/auth.go:134`）

## P2：交付、增长与工程质量

- [ ] **P2-1 CI 发布构建失败**
  - 现象：`CGO_ENABLED=0` 时 `internal/macos` 被构建约束全部排除，构建报错；Release 无可用二进制（已本地复现）
  - 位置：`.github/workflows/build.yml:44`（且 runner 为 ubuntu，需改为 macOS + CGo）

- [ ] **P2-2 无 Homebrew、无签名/公证；二进制提交进仓库**
  - 未签名会被 Gatekeeper 拦截；Keychain ACL 绑定签名，升级后可能重复弹授权（待实测）
  - 仓库中提交了 7.8MB 的 `fssh` 二进制

- [ ] **P2-3 无任何测试**
  - crypt、TOTP、ssh config 写入等高风险模块无回归保障

- [ ] **P2-4 文档与实现不一致**
  - CLAUDE.md 称 OTP 用 scrypt，代码为 PBKDF2
  - README FAQ 编号重复（两个“4.”）
  - `rekey`、`config-gen`、`sshd-align` 及 Shell 的 `add`/`edit`/`delete`/`global` 未写入文档

## U：使用者视角（实际上手测试，2026-10-21）

> 在隔离 HOME 中编译运行验证；标注“实测”的为已复现，其余为按代码推演的使用场景。

- [ ] **U-1 多密钥时无法指定“哪台主机用哪把钥匙”**
  - 场景：同时导入 GitHub 个人/公司两把 key，`git push` 用 Agent 中第一把被接受的 key，推到错误账号；密钥 ≥6 把时服务器报 `Too many authentication failures`；所有公钥都会暴露给每一台服务器
  - 原因：Shell `add` 选“Use fssh agent”只写 `IdentityAgent`，不绑定具体 key（`cmd/fssh/shell_commands.go:119-135`）；没有导出 `.pub` 供 `IdentityFile` + `IdentitiesOnly` 使用

- [ ] **U-2 `fssh import` 同名 alias 静默覆盖**
  - 场景：误用已有别名导入，旧私钥被直接覆盖且无提示；若原文件已删除则永久丢失
  - 位置：`cmd/fssh/main.go`（`cmdImport` 未检查 `.enc` 是否存在）

- [ ] **U-3 导入加密私钥不会自动询问密码（实测）**
  - 现象：不加 `--ask-passphrase` 时直接报 `error: ssh: this private key is passphrase protected`；密码错误报 `x509: decryption password incorrect`，均为底层库原文
  - 期望：TTY 下检测到加密自动提示输入；错误信息人话化并给出下一步

- [ ] **U-4 没有帮助和版本信息（实测）**
  - 现象：`fssh help` / `--help` / `version` 都只输出一行 usage 且退出码 2；无子命令说明、无版本号，用户无法判断自己装的版本
  - 无参数运行直接进入 Shell，新用户不知道这是什么

- [ ] **U-5 Shell 不读 `Include`（实测）**
  - 现象：`Include conf.d/*` 中的主机不出现在 `list` 中

- [ ] **U-6 Shell 显示的 IP 在代理环境下是假的（实测）**
  - 现象：开启 Clash/Surge 等 fake-ip 代理时，不存在的域名被解析成 `198.18.x.x` 并显示为主机 IP，按 IP 搜索/连接也会错配
  - 位置：`cmd/fssh/shell.go:374`（`resolveIPName`）

- [ ] **U-7 Shell 同一 Host 的多个别名显示成多台主机（实测）**
  - 现象：`Host web1 web1-alias` 在列表中出现两行

- [ ] **U-8 Shell 连接能力受限**
  - 只能连 config 里已有的主机，不能 `connect user@1.2.3.4`，不能透传 `-L`/`-J` 等参数；ssh 退出码被忽略，连接失败无提示
  - 位置：`cmd/fssh/shell.go:217-225`

- [ ] **U-9 没有生成密钥、查看公钥的命令**
  - 新用户必须先用 `ssh-keygen` 生成明文私钥再导入；部署新服务器时无 `fssh pubkey <alias>` 复制公钥，需绕道 `ssh-add -L`
  - `fssh list` 输出为 `alias=... fingerprint=...` 机器格式，不显示密钥类型

- [ ] **U-10 认证失败时用户看不懂**
  - 取消指纹或 Agent 未运行时，ssh 只显示 `agent refused operation` / `Permission denied (publickey)`，没有任何指向 fssh 的提示；若 `~/.ssh` 还有明文 key，会静默回退使用它

- [ ] **U-11 无卸载/停用路径**
  - 向导改动了 `/usr/local/bin`、LaunchAgent、`~/.ssh/config`、Keychain，没有 `fssh uninstall`；只删二进制会导致 LaunchAgent 反复拉起失败

- [ ] **U-12 `remove` 先要求认证再检查是否存在**
  - 现象：输错别名也要先按指纹，按完才报 `no such file or directory`
  - 位置：`cmd/fssh/main.go:241`
