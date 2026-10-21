# fssh - 用 Touch ID 或 OTP 解锁的 macOS SSH 密钥管理器

[English](README.md)

![Touch ID 验证](images/finger.png)

## 这是什么？

fssh 把 SSH 私钥加密保存，并作为你的 SSH Agent 工作。不再需要明文私钥文件或反复输入私钥密码：每次签名用 Touch ID（或 macOS 登录密码）解锁，或者用「密码 + 验证器验证码」解锁（OTP 模式）。

- **磁盘上不留明文私钥**：私钥用 AES-256-GCM 加密；`fssh keygen` 生成的新密钥从不以明文落盘
- **知道是谁在请求**：解锁弹窗写明哪个程序、要用哪把密钥、登录哪台服务器；通过 `ssh -A` 转发来的请求会醒目提示
- **每台主机用对的密钥**：`fssh bind github.com work` 让主机只使用指定密钥
- **交互式 Shell**：浏览、搜索、连接 `~/.ssh/config` 中的主机，支持 Tab 补全
- **自查**：`fssh doctor` 找出配置问题并给出修复命令

```
┌─────────────┐     ┌──────────────────────┐     ┌──────────────┐
│ ssh / git   │ ──▶ │ fssh agent           │ ──▶ │   远程服务器   │
└─────────────┘     │ Touch ID / OTP 验证  │     └──────────────┘
                    │ 解密一把私钥并签名   │
                    └──────────────────────┘
```

**交互式 Shell：**

![交互式 Shell](images/shell.png)

---

## 安装

支持 Apple Silicon 和 Intel 的 macOS。

**Homebrew**（从源码编译）：

```bash
brew tap Mister-leo/fssh
brew install fssh
```

**安装脚本**（下载 Release 二进制，校验 sha256 并解除下载隔离）：

```bash
curl -fsSL https://raw.githubusercontent.com/Mister-leo/fssh/main/contrib/install.sh | sh
```

**从源码编译**（Go 1.21+，需要 Xcode 命令行工具）：

```bash
go build -o fssh ./cmd/fssh
sudo install -m 755 fssh /usr/local/bin/fssh
```

Release 二进制没有 Apple 签名。Homebrew 和安装脚本不会被 Gatekeeper 拦截；手动下载时请先执行 `xattr -d com.apple.quarantine fssh`。

## 快速开始

```bash
fssh init      # 设置向导
fssh doctor    # 检查是否全部接好
ssh my-server  # 会弹出 Touch ID / OTP 验证
```

向导依次完成：

1. **认证方式**：Touch ID（推荐；没有可用传感器的 Mac 会改为询问 macOS 登录密码）或 OTP
2. **安装** fssh 到 `/usr/local/bin`（Homebrew 安装时跳过）
3. **导入密钥**：从 `~/.ssh` 导入，并把明文原文件归档到 `~/.ssh/fssh-archive/`（也可删除或保留）
4. **开机自启**：配置 LaunchAgent
5. **启动** agent
6. **配置 ssh**：在 `~/.ssh/config` 开头加入一个带标记的配置块，让所有主机使用 fssh agent
7. **Shell 环境变量**（可选）：设置 `SSH_AUTH_SOCK`，供 `ssh-add` 和不读取 `~/.ssh/config` 的工具使用

再次运行 `fssh init` 时，可以选择保留当前配置、切换认证模式（保留所有密钥）或全部重来。

## 日常使用

### 解锁

照常使用 `ssh`、`git`、`scp`。验证一次后，agent 会在 `unlock_ttl_seconds`（默认 600 秒）内复用这次解锁，所以连续连接或用 Ansible 连 50 台机器也只需验证一次。设为 `0` 表示每次签名都验证。

弹窗会说明是谁在请求，例如「git → ssh 请求使用密钥 work 登录 github.com」。通过 `ssh -A` 转发来的请求会醒目标注，并且**每次都要确认**，不使用缓存；配置 `"forwarded_sign": "deny"` 可以直接拒绝。用 `fssh log` 查看最近的签名请求。

### 多把密钥

不绑定时，ssh 会把 agent 中所有密钥逐一提供给每台服务器：可能用错 GitHub 账号推送，密钥多于 6 把左右时服务器还会直接拒绝（`Too many authentication failures`）。把主机绑定到密钥：

```bash
fssh bind github.com work        # 写入 IdentityFile ~/.fssh/pubkeys/work.pub 和 IdentitiesOnly yes
fssh bind gitlab.com personal
fssh list                        # 查看每把密钥绑定了哪些主机
fssh unbind gitlab.com
```

### 新建密钥

```bash
fssh keygen deploy                  # 默认 ed25519；可选 --type ecdsa|rsa、--bits 4096
fssh pubkey deploy --copy           # 公钥复制到剪贴板
```

### 交互式 Shell

运行 `fssh`（或 `fssh shell`）：

```
fssh> list                       # 所有主机（读取 Include，合并别名）
fssh> list -r                    # 显示解析出的 IP（代理的 fake-ip 地址会被隐藏）
fssh> search prod
fssh> web1                       # 按名称、别名、编号、主机名或 IP 直接连接
fssh> connect me@10.0.0.9 -p 2222   # 任何 ssh 接受的参数
fssh> show web1                  # 详情，包括绑定的 fssh 密钥
fssh> add / edit web1 / delete web1
fssh> global show                # Host * 配置块
```

`edit` 会保留它不管理的所有选项（LocalForward、SetEnv、注释、额外别名）。`Include` 进来的主机可以查看，但不会被修改。

## 命令一览

| 命令 | 说明 |
|---|---|
| `fssh init` | 设置向导（`--mode touchid\|otp` 非交互初始化，`--force` 全部重来） |
| `fssh import --alias 名 --file 路径` | 导入私钥，按需询问私钥密码；`--original archive\|delete\|keep` 处理原文件 |
| `fssh keygen 名` | 生成新密钥并直接加密保存 |
| `fssh list [--json]` | 列出密钥：类型、指纹、绑定的主机 |
| `fssh pubkey 名 [--copy]` | 输出公钥 |
| `fssh bind 主机 名` / `fssh unbind 主机` | 让主机只使用指定密钥 |
| `fssh export --alias 名 --out 文件` | 导出为 OpenSSH 格式（`--ask-passphrase` 加密；`--format pkcs8` 导出未加密 PKCS#8） |
| `fssh remove --alias 名` | 删除密钥（会确认；脚本中用 `--yes`） |
| `fssh backup [--out 文件]` / `fssh restore 文件` | 把所有密钥备份到加密文件，可在其他 Mac 或其他认证模式下恢复 |
| `fssh rekey` | 更换主密钥（原子地重新加密所有密钥） |
| `fssh mode switch touchid\|otp` | 切换认证模式，保留所有密钥 |
| `fssh status` | 总览：模式、密钥、agent、开机自启、ssh 配置 |
| `fssh doctor` | 检查问题并给出修复命令 |
| `fssh agent` | 在前台运行 agent |
| `fssh log [-n 条数]` | 最近的签名请求（谁、哪把密钥、哪台主机、结果） |
| `fssh otp recover\|change-password\|regen-recovery\|show-secret` | OTP 维护 |
| `fssh shell` | 交互式主机管理（不带参数运行时的默认命令） |
| `fssh uninstall [--purge]` | 从 ssh 配置、开机自启和 shell 配置中移除 fssh |
| `fssh help [命令]`、`fssh version` | 帮助与版本 |

## 配置

`~/.fssh/config.json`（所有字段都可省略）：

```json
{
  "socket": "~/.fssh/agent.sock",
  "require_touch_id_per_sign": true,
  "unlock_ttl_seconds": 600,
  "forwarded_sign": "prompt",
  "language": "",
  "log_level": "info",
  "log_format": "plain"
}
```

| 字段 | 默认值 | 含义 |
|---|---|---|
| `require_touch_id_per_sign` | `true` | `false` 为便捷模式：agent 启动时解密全部密钥，之后不再验证 |
| `unlock_ttl_seconds` | `600` | 一次解锁的复用时间；`0` 表示每次签名都验证 |
| `forwarded_sign` | `prompt` | `ssh -A` 转发来的请求：`prompt`（每次确认）或 `deny`（拒绝） |
| `language` | 跟随系统 | `zh` 或 `en`；也可用环境变量 `FSSH_LANG`，其次是 `LANG`，最后是 macOS 系统语言 |

## 认证模式

### Touch ID（推荐）

随机生成的 32 字节主密钥存放在 macOS 钥匙串中，fssh 在使用前先弹出 Touch ID 验证。没有可用传感器（没有 Touch ID、未录入指纹或合盖使用）时，改为询问 macOS 登录密码。

### OTP

适合更习惯「密码 + 验证器验证码」的用户：

```bash
fssh init --mode otp
```

设置密码（至少 12 位）、把密钥添加到验证器 App（安装了 `qrencode` 会显示二维码），并输入一次验证码确认后才会保存。同时会得到 10 个一次性**恢复码**。

- 忘记密码：`fssh otp recover`（消耗一个恢复码）
- 换手机：`fssh otp show-secret`
- 改密码 / 重新生成恢复码：`fssh otp change-password`、`fssh otp regen-recovery`
- agent 在后台运行时，密码和验证码通过 macOS 系统弹窗输入。
- 每个验证码只能使用一次，刚用过的话请等下一个。

**安全边界：** OTP 密钥保存在这台 Mac 上，用你的密码加密。同时拿到密码和 `~/.fssh` 副本的人，不需要验证器就能推出主密钥。验证码能阻止「只知道密码」的人在这台 Mac 上使用 fssh，但它不是硬件级的第二因素。请开启 FileVault。

### 切换模式

```bash
fssh mode switch otp       # 或 touchid
```

所有密钥会先针对新模式重新加密并校验，确认无误后才切换；切换到 OTP 时需要先输入一次验证码。

## Agent 行为

| ssh-add | fssh agent |
|---|---|
| `ssh-add -l` | 列出已导入的密钥 |
| `ssh-add -x` / `-X` | 锁定 / 解锁 agent（锁定期间不列出、不签名） |
| `ssh-add -D` | 会显示「All identities removed」，但密钥**不会**被删除（它们保存在 fssh 的加密存储中）；实际效果是清除解锁缓存，下次签名重新验证 |
| `ssh-add <文件>` | 拒绝，请使用 `fssh import` |

## 备份、换机、卸载

```bash
fssh backup                         # 生成 ~/fssh-backup-<时间>.fsshbak，由单独的备份密码保护
fssh restore fssh-backup-....fsshbak   # 在新 Mac 上 fssh init 之后执行
fssh uninstall                      # 保留 ~/.fssh；--purge 同时删除密钥和主密钥
```

## 从旧版本升级

- **OTP 用户：** 旧版本显示的 TOTP 密钥格式无法被验证器 App 使用。请运行 `fssh otp show-secret` 重新添加。旧恢复码无法找回任何东西，请运行 `fssh otp regen-recovery`。
- **OTP 用户：** 旧版本还会把主密钥存进钥匙串，导致可以绕过 OTP。下次通过 OTP 解锁后会自动移除。
- 每次升级后，macOS 可能再次询问是否允许 fssh 使用钥匙串，点击「始终允许」即可。
- 运行一次 `fssh doctor`：它还会为旧版本导入的密钥补齐 `fssh bind` 需要的公钥文件。

## 常见问题

先运行 `fssh doctor`。常见情况：

- **ssh 没有弹出 Touch ID / OTP**：agent 没在运行，或 ssh 没有配置使用它。`fssh doctor` 会给出具体修复命令。
- **ssh 要求输入私钥文件的密码**：agent 拒绝了请求（已锁定、被取消或没在运行），ssh 退回使用 `~/.ssh` 里的明文私钥。请归档已导入的原文件：`fssh import ... --original archive`，或按 `fssh doctor` 的提示处理。
- **「Too many authentication failures」**：提供的密钥太多，请绑定主机：`fssh bind <主机> <别名>`。
- **「incorrect signature type」/「no mutual signature supported」**：服务器的 RSA 配置较旧，`fssh sshd-align --host <服务器>` 可开启 RSA-SHA2。
- **OTP 验证码被拒绝**：检查手机时间；每个验证码只能用一次。
- **agent 日志**：`~/Library/Logs/fssh/agent.log`。

## 安全说明

- 私钥用 AES-256-GCM 加密，每把私钥用 HKDF-SHA256 派生独立密钥，指纹作为附加认证数据。
- Touch ID 模式：主密钥在钥匙串中；Touch ID 检查由 fssh 执行（应用层检查，不是钥匙串的访问控制标志）。
- 便捷模式会把解密后的私钥一直保存在 agent 内存中，直到 agent 退出。
- 开启 agent 转发时，连接期间远程主机可以使用你的密钥；fssh 会对每次转发请求单独确认。
- 建议开启 FileVault。

## 开发

```bash
go build ./cmd/fssh
go test -race ./...
```

访问钥匙串的测试默认不运行（需设置 `FSSH_KEYCHAIN_TESTS=1`），并使用隔离的条目名称（`FSSH_KEYCHAIN_SERVICE`）。调用钥匙串时不要把 `HOME` 指向临时目录：macOS 会在 `$HOME` 下寻找登录钥匙串，找不到时会弹出「Keychain Not Found」对话框。

## 致谢

本项目由 TRAE AI 软件辅助生成。
