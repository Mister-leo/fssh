# fssh 修复方案

> 对应 [known-issues.md](known-issues.md)，编号保持一致
> 日期：2026-10-21
> 工作量：S（≤1 天）· M（2–4 天）· L（≥1 周），为粗略估计

## 一、公共基础改造

很多问题的根因相同，先做下面 5 项基础改造，后续逐项修复会简单很多。

### F1 统一解锁入口
- 所有命令（`import`/`export`/`remove`/`rekey`）改为通过 `auth.GetAuthProvider(ttl).UnlockMasterKey()` 解锁，禁止在 `cmd/` 中直接调用 `keychain.LoadMasterKey()`
- 新增 `auth.IsInitialized()`：按 `auth_mode.json` 判断（touchid → Keychain 有 key；otp → `config.enc` 存在），替换 `setup.go`、`cmdStatus` 中的 `keychain.MasterKeyExists()`
- 支撑：P0-3、P0-6、P1-2、P1-8

### F2 提示器抽象（Prompter）
```go
type Prompter interface {
    Password(msg string) (string, error)
    Code(msg string) (string, error)
    Confirm(msg string) (bool, error)
    Notify(title, msg string)
}
```
- `TTYPrompter`：CLI 使用，读 `/dev/tty`
- `GUIPrompter`：Agent 在后台（无 TTY）时使用，`osascript -e 'display dialog ... with hidden answer'` 输入，`display notification` 通知
- Agent 启动时按 `term.IsTerminal` 自动选择
- 支撑：P0-4、P0-8、U-10

### F3 每连接 Agent 包装 + 签名上下文
- `server.go` 为每个连接创建 `connAgent{shared *secureAgent, peer PeerInfo, bind *SessionBind}`，再交给 `xagent.ServeAgent`
- 请求方进程：`unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)` 取 PID（x/sys v0.29 已支持），再用 `sysctl kern.procargs2` 取进程名和命令行
- 目标主机与是否转发：实现 OpenSSH 8.9+ 的 `session-bind@openssh.com` 扩展（`ServeAgent` 会把扩展请求转给 `Extension()`），拿到服务器主机公钥和 `is_forwarding` 标志，再用 `~/.ssh/known_hosts` 反查主机名
- 支撑：P0-8、P1-4

### F4 ssh config 托管块 + 完整解析
- fssh 写入的所有内容统一包在 `# >>> fssh managed >>>` / `# <<< fssh managed <<<` 中，更新和卸载只改动标记内的内容
- 解析器支持 `Include`（glob，相对路径基于 `~/.ssh`），同一 `Host` 行的多个别名合并为一个条目
- 支撑：P1-6、P1-7、U-1、U-5、U-7、U-11

### F5 公钥文件导出
- 导入或生成密钥时写 `~/.fssh/pubkeys/<alias>.pub`，供 `IdentityFile` 引用
- 支撑：P1-1、U-1、U-9

## 二、里程碑

| 里程碑 | 目标 | 包含 |
|---|---|---|
| M1 能用 | 装得上、不烦人、看得懂 | P0-1、P0-2、P2-1、U-4、U-3、U-2、U-12、P1-9（小项） |
| M2 安全可信 | 兑现安全承诺 | F1、F2、F3；P0-3 ~ P0-8、P1-4 |
| M3 顺手 | 多密钥、Shell、排障 | F4、F5；U-1、P1-1、P1-7、U-5 ~ U-9、P1-8、U-10 |
| M4 可交付 | 分发、迁移、收尾 | P2-2、P2-3、P2-4、P1-2、P1-3、P1-5、P1-6、U-11 |

## 三、逐项方案

### P0

#### P0-1 Touch ID 模式 TTL 缓存不生效 · S
- `NewTouchIDProvider(ttl)`，增加 `mu`、`cachedKey`、`expiry`，逻辑与 `OTPProvider` 一致；`GetAuthProvider` 传入 TTL
- 用同一把锁包住“查缓存 → 弹指纹 → 写缓存”：多个并发签名只弹一次，后到的请求等待第一个结果；认证失败不写缓存
- 增强（可选）：通过 cgo 订阅 `com.apple.screenIsLocked` 和睡眠通知，锁屏或睡眠时清缓存；`ssh-add -x` 清缓存（见 P1-4）
- 验收：TTL=600 时 10 分钟内连续 ssh 只弹一次；并发 10 个 ssh 只弹一次；TTL=0 时每次都弹

#### P0-2 配置文件无法关闭 `require_touch_id_per_sign` · S
- `Load()` 先构造带默认值的 `Config{RequireTouchPerSign: true, ...}`，再 `json.Unmarshal` 覆盖；删除 `ApplyDefaults` 中强制改回 `true` 的那一行
- 验收：单测覆盖“文件不存在 / 字段缺失 / 显式 false”三种情况

#### P0-3 OTP 双因素可被绕过 · M（依赖 F1）
- OTP 初始化不再写 Keychain（删除 `otp_init.go:58`）
- 迁移：OTP 模式下检测到 Keychain 中有 `fssh` 条目时，先用 OTP 派生的 key 成功解密一条记录，确认两者一致后提示并删除该条目
- 验收：OTP 模式下 `export`/`remove` 必须输入密码和验证码；`security find-generic-password -s fssh` 查不到条目

#### P0-4 OTP 与 LaunchAgent 冲突 · M（依赖 F2）
- Agent 启动时只在有 TTY 时询问是否预解锁；无 TTY（launchd）直接开始监听，首次签名时用 `GUIPrompter` 弹出系统输入框
- 同一时刻只显示一个输入框，其他签名请求排队等待结果
- 验收：launchd 启动 OTP Agent 不再反复重启；首次 ssh 弹出系统输入框，输入正确后签名成功

#### P0-5 OTP 预解锁缓存未共享 · S（与 P0-4 一起做）
- `StartWithOptions` 只创建一次 provider，同一个实例同时用于预解锁和 `secureAgent`；`newSecureAgentWithTTL` 改为接收 provider 参数
- 验收：前台预解锁后，TTL 内首次 ssh 不再询问

#### P0-6 OTP 模式下 rekey 导致密钥不可用 · M（依赖 F1）
- 按模式分派：touchid 生成新的随机 key 写入 Keychain；otp 生成新的 `MasterKeySalt`（seed 不变，验证器无需重新绑定）并写回配置
- 原子性：当前实现中途失败时，一部分文件已用新 key 加密，Keychain 里却还是旧 key，会造成数据丢失。改为：
  1. 全部重新加密到 `keys.new/`
  2. 逐个用新 key 解密校验
  3. 保存新 key 或新 salt
  4. 将 `keys/` 重命名为 `keys.bak.<ts>/`，再将 `keys.new/` 重命名为 `keys/`
- `mode switch`（P1-2）复用这套流程
- 验收：两种模式 rekey 后签名正常；在第 N 个文件处注入失败，所有原密钥仍可用

#### P0-7 恢复码只生成不可用 · M
- 现状：恢复码只存了 SHA-256 哈希，密码学上无法用它恢复 seed，必须重新设计
- 初始化时为每个恢复码派生一个密钥（PBKDF2 + 独立 salt），用它加密一份 seed 副本，存为 `recovery_wrapped: [{salt, nonce, ct}]`
- 新命令：
  - `fssh otp recover`：输入恢复码 → 解出 seed → 设置新密码 → 用新密码重新加密 seed → 删除这个恢复码对应的副本（一次性）
  - `fssh otp change-password`：需要当前密码和验证码
  - `fssh otp regen-recovery`：需要当前密码和验证码，重新生成 10 个恢复码
- 老用户的已有恢复码作废（已决策），需要执行 `regen-recovery`。引导方式：
  - 检测到旧格式配置（有 `recovery_codes_hash`、没有 `recovery_wrapped`）时，OTP 解锁成功后提示一次“恢复码已失效，请运行 `fssh otp regen-recovery`”
  - `fssh doctor` 将其列为警告
  - README 和 Release 说明中写明
- 验收：用恢复码重置密码后 Agent 正常签名；同一个恢复码第二次使用失败

#### P0-8 认证弹窗不显示请求来源 · L（依赖 F3）
- 弹窗文案：`「<进程名>」请求使用密钥「<alias>」登录 <host>`；转发请求加醒目标记“⚠️ 来自远程转发（ssh -A）”
- 新配置 `forwarded_sign: prompt | deny`，默认 `prompt`；转发请求不使用 TTL 缓存，每次都要确认
- 每次签名写审计日志（时间、alias、进程、主机、是否转发、结果），新增 `fssh log` 查看
- 顺带清理：`ext-info-c` 是 SSH 传输层扩展而不是 agent 扩展，删除该分支；未知扩展返回 `xagent.ErrExtensionUnsupported`
- 验收：ssh 和 git 触发的弹窗显示正确的进程和主机；`ssh -A` 之后远端的 git 操作显示转发标记

### P1

#### P1-1 导入后明文私钥仍留在 `~/.ssh` · S（依赖 F5）
- 导入成功后让用户选择原文件的处理方式：保留 / 移到 `~/.ssh/fssh-archive/`（0700，默认）/ 删除（二次确认）
- 检查 ssh config 中指向该私钥的 `IdentityFile`，提示改为指向 `.pub` 文件（见 U-1）
- `fssh doctor` 扫描 `~/.ssh` 中的明文私钥并告警（见 P1-8）
- 验收：用户选择归档或删除后，`~/.ssh` 中不再有已导入密钥的明文

#### P1-2 重新初始化无效，`--force` 后旧密钥成孤儿 · M（依赖 F1、P0-6）
- 新命令 `fssh mode switch <touchid|otp>`：用旧 provider 解锁 → 初始化新模式 → 用新 master key 原子地重新加密所有密钥 → 清理旧模式的数据。取代“重新初始化”这种用法
- 向导检测到已初始化时，给出选项：退出 / 切换模式 / 清空重来。清空重来时列出将失效的密钥，先建议执行 `fssh backup`，再要求输入 `DELETE` 确认
- 正确向下传递 `force` 参数
- `auth.go:53` 的提示改为指向 `fssh mode switch otp`

#### P1-3 Touch ID 检测是假的 · S
- `internal/macos` 新增 `BiometryAvailable() bool`，通过 cgo 调用 `canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics`
- 不可用时默认选 OTP，并说明原因（没有传感器 / 未录入指纹 / 合盖使用）

#### P1-4 Agent 协议操作“假成功” · S（依赖 F3）
- `Lock(pass)`：保存加盐的口令哈希并清空缓存；锁定期间 `List` 返回空、`Sign` 拒绝。`Unlock(pass)` 校验口令后解除锁定
- `RemoveAll`：清空解锁缓存并返回成功（语义是“忘记已解锁状态”），记录日志
- `Add` / `Remove`：返回明确错误，提示改用 `fssh import` / `fssh remove`
- 验收：`ssh-add -x` 后 ssh 失败，`ssh-add -X` 后恢复；`ssh-add -D` 后下一次签名需要重新认证

#### P1-5 备份 / 换机路径缺失 · M
- `export` 改用 `ssh.MarshalPrivateKeyWithPassphrase`（x/crypto v0.32 已提供），默认输出 OpenSSH 格式；保留 `--format pkcs8`，但加密时不再使用旧式 PEM 加密
- 新命令 `fssh backup --out x.fsshbak` / `fssh restore --in x.fsshbak`：用用户设定的备份口令（scrypt + AES-256-GCM）打包所有记录；恢复时用新机器的 master key 重新加密
- 验收：导出文件可被 `ssh -i` 直接使用；在 A 机备份、B 机恢复后签名正常

#### P1-6 向导引导矛盾 · S
- 根据 `addToSSHConfig` 的结果决定结束语：已写入 `IdentityAgent` 时，环境变量标注为“可选，供不读 ssh config 的工具使用”
- 提供“自动写入 shell 配置”选项：检测 `$SHELL`，以托管块形式写入，写入前确认
- 欢迎页与步骤标题从同一个步骤数组生成，保证数量一致

#### P1-7 交互式 Shell 可用性（同时修 U-5、U-6、U-7） · M（依赖 F4）
- `Include`：使用 F4 的解析器
- DNS：默认不解析，只显示 `HostName`；只有 `HostName` 本身是 IP 时才参与 IP 补全和匹配。提供 `list --resolve` 并发解析，每个主机 300ms 超时，并过滤 fake-ip 网段 `198.18.0.0/15`
- 多别名合并为一行，例如 `web1 (web1-alias)`
- 编号按主机名排序，保持稳定
- 验收：Include 中的主机能显示；断网时 Shell 启动不超过 100ms；fake-ip 地址不显示

#### P1-8 `status` 信息过少（同时修 U-10） · M
- `fssh status` 显示：认证模式、是否已初始化、Agent 是否运行（连接 socket 并调用 List 得到密钥数）、TTL、LaunchAgent 状态、ssh config 是否已接入、`SSH_AUTH_SOCK`
- 新增 `fssh doctor`：逐项检查并给出修复命令，覆盖明文私钥残留、缺少 `IdentitiesOnly`、socket 不可达、运行中的 Agent 与 CLI 版本不一致
- 签名被拒绝或失败时，通过 `GUIPrompter.Notify` 发系统通知：“fssh 拒绝了 <进程> 的签名请求：<原因>”
- 验收：Agent 停止时 `doctor` 能指出问题，并给出 `launchctl kickstart` 命令

#### P1-9 细节问题 · S（i18n 为 M）
- 语言（已决策：中英双语）：
  - 新增 `internal/i18n` 包，所有面向用户的文案用 `i18n.T("key", args...)` 获取，中英文案放在同一张表里，缺少翻译时回退英文
  - 语言判定顺序：环境变量 `FSSH_LANG` → `config.json` 的 `language` 字段 → `LC_ALL` / `LC_MESSAGES` / `LANG`（`zh*` 为中文，否则英文）→ macOS 系统首选语言（`defaults read -g AppleLanguages`）
  - 最后一步是为 launchd 启动的 Agent 准备的：它没有 shell 环境变量，否则 Touch ID 弹窗和系统通知会一律变成英文
  - 日志字段名保持英文，便于检索；只翻译日志的 message
  - 帮助（U-4）、向导、错误提示、弹窗文案全部走 i18n；`init` 向导写入 `language` 字段，固定用户的选择
  - 验收：`FSSH_LANG=en` 和 `FSSH_LANG=zh` 下，所有命令和向导都没有混杂语言；launchd 下的 Agent 弹窗语言与系统语言一致
- 验证码提示改为使用 `config.Digits`
- 删除对不存在的 `switch-to-otp` 的引用（改为 P1-2 的新命令）
- 日志移到 `~/Library/Logs/fssh/agent.log`，权限 0600；`auth_mode.json` 改为 0600

### P2

#### P2-1 CI 发布构建失败 · S
- 改为 `runs-on: macos-14`、`CGO_ENABLED=1`，分别构建 arm64 和 amd64，再用 `lipo -create` 合成 universal binary
- `go-version-file: go.mod`；增加 `go vet ./...` 和 `go test ./...`
- 验收：推送 tag 后，Release 中有可运行的二进制

#### P2-2 无 Homebrew、无签名，二进制提交进仓库 · M
- `git rm --cached fssh`；`.gitignore` 增加 `/fssh` 和 `dist/`
- 不做签名和公证（已决策），以下面三点降低影响：
  - **Homebrew 作为首选安装方式**：建 `homebrew-fssh` tap，formula 从源码编译（`depends_on "go" => :build`）。本地编译的二进制不带下载隔离标记，不会被 Gatekeeper 拦截
  - **Release 直接下载作为备选**：Release 说明和 README 写明 `xattr -d com.apple.quarantine fssh-*`；`contrib/` 提供一个安装脚本，自动完成下载、校验 sha256、解除隔离和安装
  - **升级后重新授权 Keychain**：没有固定签名身份时，每次构建的二进制签名都不同，升级后访问 Keychain 预计会再弹一次授权框（待实测确认）。在 README 的升级章节说明“点击『始终允许』即可”；`fssh doctor` 检测到这种情况时也给出同样的提示
- 验收：在全新机器上执行 `brew install` 后能直接运行；通过安装脚本安装的二进制不被 Gatekeeper 拦截

#### P2-3 无任何测试 · M
- 优先补单测：crypt 加解密往返、store 保存/加载/篡改检测、TOTP（RFC 6238 附录测试向量）、config 默认值（P0-2 回归）、sshconfig 解析与写入（golden 文件）、恢复码
- Agent 测试：用假的 `AuthProvider`（接口已存在）测 List / Sign / TTL / 并发 / Lock
- 给 keychain 和 touchid 包一层接口，便于在测试中替换

#### P2-4 文档与实现不一致 · S
- 修正 CLAUDE.md 中 scrypt → PBKDF2，修正 README FAQ 编号，补全命令文档
- 命令帮助由代码生成（U-4），README 引用这份帮助，避免再次不一致

### U

#### U-1 无法指定哪台主机用哪把钥匙 · M（依赖 F4、F5）
- Shell `add`/`edit` 选择 fssh 密钥时，写入 `IdentityAgent` + `IdentityFile ~/.fssh/pubkeys/<alias>.pub` + `IdentitiesOnly yes`。OpenSSH 支持用公钥文件从 agent 中选择私钥，1Password 也采用这种做法
- 新命令 `fssh bind <host> <alias>`；`show`/`info` 显示该主机绑定的 alias
- 向导检测到多把密钥时，提示进行绑定（例如区分 github.com 的个人账号和公司账号）
- 验收：两把 GitHub key 分别绑定不同的 Host 别名后，push 使用的账号正确；导入 8 把 key 时不再出现 `Too many authentication failures`

#### U-2 同名 alias 静默覆盖 · S
- 导入前检查 `<alias>.enc` 是否存在：存在则报错并提示使用 `--force`；指纹相同时提示“已导入”
- alias 校验 `^[A-Za-z0-9._-]+$`，同时防止 `../` 路径穿越

#### U-3 导入加密私钥不会自动询问密码 · S
- 遇到 `*ssh.PassphraseMissingError` 且在 TTY 中时，自动提示输入密码，最多重试 3 次
- 底层错误映射为易懂的说明，并附下一步建议，例如“密码不正确，请重试；如忘记密码，该私钥无法导入”

#### U-4 没有帮助和版本信息 · S
- 构建时用 `-ldflags "-X main.version=… -X main.commit=…"` 注入版本号，支持 `fssh version` / `--version`
- `fssh help [cmd]` 列出所有命令及一句话说明；各子命令的 `-h` 使用 flag 自带帮助
- 无参数运行：未初始化时提示运行 `fssh init`；已初始化时进入 Shell，并显示一行提示说明当前状态
- 退出码：`help` 返回 0，未知命令返回 2

#### U-5 / U-6 / U-7
- 见 P1-7

#### U-8 Shell 连接能力受限 · S
- `connect` 在 config 中找不到主机时，把参数原样透传给 ssh（如 `connect user@1.2.3.4 -p 2222`），参数按 shell 规则切分
- ssh 以非 0 退出码结束时，显示退出码

#### U-9 没有生成密钥、查看公钥的命令 · S（依赖 F5）
- `fssh keygen --alias x [--type ed25519|ecdsa|rsa]`：在内存中生成后直接加密存储并输出公钥，明文私钥从不落盘
- `fssh pubkey <alias> [--copy]`：输出 authorized_keys 格式，`--copy` 时通过 `pbcopy` 写入剪贴板
- `fssh list` 改为表格（ALIAS / TYPE / FINGERPRINT / CREATED / COMMENT），并提供 `--json`

#### U-10 认证失败时用户看不懂
- 见 P1-8（系统通知 + `doctor`）和 P1-1（不再静默回退到明文 key）

#### U-11 无卸载路径 · S（依赖 F4）
- 新命令 `fssh uninstall`：卸载并删除 LaunchAgent、移除 ssh config 托管块、可选删除 `/usr/local/bin/fssh`
- 默认保留 `~/.fssh` 和 Keychain 条目；加 `--purge` 才删除，删除前强制提示先执行 `fssh backup`

#### U-12 `remove` 先认证再检查是否存在 · S
- 调整顺序：检查是否存在 → 显示指纹并二次确认 → 认证 → 删除
- 可选：删除改为移入 `~/.fssh/trash/`，支持恢复

## 四、决策记录

### 已决策（2026-10-21）

1. **界面语言**：中英双语，见 P1-9
2. **签名与公证**：不签名，以 Homebrew 源码编译 + 安装脚本替代，见 P2-2
3. **转发签名请求的默认策略**：每次确认（`forwarded_sign: prompt`），不使用 TTL 缓存，见 P0-8
4. **OTP 后台输入方式**：`osascript` 系统弹窗，不做菜单栏 App，见 F2、P0-4
5. **老用户的恢复码作废**：接受，新设计不兼容旧恢复码；通过提示引导用户重新生成，见 P0-7

所有决策项均已确定。
