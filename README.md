# fssh

macOS 安装与开机自启请参阅 docs/macos.md，其中包含 `launchd` 配置示例（contrib/com.fssh.agent.plist）。

在 macOS 上通过 Touch ID 解锁对称主密钥，解密本地加密的 SSH 私钥并用于登录；同时提供兼容 OpenSSH 的 ssh-agent。

## 功能概述
- 通过 Touch ID/用户在场验证读取主密钥（存储于 Keychain）
- 使用 AES-256-GCM + HKDF 加密私钥（每文件独立 `salt`/`nonce`）
- 私钥导入/导出（统一为 PKCS#8 PEM 备份）、列出与状态检查
- 提供 ssh-agent：
  - 支持“每次签名都触发指纹”模式（默认开启）
  - 不将明文私钥写回磁盘，签名仅在内存中完成

## 安装与构建
- 依赖：Go 1.21+、macOS 13+（含 Touch ID 或 Apple Watch 解锁）
- 构建：
  - `go build ./cmd/fssh`
  - 生成二进制 `./fssh`

## 快速开始
1. 初始化主密钥：
   - `./fssh init`
2. 导入私钥：
   - 无口令私钥：`./fssh import --alias work --file ~/.ssh/id_ed25519`
   - 有口令私钥（安全输入）：
     - 交互式读取：`./fssh import --alias work --file ~/.ssh/id_ed25519 --ask-passphrase`
     - 从文件读取：`./fssh import --alias work --file ~/.ssh/id_ed25519 --passphrase-file /secure/path/pass.txt`
     - 从 stdin 读取：`echo -n '<原口令>' | ./fssh import --alias work --file ~/.ssh/id_ed25519 --passphrase-stdin`
3. 启动按签名解锁的 agent：
   - `./fssh agent --require-touch-id-per-sign=true --socket ./agent.sock`
   - `export SSH_AUTH_SOCK=$(pwd)/agent.sock`
   - 验证：`ssh-add -l`（列出公钥，签名时会弹出 Touch ID）

## 命令说明
- `fssh init`
  - 生成并写入主密钥到 Keychain（GenericPassword，解锁前会触发 Touch ID）
  - 可选：`--force` 覆盖已存在主密钥
- `fssh import --alias <name> --file <path> [--passphrase <p>] [--comment <c>]`
  - 解析 OpenSSH 私钥，统一序列化为 PKCS#8 DER，并加密保存为 `~/.fssh/keys/<alias>.enc`
- `fssh list`
  - 列出已导入的别名、指纹与创建时间
- `fssh export --alias <name> --out <path> [--ask-passphrase|--passphrase-file <pfile>|--passphrase-stdin] [--force]`
  - 解密指定别名并导出为 PKCS#8 PEM；可选使用备份口令（PEM AES-256）
   - 不推荐直接用 `--passphrase '<口令>'` 在命令行传参，避免泄露风险
- `fssh remove --alias <name>`
  - 删除指定别名的加密私钥文件（访问主密钥前会触发 Touch ID）
- `fssh rekey`
  - 重新生成主密钥，并对所有记录进行“解密→用新主密钥重加密”，最后更新 Keychain
- `fssh status`
  - 查看主密钥是否存在、存储目录状态
- `fssh agent [--socket <path>] [--require-touch-id-per-sign=<true|false>]`
  - 启动 ssh-agent 服务，监听 UNIX socket；默认按签名触发指纹

## SSH agent 使用
- 建议使用项目目录中的 socket，避免家目录权限限制：
  - `./fssh agent --socket ./agent.sock`
  - `export SSH_AUTH_SOCK=$(pwd)/agent.sock`
- 列出 agent 身份：`ssh-add -l`
- 使用 ssh 登录：`ssh user@host`（OpenSSH 会调用 agent 完成签名）

## 安全设计
- 主密钥保护：macOS Keychain + Touch ID/用户在场验证（LocalAuthentication）
- 数据加密：AES-256-GCM；HKDF(master, salt, info=alias) 派生文件级密钥；AEAD 绑定 `fingerprint` 作为 AAD
- 内存策略：签名所需的私钥仅在内存中存在；不落盘明文
- 记录元数据：保存 `pubkey`（base64 的 `Marshal()`）、`fingerprint`，agent 列表无需解密

## 存储格式（fingerpass/v1）
JSON 文件 `~/.fssh/keys/<alias>.enc` 字段：
- `version`、`alias`、`fingerprint`、`pubkey`、`key_type`（PKCS8）、`hkdf_salt`、`nonce`、`ciphertext`、`created_at`、`comment`

## 常见问题
- “The agent has no identities”：请确认已导入私钥并启动 agent；`ssh-add -l` 只读取 `SSH_AUTH_SOCK` 指定的 socket。
- 删除家目录下的 socket 失败：使用 `--socket ./agent.sock` 在工程目录启动。
- 指纹集合变化后读取失败：执行 `fssh rekey` 重建主密钥并重加密。

## 路线图
- 在 `Sign` 阶段通过 SecItem 的 AccessControl 强绑定生物识别，进一步收紧策略
- 会话 TTL 与缓存控制、每次签名必触发与“会话内一次触发”两种模式切换
- `fssh ssh` 便捷封装命令