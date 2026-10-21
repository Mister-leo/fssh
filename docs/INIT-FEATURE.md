> **注意 / Note:** 本文档是早期的设计与实现记录，部分内容（如 TOTP 密钥格式、恢复码、命令用法）已过时，请以 [README](../README_CN.md) 为准。
> This is an early design/implementation record and is partly outdated (TOTP secret format, recovery codes, commands); see the [README](../README.md).

# fssh init 功能整理

## 概述

`fssh init` 是 fssh 的初始化命令，用于创建和配置主密钥（Master Key），支持两种认证模式：**Touch ID** 和 **OTP（一次性密码）**。

## 命令格式

```bash
fssh init [options]
```

## 通用选项

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--force` | bool | false | 强制重新创建主密钥（覆盖已存在的配置） |
| `--mode` | string | touchid | 认证模式：`touchid` 或 `otp` |

---

## 模式 1: Touch ID 认证（默认）

### 功能说明

使用 macOS 的 Touch ID 或密码保护主密钥，存储在系统 Keychain 中。

### 使用方法

```bash
# 使用默认 Touch ID 模式
fssh init

# 明确指定 Touch ID 模式
fssh init --mode touchid

# 强制重新初始化
fssh init --mode touchid --force
```

### 工作流程

1. **检查现有密钥**：如果主密钥已存在且未使用 `--force`，终止并提示
2. **生成主密钥**：生成 32 字节随机密钥
3. **存储到 Keychain**：使用 macOS Keychain 存储，受 Touch ID/密码保护
4. **保存认证模式**：记录当前使用 Touch ID 模式

### 特点

- ✅ **无需记忆密码**：依赖 macOS 生物识别或系统密码
- ✅ **系统级安全**：Keychain 提供硬件级加密保护
- ✅ **快速访问**：Touch ID 验证后快速解锁
- ⚠️ **平台限制**：仅支持 macOS 系统
- ⚠️ **设备绑定**：无法在其他设备上使用

### 输出示例

```
initialized master key with Touch ID protection
```

---

## 模式 2: OTP 认证

### 功能说明

使用基于时间的一次性密码（TOTP）+ 自定义密码保护主密钥，支持跨平台和多设备同步。

### OTP 专用选项

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--seed-unlock-ttl` | int | 3600 | OTP seed 缓存时间（秒），解锁后在此时间内无需重新输入密码 |
| `--algorithm` | string | SHA1 | TOTP 哈希算法：`SHA1`、`SHA256`、`SHA512` |
| `--digits` | int | 6 | TOTP 验证码位数：`6` 或 `8` |

### 使用方法

```bash
# 使用默认 OTP 配置
fssh init --mode otp

# 自定义 OTP 参数
fssh init --mode otp \
  --seed-unlock-ttl 7200 \
  --algorithm SHA256 \
  --digits 8

# 强制重新初始化 OTP
fssh init --mode otp --force
```

### 工作流程

1. **检查现有配置**：如果 OTP 配置已存在且未使用 `--force`，终止并提示
2. **设置 OTP 密码**：
   - 提示用户输入密码（至少 12 位）
   - 要求确认密码
   - 使用 Argon2id 对密码进行哈希加密
3. **生成 TOTP 配置**：
   - 生成 20 字节随机 OTP seed
   - 使用密码加密 seed（AES-256-GCM）
   - 生成恢复码（10 个 32 字符的十六进制码）
4. **派生主密钥**：
   - 使用 HKDF 从 OTP seed 派生主密钥
   - 主密钥也存储到 Keychain（用于兼容 import/export 命令）
5. **保存配置**：
   - 保存 OTP 配置到 `~/.fssh/otp-config.json`
   - 保存恢复码到 `~/.fssh/recovery-codes.json`
   - 保存认证模式标记
6. **显示初始化结果**：
   - 显示 TOTP 二维码（用于手机 Authenticator 扫描）
   - 显示 TOTP URI（手动输入）
   - 显示恢复码列表

### 配置文件

#### OTP 配置文件：`~/.fssh/otp-config.json`

```json
{
  "version": "1.0",
  "algorithm": "SHA1",
  "digits": 6,
  "period": 30,
  "encrypted_seed": "base64-encoded-ciphertext",
  "nonce": "base64-encoded-nonce",
  "salt": "base64-encoded-salt",
  "password_hash": "argon2id-hash",
  "master_key_salt": "base64-encoded-salt",
  "seed_unlock_ttl": 3600
}
```

#### 恢复码文件：`~/.fssh/recovery-codes.json`

```json
{
  "codes": [
    "e4b3a2c1d5f6g7h8i9j0k1l2m3n4o5p6",
    "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    ...
  ],
  "created_at": "2026-01-06T01:30:00Z"
}
```

### 特点

- ✅ **跨平台支持**：可在 Linux/Windows 等系统使用
- ✅ **多设备同步**：通过导出/导入配置在多台设备使用
- ✅ **离线可用**：不依赖网络，基于时间戳生成验证码
- ✅ **双因素认证**：密码 + 动态 OTP，安全性更高
- ✅ **恢复机制**：提供 10 个恢复码，防止 OTP 设备丢失
- ⚠️ **需记忆密码**：必须记住初始化时设置的密码
- ⚠️ **时间同步**：需要系统时间准确（允许 ±30 秒偏差）

### OTP 工作原理

```
用户输入密码
    ↓
验证密码哈希（Argon2id）
    ↓
解密 OTP seed（AES-256-GCM）
    ↓
缓存 seed（TTL 可配置）
    ↓
用 seed 派生 Master Key（HKDF）
    ↓
解密 SSH 私钥
```

### 输出示例

```
初始化 OTP 认证模式

请设置 OTP 密码（至少12位）: ************
确认密码: ************

=== OTP 初始化成功 ===

1. 请使用 Authenticator 应用扫描此二维码:

█████████████████████████████
█████████████████████████████
████   ▄▄▄▄▄ █▀▄█  ▄▄▄▄▄   ████
████   █   █ █ ██  █   █   ████
████   █▄▄▄█ █ ▀▀  █▄▄▄█   ████
████ ▄▄▄▄▄▄▄ ▀ ▀▀ ▄▄▄▄▄▄▄  ████
...
█████████████████████████████

2. 或手动输入以下 URI:

   otpauth://totp/fssh:user@hostname?secret=ABCD1234EFGH5678&algorithm=SHA1&digits=6&period=30

3. TOTP 配置参数:
   - 算法: SHA1
   - 位数: 6
   - 周期: 30 秒

4. 恢复码（请妥善保管，用于密码遗忘时恢复访问）:

   e4b3a2c1d5f6g7h8i9j0k1l2m3n4o5p6
   a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
   f1g2h3i4j5k6l7m8n9o0p1q2r3s4t5u6
   ...

   恢复码已保存到: /Users/user/.fssh/recovery-codes.json

⚠️ 重要提示:
  - 请立即备份恢复码到安全位置
  - 每个恢复码只能使用一次
  - OTP 配置文件位于: /Users/user/.fssh/otp-config.json
```

---

## 认证模式切换

### 查看当前模式

```bash
fssh status
```

输出包含认证模式信息（如果已初始化）。

### 从 Touch ID 切换到 OTP

```bash
# 先备份现有的密钥
fssh list
# 导出所有密钥...

# 重新初始化为 OTP 模式
fssh init --mode otp --force

# 重新导入密钥
# fssh import ...
```

### 从 OTP 切换到 Touch ID

```bash
# 先备份现有的密钥
fssh list
# 导出所有密钥...

# 重新初始化为 Touch ID 模式
fssh init --mode touchid --force

# 重新导入密钥
# fssh import ...
```

⚠️ **警告**：切换认证模式会生成新的主密钥，需要重新导入所有 SSH 私钥。

---

## 安全考虑

### Touch ID 模式

- **优点**：
  - 依赖硬件安全模块（Secure Enclave）
  - 无需担心密码泄露
  - 系统级加密保护

- **风险**：
  - 如果 Mac 丢失且未设置固件密码，可能被物理攻击
  - 依赖单一设备，设备损坏数据丢失

### OTP 模式

- **优点**：
  - 双因素认证（密码 + 动态 OTP）
  - 支持多设备备份
  - 恢复码机制

- **风险**：
  - 密码被破解的风险（建议使用强密码）
  - OTP 设备丢失需使用恢复码
  - 配置文件被窃取且密码较弱时存在风险

### 推荐实践

1. **Touch ID 模式**：
   - 设置固件密码保护 Mac
   - 启用 FileVault 全盘加密
   - 定期导出密钥到安全位置

2. **OTP 模式**：
   - 使用强密码（16+ 字符，大小写+数字+符号）
   - 恢复码打印并存放在安全位置（如保险柜）
   - 定期测试恢复码是否有效
   - 备份 `~/.fssh/otp-config.json` 到加密存储

3. **通用建议**：
   - 定期使用 `fssh rekey` 更换主密钥
   - 不要在共享计算机上使用
   - 监控 `~/.fssh/` 目录的文件完整性

---

## 错误处理

### 常见错误

1. **"master key already exists"**
   - 原因：已初始化过 Touch ID 模式
   - 解决：使用 `--force` 强制覆盖

2. **"OTP 配置已存在"**
   - 原因：已初始化过 OTP 模式
   - 解决：使用 `--force` 强制覆盖

3. **"密码长度不足"**
   - 原因：OTP 密码少于 12 位
   - 解决：使用更长的密码

4. **"两次密码输入不一致"**
   - 原因：确认密码与初始密码不匹配
   - 解决：重新运行命令并仔细输入

5. **"不支持的认证模式"**
   - 原因：`--mode` 参数值不正确
   - 解决：使用 `touchid` 或 `otp`

6. **"保存认证模式失败"**
   - 原因：文件系统权限问题
   - 解决：检查 `~/.fssh/` 目录权限

---

## 高级用法

### 自定义 OTP 参数

适用于高安全性要求场景：

```bash
fssh init --mode otp \
  --seed-unlock-ttl 1800 \    # 30分钟缓存
  --algorithm SHA512 \         # 使用更强的哈希算法
  --digits 8                   # 8位验证码（更安全）
```

### 恢复码使用

当 OTP 设备丢失时：

```bash
# 系统会提示输入恢复码
# 输入 32 字符的十六进制恢复码
# 恢复码使用一次后自动失效
```

### 批量初始化（自动化部署）

不推荐，但如果需要在 CI/CD 中使用：

```bash
# 仅用于测试环境
export OTP_PASSWORD="test-password-12345"
echo "$OTP_PASSWORD" | fssh init --mode otp --seed-unlock-ttl 86400
```

⚠️ **警告**：生产环境应避免自动化初始化，以防密码泄露。

---

## 相关命令

- `fssh status` - 查看初始化状态和认证模式
- `fssh import` - 导入 SSH 私钥（需先初始化）
- `fssh list` - 列出已导入的密钥
- `fssh export` - 导出私钥
- `fssh rekey` - 更换主密钥
- `fssh agent` - 启动 SSH agent（需先初始化并导入密钥）

---

## 技术细节

### 密钥派生（OTP 模式）

```
OTP Password (用户输入)
    ↓
Argon2id(password, salt, iterations, memory)
    ↓
Password Hash (用于验证密码)

OTP Password (用户输入)
    ↓
PBKDF2(password, salt, 600000 iterations, SHA256)
    ↓
Key Encryption Key (KEK)
    ↓
AES-256-GCM(KEK, nonce)
    ↓
解密 OTP Seed

OTP Seed (20 bytes)
    ↓
HKDF(seed, master_key_salt, "fssh-master-key-v1", 32)
    ↓
Master Key (32 bytes)
```

### 文件存储

```
~/.fssh/
├── otp-config.json         # OTP 配置（加密的 seed）
├── recovery-codes.json     # 恢复码列表
├── auth-mode.json          # 认证模式标记
├── keys/                   # 加密的私钥存储
│   ├── alias1.enc
│   └── alias2.enc
└── agent.sock              # SSH agent socket
```

### 加密算法

- **主密钥加密私钥**：AES-256-GCM
- **密码加密 OTP seed**：AES-256-GCM
- **密码哈希**：Argon2id（时间成本 3, 内存 64MB, 并行度 4）
- **密钥派生**：PBKDF2-HMAC-SHA256（600,000 迭代）或 HKDF-SHA256
- **TOTP 算法**：HMAC-SHA1/SHA256/SHA512（可配置）

---

## 常见问题

### Q: 能否同时支持 Touch ID 和 OTP？

A: 当前不支持。系统只能使用一种认证模式。但可以：
- 在 Mac 上使用 Touch ID 模式
- 在其他设备上导出配置后使用 OTP 模式

### Q: 忘记 OTP 密码怎么办？

A: 使用恢复码访问：
1. 运行需要认证的命令（如 `fssh import`）
2. 当提示输入密码时，输入恢复码
3. 恢复码验证通过后可继续使用
4. 建议立即重新初始化并更换密码

### Q: OTP 验证码一直提示错误？

A: 检查系统时间：
```bash
# macOS
sudo sntp -sS time.apple.com

# Linux
sudo ntpdate pool.ntp.org
```

TOTP 依赖准确的系统时间（±30 秒容差）。

### Q: 如何备份 OTP 配置到其他设备？

A:
```bash
# 在原设备上
cd ~/.fssh
tar czf fssh-backup.tar.gz otp-config.json recovery-codes.json auth-mode.json

# 传输 fssh-backup.tar.gz 到新设备

# 在新设备上
mkdir -p ~/.fssh
cd ~/.fssh
tar xzf /path/to/fssh-backup.tar.gz
```

⚠️ 传输时使用加密通道（如 scp），不要通过不安全的渠道。

### Q: 可以在 Linux/Windows 上使用 fssh 吗？

A:
- **Touch ID 模式**：仅支持 macOS
- **OTP 模式**：理论支持所有平台（需要编译适配）

当前 fssh 主要针对 macOS 开发，Linux/Windows 支持需要适配 Keychain 替代方案。

---

## 版本历史

- **v1.0** - 初始版本，仅支持 Touch ID
- **v2.0** - 新增 OTP 认证模式，支持跨平台
- **v2.1** - 优化恢复码机制，增加配置验证

---

## 参考文档

- [OTP 认证实现](./otp-authentication.md)
- [OTP 快速开始](./OTP-QUICKSTART.md)
- [安全设计文档](./security-design.md)
- [RFC 6238 - TOTP 规范](https://tools.ietf.org/html/rfc6238)
- [RFC 4226 - HOTP 规范](https://tools.ietf.org/html/rfc4226)
