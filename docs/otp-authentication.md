> **注意 / Note:** 本文档是早期的设计与实现记录，部分内容（如 TOTP 密钥格式、恢复码、命令用法）已过时，请以 [README](../README_CN.md) 为准。
> This is an early design/implementation record and is partly outdated (TOTP secret format, recovery codes, commands); see the [README](../README.md).

# OTP 认证方案设计文档

## 版本信息
- **文档版本**: v4 (最终版)
- **创建日期**: 2025-01-15
- **适用fssh版本**: v2.0+

---

## 目录
1. [概述](#概述)
2. [认证模型](#认证模型)
3. [技术架构](#技术架构)
4. [安全性分析](#安全性分析)
5. [用户使用指南](#用户使用指南)
6. [配置参考](#配置参考)
7. [命令行接口](#命令行接口)
8. [实施计划](#实施计划)

---

## 概述

### 方案背景

fssh 目前使用 Touch ID 认证保护 SSH 私钥。然而，部分 macOS 设备不支持 Touch ID（如 Mac Mini、老款 MacBook、虚拟机等）。OTP（One-Time Password）认证方案提供了一个基于密码和 TOTP 验证码的替代认证方式。

### 核心特性

- **双层安全架构**: 密码保护 OTP seed + TOTP 动态验证码
- **灵活的缓存策略**: 可配置 OTP seed 和 Master Key 的缓存周期
- **恢复码机制**: 防止丢失认证器时无法访问
- **与 Touch ID 并行**: 用户可根据设备能力选择认证方式
- **标准兼容**: 使用 RFC 6238 TOTP 标准，兼容各类认证器应用

### 认证方式对比

| 特性 | Touch ID 模式 | OTP 模式 |
|-----|--------------|---------|
| **设备要求** | 需 Touch ID/Face ID 硬件 | 任意 Mac |
| **解锁方式** | 生物特征（指纹/面容） | 密码 + TOTP 验证码 |
| **安全性** | 硬件级保护 + Keychain | PBKDF2 + AES-256 + TOTP |
| **跨设备迁移** | ❌ (Keychain 绑定设备) | ✅ (可导出配置) |
| **离线可用** | ✅ | ✅ |
| **适用场景** | 个人 MacBook/iMac | 服务器、虚拟机、旧款 Mac |

---

## 认证模型

### 双层安全架构

```
┌─────────────────────────────────────────────────────────┐
│ Layer 1: 密码解锁 OTP seed (长期保护)                     │
│   用户输入密码 → PBKDF2(100k迭代) → AES-256-GCM解密      │
│   → 获取 OTP seed → 缓存到内存 (TTL: seed_unlock_ttl)   │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Layer 2: TOTP 验证码验证 (动态认证)                      │
│   用户输入验证码 → 验证 TOTP(seed, code)                │
│   → 从 seed 派生 Master Key → 缓存 (TTL: unlock_ttl)    │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Layer 3: 私钥解密和签名                                  │
│   Master Key → HKDF 派生文件密钥 → AES-256-GCM 解密私钥  │
│   → SSH 签名 → 返回客户端                                │
└─────────────────────────────────────────────────────────┘
```

### 工作流程详解

#### 1. Agent 启动时 / OTP seed 缓存过期

```
用户: fssh agent
  ↓
提示输入密码: ****************
  ↓
PBKDF2(password, salt, 100000, SHA-256) → 解密密钥
  ↓
AES-256-GCM 解密 OTP seed
  ↓
缓存 seed 到内存 (有效期: seed_unlock_ttl_seconds)
  ↓
提示输入验证码: 123456
  ↓
验证 TOTP(seed, code) → 成功
  ↓
HKDF(seed, salt, info) → Master Key
  ↓
缓存 Master Key (有效期: unlock_ttl_seconds)
  ↓
Agent 启动完成
```

#### 2. SSH 连接时 (Master Key 在缓存期内)

```
用户: ssh user@server
  ↓
SSH 客户端请求签名
  ↓
检查 Master Key 缓存 → 命中
  ↓
直接使用 Master Key 解密私钥并签名
  ↓
连接建立
```

#### 3. SSH 连接时 (Master Key 过期，seed 在缓存期内)

```
用户: ssh user@server
  ↓
检查 Master Key 缓存 → 过期
  ↓
检查 OTP seed 缓存 → 命中
  ↓
提示输入验证码: 789012
  ↓
验证 TOTP(缓存的seed, code) → 成功
  ↓
派生新的 Master Key 并缓存
  ↓
解密私钥并签名
  ↓
连接建立
```

#### 4. SSH 连接时 (seed 缓存过期)

```
用户: ssh user@server
  ↓
检查 OTP seed 缓存 → 过期
  ↓
提示输入密码: ****************
  ↓
解密 OTP seed 并缓存
  ↓
提示输入验证码: 456789
  ↓
验证 TOTP 并派生 Master Key
  ↓
解密私钥并签名
  ↓
连接建立
```

---

## 技术架构

### 数据结构

#### OTP 配置文件 (`~/.fssh/otp/config.enc`)

```json
{
    "version": "fssh-otp/v1",
    "algorithm": "SHA1",
    "digits": 6,
    "period": 30,

    "encrypted_seed": "base64-encoded-ciphertext",
    "seed_salt": "base64-32-bytes",
    "seed_nonce": "base64-12-bytes",

    "master_key_salt": "base64-32-bytes",

    "seed_unlock_ttl_seconds": 3600,

    "recovery_codes_hash": [
        "sha256-hash-1",
        "sha256-hash-2",
        "..."
    ],

    "created_at": "2025-01-15T10:30:00Z"
}
```

**字段说明:**

| 字段 | 类型 | 说明 |
|-----|------|------|
| `version` | string | 配置版本标识 |
| `algorithm` | string | TOTP 算法: SHA1/SHA256/SHA512 |
| `digits` | int | 验证码位数: 6 或 8 |
| `period` | int | TOTP 时间窗口（秒），标准为 30 |
| `encrypted_seed` | string | AES-256-GCM 加密的 OTP seed (base64) |
| `seed_salt` | string | PBKDF2 使用的 salt (base64, 32字节) |
| `seed_nonce` | string | AES-GCM 使用的 nonce (base64, 12字节) |
| `master_key_salt` | string | HKDF 派生 Master Key 的 salt (base64, 32字节) |
| `seed_unlock_ttl_seconds` | int | OTP seed 缓存有效期（秒） |
| `recovery_codes_hash` | array | 恢复码的 SHA-256 哈希数组 |

#### 运行时状态 (内存中)

```go
type OTPProvider struct {
    configPath string
    config     *otp.Config

    // OTP seed 缓存
    mu         sync.Mutex
    cachedSeed []byte      // 解密后的 OTP seed
    seedExpiry time.Time   // seed 缓存过期时间

    // Master key 缓存
    cachedMasterKey []byte
    masterKeyExpiry time.Time
    masterKeyTTL    int
}
```

### 密码学设计

#### 1. OTP Seed 加密

```
用户密码 (string)
  ↓
PBKDF2-HMAC-SHA256(password, salt, 100000 iterations) → 32字节解密密钥
  ↓
AES-256-GCM.Encrypt(解密密钥, nonce, OTP_seed, AAD=nil) → 密文
  ↓
Base64编码 → 存储到 config.enc
```

**参数选择:**
- **PBKDF2 迭代次数**: 100,000 (OWASP 2023 推荐最小值)
- **Salt 长度**: 32 字节 (256 bits)
- **AES 模式**: GCM (Galois/Counter Mode) 提供认证加密
- **Nonce 长度**: 12 字节 (GCM 标准推荐)

#### 2. Master Key 派生

```
OTP seed (20字节) + Master Key Salt (32字节)
  ↓
HKDF-SHA256(seed, salt, info="fssh-master-key-v1", length=32)
  ↓
32字节 Master Key
```

**HKDF 流程:**
```
1. Extract: PRK = HMAC-SHA256(salt, OTP_seed)
2. Expand:
   T(0) = ""
   T(1) = HMAC-SHA256(PRK, T(0) || info || 0x01)
   T(2) = HMAC-SHA256(PRK, T(1) || info || 0x02)
   ...
   Output = first 32 bytes of (T(1) || T(2) || ...)
```

#### 3. TOTP 验证

```go
func Verify(seed []byte, userCode string, algorithm string, digits int, period int) bool {
    now := time.Now().Unix()
    counter := now / int64(period)

    // 允许 ±1 个时间窗口（±30秒容错）
    for offset := int64(-1); offset <= 1; offset++ {
        expected := GenerateTOTP(seed, counter+offset, algorithm, digits)
        if userCode == expected {
            return true
        }
    }
    return false
}

func GenerateTOTP(seed []byte, counter int64, algorithm string, digits int) string {
    // HOTP 算法 (RFC 4226)
    h := hmac.New(sha1.New, seed)
    binary.Write(h, binary.BigEndian, counter)
    hash := h.Sum(nil)

    // Dynamic truncation
    offset := hash[len(hash)-1] & 0x0f
    code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
    code = code % uint32(math.Pow10(digits))

    return fmt.Sprintf("%0*d", digits, code)
}
```

**时间窗口容错:**
- 当前时间窗口: `T₀ = Unix_Time / 30`
- 验证范围: `[T₀-1, T₀, T₀+1]` (覆盖 ±30 秒)
- 防止时钟偏移导致的验证失败

### 文件系统安全

```bash
~/.fssh/
├── config.json              # 权限: 0644 (全局配置)
├── auth_mode.json           # 权限: 0644 (认证模式标识)
├── agent.sock               # 权限: 0600 (Unix socket)
├── otp/
│   └── config.enc           # 权限: 0600 (仅当前用户读写)
└── keys/
    ├── myserver.enc         # 权限: 0600
    └── github.enc           # 权限: 0600
```

**安全措施:**
- 所有敏感文件权限设置为 `0600`
- 依赖 macOS FileVault 全盘加密保护静态数据
- 进程间通过 Unix socket 通信（权限控制）

---

## 安全性分析

### 威胁模型

#### 攻击场景矩阵

| 攻击场景 | 攻击者需要 | 防护措施 | 风险等级 |
|---------|-----------|---------|---------|
| **磁盘被盗** | 物理设备 | FileVault加密 + config.enc权限0600 | 🟢 低 |
| **配置文件泄露** | config.enc文件 | PBKDF2 100k迭代 + 强密码要求 | 🟡 中 |
| **密码泄露** | OTP密码 | 仍需TOTP验证码（30秒过期） | 🟡 中 |
| **验证码拦截** | 当前验证码 | 需要密码解锁seed | 🟢 低 |
| **seed + 验证码同时泄露** | 缓存的seed + 当前验证码 | 可在30秒内解密私钥 | 🔴 高 |
| **内存dump** | root权限 + TTL窗口 | 设置seed_unlock_ttl=0 | 🟡 中 |
| **离线暴力破解密码** | config.enc | PBKDF2减缓（~10秒/尝试） | 🟢 低 |
| **Keylogger** | 记录密码和验证码 | 物理安全/系统安全范畴 | 🔴 高 |

#### 防护层级

```
┌────────────────────────────────────────────────────────┐
│ L5: 物理安全                                            │
│   - 设备物理访问控制                                    │
│   - 防止 Keylogger/Screen capture                      │
└────────────────────────────────────────────────────────┘
                      ↓
┌────────────────────────────────────────────────────────┐
│ L4: 操作系统安全                                        │
│   - FileVault 全盘加密                                 │
│   - 文件系统权限 (0600)                                │
│   - 进程隔离和权限管理                                  │
└────────────────────────────────────────────────────────┘
                      ↓
┌────────────────────────────────────────────────────────┐
│ L3: 密码学保护                                          │
│   - PBKDF2 100k 迭代                                   │
│   - AES-256-GCM 认证加密                               │
│   - HKDF 密钥派生                                       │
└────────────────────────────────────────────────────────┘
                      ↓
┌────────────────────────────────────────────────────────┐
│ L2: 动态认证                                            │
│   - TOTP 30秒时效验证码                                │
│   - 时间窗口容错 (±30秒)                               │
└────────────────────────────────────────────────────────┘
                      ↓
┌────────────────────────────────────────────────────────┐
│ L1: 缓存管理                                            │
│   - TTL 时间限制                                        │
│   - 内存敏感数据清零                                    │
│   - 可配置缓存策略                                      │
└────────────────────────────────────────────────────────┘
```

### 密码学强度评估

#### PBKDF2 暴力破解时间估算

假设攻击者使用高端 GPU (NVIDIA RTX 4090):
- PBKDF2-SHA256 性能: ~100,000 次/秒
- 每次尝试时间: ~0.01 秒

| 密码强度 | 组合数 | 破解时间 (单GPU) |
|---------|-------|----------------|
| 8位纯数字 | 10⁸ | 16 分钟 |
| 8位字母+数字 | 62⁸ | 7,000 年 |
| 12位字母+数字 | 62¹² | 1.4×10⁹ 年 |
| 16位随机 | 62¹⁶ | 1.3×10¹⁸ 年 |

**推荐:**
- 最小长度: 12 位
- 组成: 大小写字母 + 数字 + 符号
- 使用密码管理器生成和存储

#### TOTP 安全性

- **时间窗口**: 30 秒
- **验证码空间**: 10⁶ (6位数字)
- **暴力破解概率**:
  - 单次尝试: 1/1,000,000
  - 3个窗口内: 3/1,000,000
- **限流保护**: 建议添加失败限流（未实现）

### 配置安全等级

#### 极致安全配置

```json
{
    "seed_unlock_ttl_seconds": 0,
    "unlock_ttl_seconds": 0,
    "require_auth_per_sign": true
}
```

**特点:**
- ✅ 内存中不缓存敏感数据
- ✅ 每次 SSH 都需要密码 + 验证码
- ❌ 用户体验差

**适用场景:** 高度敏感环境（金融、军事、关键基础设施）

#### 平衡配置（推荐）

```json
{
    "seed_unlock_ttl_seconds": 3600,
    "unlock_ttl_seconds": 600,
    "require_auth_per_sign": true
}
```

**特点:**
- ✅ 1小时输入1次密码
- ✅ 10分钟内免验证码
- ✅ 安全性和体验平衡

**适用场景:** 日常开发工作，企业环境

#### 便利配置

```json
{
    "seed_unlock_ttl_seconds": 86400,
    "unlock_ttl_seconds": 3600,
    "require_auth_per_sign": false
}
```

**特点:**
- ✅ 接近 Touch ID 体验
- ✅ Agent 启动时认证一次
- ⚠️ 24小时内 seed 保留在内存

**适用场景:** 个人开发环境，已启用 FileVault

### 恢复码机制

#### 生成和存储

```go
// 生成10个恢复码
func generateRecoveryCodes() []string {
    codes := make([]string, 10)
    for i := 0; i < 10; i++ {
        // 格式: XXXX-XXXX-XXXX-XXXX
        codes[i] = generateRandomAlphaNumeric(16, "-", 4)
    }
    return codes
}

// 存储 SHA-256 哈希
func storeRecoveryCodes(codes []string) []string {
    hashes := make([]string, len(codes))
    for i, code := range codes {
        hash := sha256.Sum256([]byte(code))
        hashes[i] = hex.EncodeToString(hash[:])
    }
    return hashes
}
```

#### 使用流程

```
用户: fssh otp-recover
  ↓
提示输入密码: ****************
  ↓
提示输入恢复码: A3F9-2K8H-9D4L-6M2P
  ↓
计算 SHA-256(recovery_code)
  ↓
对比 config.recovery_codes_hash
  ↓
验证成功 → 解锁 OTP seed
  ↓
标记该恢复码为已使用（从数组删除hash）
  ↓
提示剩余恢复码数量
```

**安全特性:**
- 每个恢复码仅可使用一次
- 存储哈希而非明文（防止泄露）
- 使用后立即失效

---

## 用户使用指南

### 快速开始

#### 1. 检查设备能力

```bash
$ fssh auth-status

认证能力检测
============
Touch ID: 不支持 ❌
建议使用: OTP 认证模式
```

#### 2. 初始化 OTP 模式

```bash
$ fssh init --mode otp

初始化 OTP 认证模式

请设置 OTP 密码（至少12位）: ****************
确认密码: ****************

正在生成 OTP seed...

请使用认证器应用扫描二维码：
┌────────────────────────────────────┐
│  ████ ▄▄▄▄ ██▀▀ ▄▄▄▄ ████          │
│  ... QR Code ...                    │
└────────────────────────────────────┘

或手动添加到 Google Authenticator / Authy:
  发行者: fssh
  账户: leo@MacBook-Pro
  密钥: JBSWY3DPEHPK3PXP
  类型: 基于时间
  算法: SHA1
  位数: 6
  间隔: 30秒

恢复码（请安全保存，打印或存入密码管理器）：
  1. A3F9-2K8H-9D4L-6M2P
  2. B7K3-9F2H-4L8D-3M9K
  3. C5M2-8K9H-3L6D-7P4F
  4. D8K6-3H2M-9L4D-5P8K
  5. E2P9-7K4H-6L3D-9M5K
  6. F9M3-5K8H-2L7D-4P6K
  7. G4K7-9H3M-8L2D-6P9K
  8. H8P2-4K6H-7L9D-3M8K
  9. J3M6-8K2H-5L4D-9P7K
 10. K7P4-2K9H-6L8D-3M5K

✓ OTP 认证已初始化
✓ OTP seed 解锁周期: 3600秒（1小时）
✓ 配置已保存到 ~/.fssh/otp/config.enc

⚠️  安全提示：
  1. 请启用 FileVault 全盘加密
  2. 建议在第二台设备也添加此 OTP（扫描相同二维码）
  3. 妥善保管恢复码，丢失无法找回

下一步：
  fssh import -alias myserver -file ~/.ssh/id_rsa
```

#### 3. 导入 SSH 私钥

```bash
$ fssh import -alias myserver -file ~/.ssh/id_rsa

请输入 OTP 密码: ****************
请输入6位验证码: 123456
✓ 验证成功

正在加密私钥...
✓ 私钥 'myserver' 已导入
```

#### 4. 启动 Agent

```bash
$ fssh agent

fssh SSH 认证代理
================

认证模式: OTP
Master key 缓存: 600秒

OTP 认证初始化
==============
请输入 OTP 密码: ****************
请输入6位验证码: 789012

✓ OTP seed 已解锁（缓存有效期: 3600秒）
✓ TOTP 验证成功
✓ Agent 已启动

[INFO] Socket: /Users/leo/.fssh/agent.sock
[INFO] 已加载 3 个私钥
[INFO] OTP seed 将在 2025-01-15 11:30:00 过期
```

#### 5. 使用 SSH

```bash
# 第一次连接（在 TTL 缓存期内）
$ ssh user@server
# 直接连接，无需输入

# TTL 过期后
$ ssh user@server2
请输入6位验证码: 456789
✓ 验证成功
[SSH 连接建立...]

# seed TTL 过期后
$ ssh user@server3
OTP seed 缓存已过期，需要重新解锁
请输入 OTP 密码: ****************
✓ OTP seed 已解锁

请输入6位验证码: 321654
✓ 验证成功
[SSH 连接建立...]
```

### 常用操作

#### 查看状态

```bash
$ fssh otp-status

OTP 认证配置
===========
认证模式: OTP
算法: SHA1
位数: 6
时间间隔: 30秒

缓存配置:
  OTP seed 解锁周期: 3600秒（1小时）
  Master key 缓存: 600秒（10分钟）

当前状态:
  OTP seed: 已解锁 ✓（剩余 2847秒）
  Master key: 已缓存 ✓（剩余 456秒）

安全检查:
  ✓ 配置文件权限: 0600
  ✗ FileVault 状态: 未启用（强烈建议启用）
  ✓ 剩余恢复码: 10个

配置文件: /Users/leo/.fssh/otp/config.enc
```

#### 修改配置

```bash
# 修改 seed 解锁周期为 2 小时
$ fssh otp-config --seed-unlock-ttl 7200
✓ OTP seed 解锁周期已更新为 7200秒（2小时）
✓ 请重启 agent 以应用更改

# 修改 master key 缓存时间
$ fssh otp-config --master-key-ttl 1800
✓ Master key 缓存已更新为 1800秒（30分钟）
```

#### 显示 OTP 设置

```bash
$ fssh otp-show

OTP 设置信息
===========

请扫描二维码添加到新设备：
┌────────────────────────────────────┐
│  ████ ▄▄▄▄ ██▀▀ ▄▄▄▄ ████          │
│  ... QR Code ...                    │
└────────────────────────────────────┘

手动添加信息：
  发行者: fssh
  账户: leo@MacBook-Pro
  密钥: JBSWY3DPEHPK3PXP
  类型: 基于时间
  算法: SHA1
  位数: 6
  间隔: 30秒

当前验证码: 789012 (剩余 18秒)

⚠️  警告: 请勿与他人分享此信息
```

#### 更改密码

```bash
$ fssh otp-change-password

更改 OTP 密码
============

请输入当前密码: ****************
请输入验证码: 123456
✓ 验证成功

请输入新密码（至少12位）: ****************
确认新密码: ****************

正在重新加密 OTP seed...
✓ 密码已更新
✓ OTP seed 已用新密码重新加密
✓ 配置已保存

建议重启 agent: pkill -f 'fssh agent' && fssh agent &
```

#### 清除缓存

```bash
$ fssh otp-lock

✓ 已清除 OTP seed 缓存
✓ 已清除 Master key 缓存
✓ 下次使用时需要重新输入密码和验证码
```

#### 恢复码管理

```bash
# 查看剩余恢复码数量
$ fssh otp-recovery-status
剩余恢复码: 8/10

# 重新生成恢复码（需验证）
$ fssh otp-recovery-regenerate

请输入 OTP 密码: ****************
请输入验证码: 123456
✓ 验证成功

新的恢复码（请重新保存）：
  1. M9K3-7H2P-4L6D-8K5M
  2. N2P8-5K4H-9L3D-6M7K
  ... (10个新恢复码)

⚠️  旧的恢复码已全部失效

# 使用恢复码登录
$ fssh otp-recover

OTP seed 恢复
============

无法生成 TOTP 验证码？使用恢复码登录。

请输入 OTP 密码: ****************
请输入恢复码: A3F9-2K8H-9D4L-6M2P

验证恢复码...
✓ 恢复码有效（该码已作废）
✓ OTP seed 已解锁

剩余恢复码: 9个
建议重新生成恢复码: fssh otp-recovery-regenerate
```

### 故障排除

#### 验证码总是错误

```bash
# 1. 检查系统时间
$ date
Tue Jan 15 10:30:45 CST 2025

# 2. 测试验证码
$ fssh otp-verify 123456
✗ 验证码错误

当前服务器时间: 2025-01-15 10:30:50
时间偏移: 0 秒

可能原因:
  - 认证器应用时间不同步
  - 认证器应用配置错误（算法、位数、间隔）
  - 手动输入密钥时出错

建议:
  1. 在认证器应用中重新扫描二维码: fssh otp-show
  2. 确保认证器应用时间与系统时间一致
  3. 尝试使用恢复码: fssh otp-recover
```

#### 忘记 OTP 密码

```bash
# 如果有恢复码，可以重置密码
$ fssh otp-reset-password

⚠️  此操作需要恢复码验证

请输入恢复码: A3F9-2K8H-9D4L-6M2P
✓ 恢复码验证成功

请输入新密码: ****************
确认新密码: ****************

✓ 密码已重置
✓ OTP seed 已用新密码重新加密

# 如果没有恢复码，只能重新初始化（会丢失现有私钥访问权限）
$ fssh init --mode otp --force
⚠️  警告: 此操作将删除现有 OTP 配置
⚠️  所有导入的私钥将无法解密
⚠️  请确保已备份私钥原始文件

确认重新初始化? (yes/no):
```

#### Agent 启动失败

```bash
$ fssh agent
错误: OTP 配置文件损坏

# 检查配置文件
$ cat ~/.fssh/otp/config.enc
{
  "version": "fssh-otp/v1",
  ... (检查 JSON 格式)
}

# 验证配置文件权限
$ ls -la ~/.fssh/otp/config.enc
-rw-------  1 leo  staff  1234 Jan 15 10:30 config.enc

# 如果配置损坏，尝试从备份恢复
$ fssh otp-import --input backup.enc
```

---

## 配置参考

### 全局配置文件 (`~/.fssh/config.json`)

```json
{
    "socket": "~/.fssh/agent.sock",
    "require_auth_per_sign": true,
    "unlock_ttl_seconds": 600,
    "log_level": "info",
    "log_format": "plain",
    "log_out": "",
    "log_err": ""
}
```

| 字段 | 类型 | 默认值 | 说明 |
|-----|------|-------|------|
| `socket` | string | `~/.fssh/agent.sock` | SSH agent socket 路径 |
| `require_auth_per_sign` | bool | `true` | 是否每次签名都需要认证 |
| `unlock_ttl_seconds` | int | `600` | Master key 缓存时间（秒） |
| `log_level` | string | `info` | 日志级别: debug/info/warn/error |
| `log_format` | string | `plain` | 日志格式: plain/json |
| `log_out` | string | `""` | 标准输出日志文件路径（空=stdout） |
| `log_err` | string | `""` | 错误输出日志文件路径（空=stderr） |

### OTP 配置文件 (`~/.fssh/otp/config.enc`)

详见 [数据结构](#数据结构) 章节。

### 配置预设方案

#### 极致安全

```json
{
    "require_auth_per_sign": true,
    "unlock_ttl_seconds": 0,
    "otp": {
        "seed_unlock_ttl_seconds": 0
    }
}
```

**特点:** 每次 SSH 都输入密码 + 验证码

#### 平衡配置（推荐）

```json
{
    "require_auth_per_sign": true,
    "unlock_ttl_seconds": 600,
    "otp": {
        "seed_unlock_ttl_seconds": 3600
    }
}
```

**特点:** 1小时输入1次密码，10分钟内免验证码

#### 便利优先

```json
{
    "require_auth_per_sign": false,
    "unlock_ttl_seconds": 3600,
    "otp": {
        "seed_unlock_ttl_seconds": 86400
    }
}
```

**特点:** Agent 启动时认证，24小时内无需重新认证

---

## 命令行接口

### 初始化和模式管理

```bash
# 初始化 OTP 模式
fssh init --mode otp [OPTIONS]
  --seed-unlock-ttl SECONDS   # OTP seed 解锁周期（默认 3600）
  --algorithm SHA1|SHA256     # TOTP 算法（默认 SHA1）
  --digits 6|8                # 验证码位数（默认 6）
  --period SECONDS            # TOTP 时间窗口（默认 30）

# 示例
fssh init --mode otp --seed-unlock-ttl 7200 --algorithm SHA256 --digits 8

# 查看认证模式和状态
fssh auth-status

# 切换认证模式
fssh switch-to-otp          # Touch ID → OTP
fssh switch-to-touchid      # OTP → Touch ID
```

### OTP 配置管理

```bash
# 查看 OTP 状态（含缓存状态）
fssh otp-status

# 显示 OTP 设置（QR 码和手动配置）
fssh otp-show

# 修改配置
fssh otp-config --seed-unlock-ttl SECONDS
fssh otp-config --algorithm SHA1|SHA256|SHA512
fssh otp-config --digits 6|8

# 更改密码
fssh otp-change-password

# 清除缓存（强制重新认证）
fssh otp-lock

# 测试验证码
fssh otp-verify CODE
```

### 恢复和备份

```bash
# 查看恢复码状态
fssh otp-recovery-status

# 显示恢复码（需验证）
fssh otp-recovery-show

# 重新生成恢复码（旧码失效）
fssh otp-recovery-regenerate

# 使用恢复码登录
fssh otp-recover

# 重置密码（使用恢复码）
fssh otp-reset-password

# 导出 OTP 配置（加密备份）
fssh otp-export --output backup.enc

# 导入 OTP 配置
fssh otp-import --input backup.enc
```

### Agent 管理

```bash
# 启动 agent
fssh agent [OPTIONS]
  --unlock-ttl-seconds SECONDS  # Master key 缓存时间

# 查看 agent 状态
fssh status

# 停止 agent
pkill -f 'fssh agent'

# 重启 agent
pkill -f 'fssh agent' && fssh agent &
```

---

## 实施计划

### 开发阶段

#### Phase 1: 核心功能（2-3天）

**目标:** 实现 OTP 模式的基本认证流程

- [ ] `internal/auth` 模块
  - [ ] `AuthProvider` 接口定义
  - [ ] `OTPProvider` 实现
  - [ ] `TouchIDProvider` 重构
  - [ ] 认证模式管理
- [ ] `internal/otp` 模块
  - [ ] TOTP 生成和验证
  - [ ] OTP 配置加载/保存
  - [ ] 密码和验证码输入提示
- [ ] `cmd/fssh` 命令
  - [ ] `init --mode otp`
  - [ ] `otp-status`
  - [ ] `otp-verify`
- [ ] 集成到 Agent
  - [ ] `server.go` 使用 `AuthProvider`
  - [ ] `secure_agent.go` 支持 OTP
  - [ ] seed 和 master key 缓存逻辑

**验收标准:**
```bash
fssh init --mode otp
fssh import -alias test -file ~/.ssh/id_rsa
fssh agent
ssh test@server  # 成功连接
```

#### Phase 2: 用户体验（1-2天）

**目标:** 完善用户交互和配置管理

- [ ] QR 码生成和显示
- [ ] 恢复码机制
  - [ ] 生成和存储
  - [ ] 验证和使用
  - [ ] 重新生成
- [ ] 配置管理命令
  - [ ] `otp-config`
  - [ ] `otp-change-password`
  - [ ] `otp-lock`
  - [ ] `otp-show`
- [ ] 错误提示优化
- [ ] 时间同步检查

**验收标准:**
```bash
fssh otp-show  # 显示 QR 码
fssh otp-recover  # 恢复码登录成功
fssh otp-config --seed-unlock-ttl 7200  # 配置修改成功
```

#### Phase 3: 高级特性（1-2天）

**目标:** 完善安全性和迁移功能

- [ ] Touch ID ↔ OTP 模式切换
  - [ ] `switch-to-otp`
  - [ ] `switch-to-touchid`
  - [ ] 私钥重新加密
- [ ] 配置导出/导入
  - [ ] `otp-export`
  - [ ] `otp-import`
  - [ ] 加密备份
- [ ] 安全检查
  - [ ] FileVault 状态检测
  - [ ] 配置文件权限检查
  - [ ] 密码强度验证
- [ ] 文档和示例

**验收标准:**
```bash
fssh switch-to-otp  # Touch ID → OTP 成功
fssh otp-export --output backup.enc  # 备份成功
fssh otp-import --input backup.enc  # 恢复成功
```

### 测试计划

#### 单元测试

- [ ] `internal/otp/totp_test.go`
  - TOTP 生成和验证
  - 时间窗口容错
  - 不同算法测试
- [ ] `internal/auth/otp_test.go`
  - seed 加密/解密
  - master key 派生
  - 缓存逻辑
- [ ] `internal/otp/recovery_test.go`
  - 恢复码生成
  - 恢复码验证

#### 集成测试

- [ ] OTP 初始化流程
- [ ] Agent 启动和认证
- [ ] SSH 连接（不同 TTL 配置）
- [ ] 模式切换
- [ ] 配置导出/导入

#### 兼容性测试

| 设备 | Touch ID | OTP | 测试结果 |
|-----|----------|-----|---------|
| MacBook Pro 2023 | ✅ | ✅ | |
| MacBook Pro 2015 | ❌ | ✅ | |
| Mac Mini 2023 | ❌ | ✅ | |
| macOS VM (Parallels) | ❌ | ✅ | |
| Hackintosh | ❌ | ✅ | |

#### 安全测试

- [ ] 配置文件权限验证
- [ ] 密码暴力破解测试（PBKDF2 性能）
- [ ] 内存泄漏检查（敏感数据清零）
- [ ] TOTP 时间同步测试

### 发布计划

#### v2.0-beta1
- Phase 1 核心功能
- 基本文档
- 内部测试

#### v2.0-beta2
- Phase 2 用户体验
- 完整文档
- 公开测试（邀请用户）

#### v2.0-rc1
- Phase 3 高级特性
- 修复 beta 阶段问题
- 性能优化

#### v2.0 正式版
- 完整功能
- 生产就绪
- 发布公告

---

## 附录

### A. 认证器应用推荐

| 应用 | 平台 | 备份 | 多设备同步 | 推荐度 |
|-----|------|-----|-----------|-------|
| Google Authenticator | iOS/Android | ✅ (云备份) | ✅ | ⭐⭐⭐⭐ |
| Authy | iOS/Android/Desktop | ✅ (云备份) | ✅ | ⭐⭐⭐⭐⭐ |
| 1Password | 多平台 | ✅ | ✅ | ⭐⭐⭐⭐⭐ |
| Microsoft Authenticator | iOS/Android | ✅ | ✅ | ⭐⭐⭐⭐ |
| FreeOTP | iOS/Android | ❌ | ❌ | ⭐⭐⭐ |

**推荐:** Authy（支持多设备同步且免费）

### B. 密码策略建议

**最小要求:**
- 长度: ≥12 位
- 组成: 大小写字母 + 数字

**推荐:**
- 长度: ≥16 位
- 组成: 大小写字母 + 数字 + 符号
- 使用密码管理器生成
- 不要使用个人信息（生日、姓名等）

**示例（使用 pwgen）:**
```bash
$ pwgen -s -y 16 1
aK9#mP2$xL7@qR4%
```

### C. FileVault 配置指南

```bash
# 检查 FileVault 状态
$ fdesetup status
FileVault is Off.

# 启用 FileVault（需要管理员权限）
$ sudo fdesetup enable
Enter the user name:leo
Enter the password for user 'leo':

A recovery key has been generated:
XXXX-XXXX-XXXX-XXXX-XXXX-XXXX

# 验证状态
$ fdesetup status
FileVault is On.
```

**或通过图形界面:**
1. 系统偏好设置 → 安全性与隐私
2. FileVault 标签页
3. 点击 "打开 FileVault"
4. 选择恢复方式（iCloud 或恢复密钥）
5. 重启加密

### D. 故障排除检查清单

问题：验证码总是错误
- [ ] 检查系统时间: `date`
- [ ] 检查认证器应用时间
- [ ] 验证 OTP 配置: `fssh otp-show`
- [ ] 重新扫描 QR 码
- [ ] 尝试使用恢复码

问题：忘记 OTP 密码
- [ ] 尝试使用恢复码重置: `fssh otp-reset-password`
- [ ] 如无恢复码，只能重新初始化（会丢失私钥访问权限）
- [ ] 从私钥原始文件重新导入

问题：Agent 启动失败
- [ ] 检查配置文件: `cat ~/.fssh/otp/config.enc`
- [ ] 检查文件权限: `ls -la ~/.fssh/otp/`
- [ ] 检查日志: `fssh agent --log-level debug`
- [ ] 尝试从备份恢复: `fssh otp-import`

问题：SSH 连接很慢
- [ ] 检查 TTL 配置（可能过短导致频繁认证）
- [ ] 增加 `unlock_ttl_seconds`
- [ ] 增加 `seed_unlock_ttl_seconds`
- [ ] 检查网络延迟（与 OTP 无关）

### E. 参考资料

- [RFC 4226: HOTP](https://datatracker.ietf.org/doc/html/rfc4226)
- [RFC 6238: TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
- [RFC 5869: HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## 版本历史

- **v4 (2025-01-15)**: 最终版 - 密码保护 OTP seed + 可配置缓存周期
- **v3 (2025-01-15)**: 仅使用 TOTP 验证码（已废弃）
- **v2 (2025-01-15)**: 密码 + TOTP 双重验证（已废弃）
- **v1 (2025-01-15)**: 初始设计 - OTP 作为 Touch ID 叠加（已废弃）

---

## 许可证

此文档遵循与 fssh 项目相同的许可证。
