> **注意 / Note:** 本文档是早期的设计与实现记录，部分内容（如 TOTP 密钥格式、恢复码、命令用法）已过时，请以 [README](../README_CN.md) 为准。
> This is an early design/implementation record and is partly outdated (TOTP secret format, recovery codes, commands); see the [README](../README.md).

# OTP 认证功能 - 软件设计文档 (SDD)

## 文档信息
- **版本**: v1.0
- **创建日期**: 2025-12-30
- **项目**: fssh OTP 认证功能实现
- **设计方法**: SDD (Software Design Document)

---

## 1. 设计概述

### 1.1 目标
为 fssh 添加 OTP (One-Time Password) 认证模式，作为 Touch ID 的替代方案，支持不具备生物识别硬件的 macOS 设备。

### 1.2 核心特性
- **双层安全架构**: 密码保护 OTP seed + TOTP 动态验证码
- **灵活缓存策略**: 可配置 OTP seed 和 Master Key 的缓存周期
- **恢复码机制**: 防止丢失认证器时无法访问
- **与 Touch ID 并行**: 通过 AuthProvider 接口统一认证抽象

### 1.3 架构原则
- **接口优先**: 使用 AuthProvider 接口统一 Touch ID 和 OTP 两种认证方式
- **最小侵入**: 保持现有 Touch ID 代码不变，通过接口扩展
- **安全第一**: 遵循 OWASP 最佳实践，使用标准密码学算法
- **用户友好**: 提供清晰的命令行交互和错误提示

---

## 2. 系统架构

### 2.1 模块结构

```
fssh/
├── internal/
│   ├── auth/                    # 认证抽象层（新增）
│   │   ├── auth.go             # AuthProvider 接口定义
│   │   ├── touchid.go          # Touch ID 实现
│   │   ├── otp.go              # OTP 实现
│   │   └── mode.go             # 认证模式管理
│   │
│   ├── otp/                     # OTP 功能模块（新增）
│   │   ├── config.go           # 配置加载/保存
│   │   ├── totp.go             # TOTP 算法实现
│   │   ├── prompt.go           # 用户输入提示
│   │   ├── recovery.go         # 恢复码管理
│   │   └── qrcode.go           # QR 码生成
│   │
│   ├── agent/                   # Agent 服务（修改）
│   │   ├── server.go           # 使用 AuthProvider
│   │   └── secure_agent.go     # 支持 AuthProvider
│   │
│   ├── config/                  # 配置管理（修改）
│   │   └── config.go           # 添加 OTP 配置字段
│   │
│   └── [existing modules...]
│
└── cmd/fssh/                    # 命令行（修改）
    ├── main.go                 # 添加 OTP 命令
    ├── otp_commands.go         # OTP 命令实现（新增）
    └── mode_switch.go          # 模式切换（新增）
```

### 2.2 接口设计

#### 2.2.1 AuthProvider 接口

```go
type AuthProvider interface {
    // 解锁并返回 master key
    UnlockMasterKey() ([]byte, error)

    // 检查认证是否可用
    IsAvailable() bool

    // 获取认证模式
    Mode() AuthMode

    // 清除缓存
    ClearCache()
}
```

**设计理由**:
- 统一 Touch ID 和 OTP 两种认证方式的接口
- Agent 代码无需关心具体认证实现
- 易于未来扩展其他认证方式（如硬件令牌）

#### 2.2.2 认证模式类型

```go
type AuthMode string

const (
    ModeTouchID AuthMode = "touchid"
    ModeOTP     AuthMode = "otp"
)
```

### 2.3 数据流程

#### 2.3.1 Agent 启动流程

```
用户执行: fssh agent
    ↓
加载配置: config.Load()
    ↓
选择认证提供者: auth.GetAuthProvider()
    ├─ 读取 ~/.fssh/auth_mode.json
    ├─ 根据模式创建 TouchIDProvider 或 OTPProvider
    └─ 检查认证可用性
    ↓
OTP 模式预热（如适用）
    ├─ 提示输入密码
    ├─ 解密 OTP seed
    ├─ 提示输入验证码
    ├─ 验证 TOTP
    └─ 派生 Master Key
    ↓
创建 Agent (Secure 或 Convenience)
    ↓
启动 Unix Socket 服务
```

#### 2.3.2 SSH 签名流程

```
SSH 客户端请求签名
    ↓
Agent 调用: authProvider.UnlockMasterKey()
    ↓
OTPProvider 检查缓存
    ├─ Master Key 缓存命中 → 直接返回
    │
    ├─ Master Key 过期，OTP seed 缓存命中
    │   ├─ 提示输入验证码
    │   ├─ 验证 TOTP
    │   └─ 派生 Master Key
    │
    └─ OTP seed 缓存过期
        ├─ 提示输入密码
        ├─ 解密 OTP seed
        ├─ 提示输入验证码
        ├─ 验证 TOTP
        └─ 派生 Master Key
    ↓
使用 Master Key 解密私钥
    ↓
执行 SSH 签名
```

---

## 3. 核心模块详细设计

### 3.1 OTP 配置模块 (internal/otp/config.go)

#### 3.1.1 数据结构

```go
type Config struct {
    Version              string   `json:"version"`
    Algorithm            string   `json:"algorithm"`           // SHA1/SHA256/SHA512
    Digits               int      `json:"digits"`              // 6 或 8
    Period               int      `json:"period"`              // 30 秒
    EncryptedSeed        string   `json:"encrypted_seed"`      // Base64
    SeedSalt             string   `json:"seed_salt"`           // Base64, 32 bytes
    SeedNonce            string   `json:"seed_nonce"`          // Base64, 12 bytes
    MasterKeySalt        string   `json:"master_key_salt"`     // Base64, 32 bytes
    SeedUnlockTTLSeconds int      `json:"seed_unlock_ttl_seconds"`
    RecoveryCodesHash    []string `json:"recovery_codes_hash"` // SHA-256 hashes
    CreatedAt            string   `json:"created_at"`
}
```

#### 3.1.2 关键函数

```go
// 加载配置
func LoadConfig(path string) (*Config, error)

// 保存配置
func SaveConfig(cfg *Config) error

// 更新配置
func UpdateConfig(updateFn func(*Config) error) error

// 配置文件路径
func ConfigPath() string  // ~/.fssh/otp/config.enc
```

### 3.2 TOTP 实现 (internal/otp/totp.go)

#### 3.2.1 核心算法

```go
// 验证 TOTP 验证码（±1 时间窗口容错）
func Verify(seed []byte, userCode string, algorithm string, digits int, period int) bool {
    now := time.Now().Unix()
    counter := now / int64(period)

    // 允许 ±1 个时间窗口（±30秒容错）
    for offset := int64(-1); offset <= 1; offset++ {
        expected := Generate(seed, counter+offset, algorithm, digits)
        if userCode == expected {
            return true
        }
    }
    return false
}

// 生成 TOTP 验证码（HOTP 算法 + 时间戳）
func Generate(seed []byte, counter int64, algorithm string, digits int) string {
    // HMAC-SHA(seed, counter)
    // Dynamic truncation
    // 返回 digits 位数字
}
```

#### 3.2.2 时间窗口容错

- 当前时间窗口: `T₀ = Unix_Time / 30`
- 验证范围: `[T₀-1, T₀, T₀+1]` (覆盖 ±30 秒)
- 防止时钟偏移导致的验证失败

### 3.3 OTP Provider (internal/auth/otp.go)

#### 3.3.1 状态管理

```go
type OTPProvider struct {
    configPath string
    config     *otp.Config

    // OTP seed 缓存
    mu         sync.Mutex
    cachedSeed []byte
    seedExpiry time.Time

    // Master key 缓存
    cachedMasterKey []byte
    masterKeyExpiry time.Time
    masterKeyTTL    int
}
```

#### 3.3.2 关键方法

```go
// 解锁 OTP seed（私有方法）
func (p *OTPProvider) unlockSeed() ([]byte, error) {
    // 1. 检查缓存
    // 2. 提示输入密码
    // 3. PBKDF2 派生解密密钥
    // 4. AES-256-GCM 解密 seed
    // 5. 更新缓存
}

// 实现 AuthProvider 接口
func (p *OTPProvider) UnlockMasterKey() ([]byte, error) {
    // 1. 检查 master key 缓存
    // 2. 解锁 seed（可能使用缓存）
    // 3. 提示输入验证码
    // 4. 验证 TOTP
    // 5. HKDF 派生 master key
    // 6. 缓存 master key
}

func (p *OTPProvider) ClearCache() {
    // 安全清零内存中的敏感数据
}
```

### 3.4 密码学设计

#### 3.4.1 OTP Seed 加密

```
用户密码 (string)
  ↓
PBKDF2-HMAC-SHA256(password, salt, 100000 iterations) → 32字节解密密钥
  ↓
AES-256-GCM.Encrypt(解密密钥, nonce, OTP_seed, AAD=nil) → 密文
  ↓
Base64编码 → 存储到 config.enc
```

**安全参数**:
- PBKDF2 迭代次数: 100,000 (OWASP 2023 推荐)
- Salt 长度: 32 字节
- Nonce 长度: 12 字节 (GCM 标准)

#### 3.4.2 Master Key 派生

```
OTP seed (20字节) + Master Key Salt (32字节)
  ↓
HKDF-SHA256(seed, salt, info="fssh-master-key-v1", length=32)
  ↓
32字节 Master Key
```

**设计理由**:
- HKDF 提供标准的密钥派生方法
- 独立的 salt 确保不同实例的 master key 不同
- info 参数防止不同用途的密钥混淆

#### 3.4.3 恢复码

```
生成: 随机生成 16 字符（XXXX-XXXX-XXXX-XXXX）
存储: SHA-256(recovery_code) → hex string
验证: 比较 SHA-256(用户输入) 与存储的哈希
```

---

## 4. 命令行接口设计

### 4.1 初始化命令

```bash
fssh init --mode otp [OPTIONS]
  --seed-unlock-ttl SECONDS   # OTP seed 解锁周期（默认 3600）
  --algorithm SHA1|SHA256     # TOTP 算法（默认 SHA1）
  --digits 6|8                # 验证码位数（默认 6）
```

**执行流程**:
1. 检查是否已存在 master key
2. 提示设置 OTP 密码（至少12位）
3. 生成随机 OTP seed (20 字节)
4. 使用密码加密 seed
5. 生成 10 个恢复码
6. 显示 QR 码和手动配置信息
7. 保存配置到 ~/.fssh/otp/config.enc

### 4.2 Agent 命令（修改）

```bash
fssh agent [OPTIONS]
  --socket PATH                # Unix socket 路径
  --require-auth-per-sign      # 每次签名需要认证
  --unlock-ttl-seconds SECONDS # Master key 缓存时间
```

**OTP 模式特殊行为**:
- Agent 启动时预先解锁（提示密码 + 验证码）
- 后续根据 TTL 配置决定是否需要重新认证

### 4.3 OTP 管理命令（新增）

```bash
# 查看 OTP 状态
fssh otp-status

# 显示 OTP 设置（QR 码）
fssh otp-show

# 修改配置
fssh otp-config --seed-unlock-ttl SECONDS

# 更改密码
fssh otp-change-password

# 清除缓存
fssh otp-lock

# 测试验证码
fssh otp-verify CODE

# 恢复码管理
fssh otp-recovery-status
fssh otp-recovery-regenerate

# 使用恢复码登录
fssh otp-recover

# 模式切换
fssh switch-to-otp
fssh switch-to-touchid
```

---

## 5. 文件系统设计

### 5.1 目录结构

```
~/.fssh/
├── config.json              # 全局配置（权限: 0644）
├── auth_mode.json           # 认证模式标识（权限: 0644）
├── agent.sock               # Unix socket（权限: 0600）
├── otp/
│   └── config.enc           # OTP 配置（权限: 0600）
└── keys/
    ├── myserver.enc         # 加密私钥（权限: 0600）
    └── github.enc
```

### 5.2 auth_mode.json 格式

```json
{
    "version": "fssh-auth/v1",
    "mode": "otp",
    "created_at": "2025-01-15T10:30:00Z"
}
```

### 5.3 文件权限

- 配置文件: 0600 (仅当前用户读写)
- 目录: 0700 (仅当前用户访问)
- 依赖 macOS FileVault 全盘加密保护静态数据

---

## 6. 安全性分析

### 6.1 威胁模型

| 攻击场景 | 攻击者需要 | 防护措施 | 风险等级 |
|---------|-----------|---------|---------|
| 磁盘被盗 | 物理设备 | FileVault加密 + config.enc权限0600 | 🟢 低 |
| 配置文件泄露 | config.enc文件 | PBKDF2 100k迭代 + 强密码 | 🟡 中 |
| 密码泄露 | OTP密码 | 仍需TOTP验证码（30秒过期） | 🟡 中 |
| 验证码拦截 | 当前验证码 | 需要密码解锁seed | 🟢 低 |
| 内存dump | root权限 + TTL窗口 | 设置seed_unlock_ttl=0 | 🟡 中 |

### 6.2 缓存策略配置

#### 极致安全配置
```json
{
    "seed_unlock_ttl_seconds": 0,
    "unlock_ttl_seconds": 0,
    "require_auth_per_sign": true
}
```
- 每次 SSH 都需要密码 + 验证码
- 内存中不缓存敏感数据

#### 平衡配置（推荐）
```json
{
    "seed_unlock_ttl_seconds": 3600,
    "unlock_ttl_seconds": 600,
    "require_auth_per_sign": true
}
```
- 1小时输入1次密码
- 10分钟内免验证码

#### 便利配置
```json
{
    "seed_unlock_ttl_seconds": 86400,
    "unlock_ttl_seconds": 3600,
    "require_auth_per_sign": false
}
```
- 接近 Touch ID 体验
- 24小时内 seed 保留在内存

---

## 7. 实施计划

### Phase 1: 核心模块结构（当前任务）
**目标**: 创建基础目录和接口定义
- [ ] 创建 internal/auth/ 目录
- [ ] 创建 internal/otp/ 目录
- [ ] 定义 AuthProvider 接口
- [ ] 定义 OTP 数据结构

### Phase 2: OTP 核心功能
**目标**: 实现 TOTP 和配置管理
- [ ] 实现 TOTP 算法
- [ ] 实现 OTP 配置加载/保存
- [ ] 实现用户输入提示
- [ ] 单元测试

### Phase 3: 认证提供者实现
**目标**: 实现 AuthProvider 接口
- [ ] 重构 Touch ID 为 TouchIDProvider
- [ ] 实现 OTPProvider
- [ ] 实现认证模式管理
- [ ] 集成测试

### Phase 4: Agent 集成
**目标**: 修改 Agent 使用 AuthProvider
- [ ] 修改 server.go 使用接口
- [ ] 修改 secure_agent.go
- [ ] 修改 config.go 添加 OTP 字段
- [ ] 端到端测试

### Phase 5: 用户交互功能
**目标**: 实现完整的用户体验
- [ ] QR 码生成
- [ ] 恢复码管理
- [ ] OTP 管理命令
- [ ] 模式切换命令

### Phase 6: 测试和文档
**目标**: 确保质量和可维护性
- [ ] 完整的单元测试
- [ ] 集成测试
- [ ] 用户文档
- [ ] API 文档

---

## 8. 依赖管理

### 8.1 新增依赖

```go
require (
    github.com/pquerna/otp v1.4.0              // TOTP 实现
    github.com/skip2/go-qrcode v0.0.0-20200617 // QR 码生成
    golang.org/x/crypto v0.x.x                 // PBKDF2, HKDF
    golang.org/x/term v0.x.x                   // 密码输入
)
```

### 8.2 现有依赖

- golang.org/x/crypto/ssh (SSH agent 协议)
- 其他现有依赖保持不变

---

## 9. 测试策略

### 9.1 单元测试
- TOTP 生成和验证（RFC 6238 测试向量）
- OTP seed 加密/解密
- Master key 派生
- 恢复码生成和验证

### 9.2 集成测试
- OTP 初始化流程
- Agent 启动和认证
- SSH 连接（不同 TTL 配置）
- 模式切换

### 9.3 兼容性测试
- MacBook Pro 2023 (Touch ID + OTP)
- MacBook Pro 2015 (仅 OTP)
- Mac Mini 2023 (仅 OTP)
- macOS 虚拟机 (仅 OTP)

---

## 10. 性能考虑

### 10.1 PBKDF2 性能

- 100,000 迭代约 100ms（现代 CPU）
- 仅在密码输入时执行
- 可接受的用户体验

### 10.2 缓存优化

- OTP seed 缓存减少密码输入频率
- Master key 缓存减少验证码输入频率
- TTL 可配置，平衡安全性和便利性

### 10.3 内存管理

- 使用 `runtime.KeepAlive` 防止编译器优化
- 敏感数据清零后释放
- 使用 `sync.Mutex` 保护并发访问

---

## 11. 向后兼容性

### 11.1 现有 Touch ID 用户

- 不受影响，继续使用 Touch ID
- 可选择切换到 OTP 模式
- 切换时需要重新加密私钥

### 11.2 配置文件

- 保持现有 config.json 格式
- 添加可选的 OTP 配置
- 默认行为不变

### 11.3 命令行接口

- 现有命令保持不变
- 新增 OTP 相关命令
- `fssh init` 支持 `--mode` 参数

---

## 12. 错误处理

### 12.1 常见错误场景

| 错误 | 原因 | 处理方式 |
|-----|------|---------|
| 密码错误 | 用户输入错误 | 提示重试，3次失败后退出 |
| 验证码错误 | 时间不同步或输入错误 | 提示检查时间，支持恢复码 |
| 配置文件损坏 | 文件被修改 | 提示从备份恢复或重新初始化 |
| OTP seed 解密失败 | 密码错误 | 提示使用恢复码 |
| Touch ID 不可用 | 设备不支持 | 提示切换到 OTP 模式 |

### 12.2 错误消息设计

- 清晰说明错误原因
- 提供具体的解决方案
- 避免暴露敏感信息

---

## 13. 未来扩展

### 13.1 可能的增强

- 支持 FIDO2/WebAuthn 硬件令牌
- 支持多个恢复码设备
- 支持密码策略配置
- 支持失败限流
- 支持审计日志

### 13.2 架构预留

- AuthProvider 接口支持扩展
- 配置文件版本控制
- 模块化设计便于添加新功能

---

## 14. 总结

本设计文档详细描述了 fssh OTP 认证功能的实现方案，包括：

1. **架构设计**: 使用 AuthProvider 接口统一认证抽象
2. **安全设计**: 遵循 OWASP 最佳实践，双层安全架构
3. **用户体验**: 灵活的缓存策略，清晰的命令行交互
4. **实施计划**: 分 6 个阶段逐步实现
5. **测试策略**: 完整的单元测试、集成测试和兼容性测试

通过 SDD 驱动的开发方式，确保代码实现与设计保持一致，降低开发风险，提高代码质量。
