> **注意 / Note:** 本文档是早期的设计与实现记录，部分内容（如 TOTP 密钥格式、恢复码、命令用法）已过时，请以 [README](../README_CN.md) 为准。
> This is an early design/implementation record and is partly outdated (TOTP secret format, recovery codes, commands); see the [README](../README.md).

# OTP 认证功能实施总结

## 实施日期
2025-12-30

## 实施方式
基于 SDD (Software Design Document) 驱动的开发方法

## 完成状态
✅ **Phase 1 核心功能已完成并编译成功**

---

## 已完成的功能模块

### 1. 认证抽象层 (`internal/auth/`)

#### 文件列表
- `auth.go` - AuthProvider 接口定义和认证模式管理
- `touchid.go` - Touch ID 认证提供者实现
- `otp.go` - OTP 认证提供者实现

#### 核心接口
```go
type AuthProvider interface {
    UnlockMasterKey() ([]byte, error)  // 解锁 master key
    IsAvailable() bool                  // 检查认证可用性
    Mode() AuthMode                     // 返回认证模式
    ClearCache()                        // 清除缓存
}
```

#### 认证模式
- `ModeTouchID` - Touch ID 认证模式
- `ModeOTP` - OTP 认证模式

#### 关键功能
- `GetAuthProvider()` - 自动选择认证提供者
- `LoadMode()` / `SaveMode()` - 认证模式管理
- `auth_mode.json` - 认证模式配置文件

### 2. OTP 功能模块 (`internal/otp/`)

#### 文件列表
- `config.go` - OTP 配置数据结构和加载/保存
- `totp.go` - TOTP 算法实现（RFC 6238）
- `prompt.go` - 用户输入提示（密码/验证码）
- `init.go` - OTP 初始化功能
- `recovery.go` - 恢复码生成和管理

#### TOTP 实现
- **算法**: SHA1/SHA256/SHA512
- **验证码**: 6位或8位数字
- **时间窗口**: 30秒（可配置）
- **容错**: ±1 个时间窗口（±30秒）

#### 配置文件结构 (`~/.fssh/otp/config.enc`)
```json
{
    "version": "fssh-otp/v1",
    "algorithm": "SHA1",
    "digits": 6,
    "period": 30,
    "encrypted_seed": "base64...",
    "seed_salt": "base64...",
    "seed_nonce": "base64...",
    "master_key_salt": "base64...",
    "seed_unlock_ttl_seconds": 3600,
    "recovery_codes_hash": ["sha256..."],
    "created_at": "2025-01-15T10:30:00Z"
}
```

#### 密码学设计

**OTP Seed 加密**:
```
用户密码 → PBKDF2(100k 迭代) → 32字节密钥 → AES-256-GCM 加密 → encrypted_seed
```

**Master Key 派生**:
```
OTP seed + Master Key Salt → HKDF-SHA256 → 32字节 Master Key
```

### 3. Agent 集成 (`internal/agent/`)

#### 修改的文件
- `server.go` - 使用 AuthProvider，OTP 预热
- `secure_agent.go` - 支持 AuthProvider 接口

#### 关键改动
1. **server.go**
   - 添加 `GetAuthProvider()` 调用
   - OTP 模式启动时预热（`preUnlockOTP()`）
   - 便利模式使用 `provider.UnlockMasterKey()`

2. **secure_agent.go**
   - 移除旧的 `masterKey()` 方法
   - 移除 master key 缓存（由 AuthProvider 管理）
   - `Sign()` 和 `SignWithFlags()` 使用 `authProvider.UnlockMasterKey()`

### 4. 命令行集成 (`cmd/fssh/`)

#### 新增文件
- `otp_init.go` - OTP 初始化相关函数

#### 修改文件
- `main.go` - 添加 `--mode` 参数支持

#### 新增命令选项
```bash
fssh init --mode otp [OPTIONS]
  --seed-unlock-ttl SECONDS   # OTP seed 缓存时间（默认 3600）
  --algorithm SHA1|SHA256     # TOTP 算法（默认 SHA1）
  --digits 6|8                # 验证码位数（默认 6）
```

---

## 工作流程

### OTP 初始化流程

```
用户执行: fssh init --mode otp
    ↓
提示输入密码（两次确认）
    ↓
生成随机 OTP seed (20 字节)
    ↓
使用密码加密 seed (PBKDF2 + AES-256-GCM)
    ↓
生成 10 个恢复码
    ↓
保存配置到 ~/.fssh/otp/config.enc
    ↓
派生 master key (HKDF)
    ↓
保存 master key 到 Keychain
    ↓
保存认证模式到 auth_mode.json
    ↓
显示 TOTP 配置信息和恢复码
```

### Agent 启动流程（OTP 模式）

```
用户执行: fssh agent
    ↓
加载认证提供者 (OTPProvider)
    ↓
OTP 预热
    ├─ 提示输入密码
    ├─ 解密 OTP seed
    ├─ 提示输入验证码
    ├─ 验证 TOTP
    └─ 派生 master key
    ↓
创建 secure agent
    ↓
启动 Unix Socket 服务
```

### SSH 签名流程（OTP 模式）

```
SSH 客户端请求签名
    ↓
Agent 调用: authProvider.UnlockMasterKey()
    ↓
OTPProvider 检查缓存
    ├─ Master Key 缓存命中 → 直接返回
    ├─ Master Key 过期，seed 缓存命中
    │   ├─ 提示输入验证码
    │   ├─ 验证 TOTP
    │   └─ 派生 master key
    └─ Seed 缓存过期
        ├─ 提示输入密码
        ├─ 解密 seed
        ├─ 提示输入验证码
        └─ 派生 master key
    ↓
使用 master key 解密私钥
    ↓
执行 SSH 签名
```

---

## 文件系统结构

```
~/.fssh/
├── config.json              # 全局配置
├── auth_mode.json           # 认证模式标识（新增）
│   {
│     "version": "fssh-auth/v1",
│     "mode": "otp",
│     "created_at": "2025-01-15T10:30:00Z"
│   }
│
├── otp/                     # OTP 配置目录（新增）
│   └── config.enc           # OTP 配置文件（权限: 0600）
│
├── agent.sock               # Unix socket
└── keys/
    ├── myserver.enc         # 加密私钥
    └── github.enc
```

---

## 安全性特性

### 1. 双层认证架构
- **第一层**: 密码解锁 OTP seed（长期保护）
- **第二层**: TOTP 验证码（动态认证）

### 2. 密码学保护
- **PBKDF2**: 100,000 迭代（OWASP 2023 推荐）
- **AES-256-GCM**: 认证加密
- **HKDF-SHA256**: 密钥派生
- **Salt**: 所有密钥派生使用独立 salt

### 3. 缓存策略
- **OTP Seed 缓存**: 可配置 TTL（默认 3600 秒）
- **Master Key 缓存**: 可配置 TTL（默认 600 秒）
- **安全清零**: 使用 `runtime.KeepAlive` 防止编译器优化

### 4. 文件权限
- OTP 配置文件: `0600` (仅当前用户)
- OTP 目录: `0700` (仅当前用户)

### 5. 恢复机制
- 10 个一次性恢复码
- 存储 SHA-256 哈希（非明文）
- 使用后立即失效

---

## 兼容性

### 向后兼容
- ✅ 现有 Touch ID 用户不受影响
- ✅ 默认使用 Touch ID 模式（`--mode touchid`）
- ✅ 所有现有命令保持不变

### 设备支持
| 设备类型 | Touch ID | OTP |
|---------|----------|-----|
| MacBook Pro 2023 | ✅ | ✅ |
| MacBook Pro 2015 | ❌ | ✅ |
| Mac Mini | ❌ | ✅ |
| macOS VM | ❌ | ✅ |

---

## 测试状态

### 编译测试
- ✅ Go 编译成功
- ✅ 无编译错误
- ✅ 无编译警告

### 待完成测试
- ⏳ OTP 初始化流程测试
- ⏳ Agent 启动测试
- ⏳ SSH 连接测试
- ⏳ 缓存 TTL 测试
- ⏳ 恢复码测试

---

## 使用示例

### 初始化 OTP 模式
```bash
$ fssh init --mode otp
初始化 OTP 认证模式

请设置 OTP 密码（至少12位）: ****************
确认密码: ****************

OTP 认证已初始化
================

TOTP 配置:
  发行者: fssh
  账户: leo@MacBook-Pro
  密钥: JBSWY3DPEHPK3PXP
  算法: SHA1
  位数: 6
  间隔: 30秒

恢复码（请安全保存）：
  1. A3F9-2K8H-9D4L-6M2P
  2. B7K3-9F2H-4L8D-3M9K
  ...

配置已保存到: /Users/leo/.fssh/otp/config.enc
```

### 导入私钥（OTP 模式）
```bash
$ fssh import -alias myserver -file ~/.ssh/id_rsa
请输入 OTP 密码: ****************
请输入6位验证码: 123456
✓ 验证成功
imported myserver fingerprint=SHA256:...
```

### 启动 Agent（OTP 模式）
```bash
$ fssh agent

OTP 认证初始化
==============
请输入 OTP 密码: ****************
请输入6位验证码: 789012

✓ OTP 认证成功
✓ Agent 已启动
Socket: /Users/leo/.fssh/agent.sock

请设置环境变量:
  export SSH_AUTH_SOCK=/Users/leo/.fssh/agent.sock
```

---

## 下一步计划

### Phase 2: 用户体验增强（待实现）
- [ ] QR 码生成和显示
- [ ] `fssh otp-status` - 查看 OTP 状态
- [ ] `fssh otp-show` - 显示 OTP 设置
- [ ] `fssh otp-config` - 修改配置
- [ ] `fssh otp-change-password` - 更改密码
- [ ] `fssh otp-lock` - 清除缓存

### Phase 3: 恢复和备份（待实现）
- [ ] `fssh otp-recover` - 使用恢复码登录
- [ ] `fssh otp-recovery-status` - 查看恢复码状态
- [ ] `fssh otp-recovery-regenerate` - 重新生成恢复码
- [ ] `fssh otp-export` - 导出配置
- [ ] `fssh otp-import` - 导入配置

### Phase 4: 模式切换（待实现）
- [ ] `fssh switch-to-otp` - Touch ID → OTP
- [ ] `fssh switch-to-touchid` - OTP → Touch ID
- [ ] 私钥重新加密

### Phase 5: 测试和文档（待实现）
- [ ] 单元测试
- [ ] 集成测试
- [ ] 用户文档
- [ ] 故障排除指南

---

## 技术亮点

1. **接口驱动设计**: 使用 `AuthProvider` 接口统一认证抽象
2. **密码学最佳实践**: PBKDF2, AES-256-GCM, HKDF, SHA-256
3. **灵活的缓存策略**: 两级缓存（seed + master key）
4. **RFC 标准兼容**: TOTP (RFC 6238), HOTP (RFC 4226)
5. **安全的内存管理**: `runtime.KeepAlive` 防止优化
6. **最小侵入性**: 保持现有代码不变，通过接口扩展

---

## 参考文档

1. [OTP 认证方案设计文档](./otp-authentication.md) - 详细的需求和安全分析
2. [OTP 实施指南](./otp-implementation.md) - 代码实现细节
3. [软件设计文档 (SDD)](./otp-sdd.md) - 架构设计和实施计划

---

## 总结

通过 SDD 驱动的开发方式，我们成功实现了 fssh 的 OTP 认证功能。核心功能已完成并编译成功，包括：

- ✅ AuthProvider 接口抽象层
- ✅ OTPProvider 完整实现
- ✅ TOTP 算法（RFC 6238）
- ✅ 双层缓存机制
- ✅ 恢复码系统
- ✅ Agent 集成
- ✅ 命令行支持

这为不支持 Touch ID 的 macOS 设备提供了安全、灵活的 SSH 私钥管理方案。
