> **注意 / Note:** 本文档是早期的设计与实现记录，部分内容（如 TOTP 密钥格式、恢复码、命令用法）已过时，请以 [README](../README_CN.md) 为准。
> This is an early design/implementation record and is partly outdated (TOTP secret format, recovery codes, commands); see the [README](../README.md).

# fssh OTP 认证快速开始指南

## 什么是 OTP 模式？

OTP（One-Time Password）模式为不支持 Touch ID 的 macOS 设备提供了一种安全的 SSH 私钥管理方案。它使用：

- **密码保护**: 使用用户设置的密码加密 OTP seed
- **TOTP 验证码**: 基于时间的一次性密码（如 Google Authenticator）
- **双层安全**: 密码 + 验证码双重认证

## 适用场景

- Mac Mini（无 Touch ID）
- 老款 MacBook（无 Touch ID）
- macOS 虚拟机
- Hackintosh
- 任何不支持 Touch ID 的设备

## 快速开始

### 1. 初始化 OTP 模式

```bash
$ ./fssh init --mode otp

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

请将以上信息添加到 TOTP 认证器应用（如 Google Authenticator, Authy）

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

⚠️  重要提示：
  - 每个恢复码仅可使用一次
  - 使用后该恢复码将立即失效
  - 请妥善保管，丢失无法找回

配置已保存到: /Users/leo/.fssh/otp/config.enc

⚠️  安全提示:
  1. 建议启用 FileVault 全盘加密
  2. 建议在第二台设备也添加此 OTP（记录密钥信息）
  3. 妥善保管恢复码，丢失无法找回

下一步:
  1. 导入 SSH 私钥: fssh import -alias myserver -file ~/.ssh/id_rsa
  2. 启动 agent: fssh agent
```

### 2. 添加 TOTP 到认证器应用

**推荐应用**:
- Google Authenticator (iOS/Android)
- Authy (iOS/Android/Desktop)
- 1Password (多平台)
- Microsoft Authenticator (iOS/Android)

**手动添加步骤**:
1. 打开认证器应用
2. 点击 "添加账户" 或 "+"
3. 选择 "手动输入" 或 "输入密钥"
4. 输入以下信息：
   - 账户名: `fssh`
   - 密钥: `JBSWY3DPEHPK3PXP` (初始化时显示的)
   - 类型: `基于时间`
   - 算法: `SHA1`
   - 位数: `6`
5. 保存

### 3. 导入 SSH 私钥

```bash
$ ./fssh import -alias myserver -file ~/.ssh/id_rsa

请输入 OTP 密码: ****************
请输入6位验证码: 123456
✓ 验证成功

正在加密私钥...
✓ 私钥 'myserver' 已导入
imported myserver fingerprint=SHA256:abc123...
```

### 4. 启动 Agent

```bash
$ ./fssh agent

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

### 5. 配置 SSH 客户端

在 `~/.ssh/config` 文件开头添加：

```
host *
  ServerAliveInterval 30
  AddKeysToAgent yes
  ControlPersist 60
  ControlMaster auto
  IdentityAgent  ~/.fssh/agent.sock
```

或者在 shell 配置中添加：

```bash
export SSH_AUTH_SOCK=~/.fssh/agent.sock
```

### 6. 使用 SSH

```bash
# 首次连接（在缓存期内，无需重新输入）
$ ssh user@server
[SSH 连接建立...]

# 缓存过期后
$ ssh user@server2
请输入6位验证码: 456789
✓ 验证成功
[SSH 连接建立...]

# seed 缓存过期后
$ ssh user@server3
OTP seed 缓存已过期，需要重新解锁
请输入 OTP 密码: ****************
✓ OTP seed 已解锁

请输入6位验证码: 321654
✓ 验证成功
[SSH 连接建立...]
```

## 高级配置

### 自定义 TTL（缓存时间）

```bash
# 初始化时设置 seed 缓存时间为 2 小时
$ ./fssh init --mode otp --seed-unlock-ttl 7200

# 启动 agent 时设置 master key 缓存时间为 30 分钟
$ ./fssh agent --unlock-ttl-seconds 1800
```

### 使用不同的 TOTP 算法

```bash
# 使用 SHA256 算法和 8 位验证码
$ ./fssh init --mode otp --algorithm SHA256 --digits 8
```

## 安全配置建议

### 极致安全（高度敏感环境）

```bash
# 不缓存任何数据，每次 SSH 都需要密码 + 验证码
$ ./fssh init --mode otp --seed-unlock-ttl 0
$ ./fssh agent --unlock-ttl-seconds 0
```

### 平衡配置（推荐，日常开发）

```bash
# 1小时输入1次密码，10分钟内免验证码
$ ./fssh init --mode otp --seed-unlock-ttl 3600
$ ./fssh agent --unlock-ttl-seconds 600
```

### 便利优先（个人开发环境）

```bash
# 24小时内 seed 保留，1小时内免验证码
$ ./fssh init --mode otp --seed-unlock-ttl 86400
$ ./fssh agent --unlock-ttl-seconds 3600
```

## 故障排除

### 验证码总是错误

**可能原因**:
1. 认证器应用时间不同步
2. 手动输入密钥时出错
3. 算法或位数配置不匹配

**解决方法**:
1. 确保认证器应用时间与系统时间一致
2. 重新添加 TOTP（重新初始化或查看密钥）
3. 使用恢复码登录（待实现）

### 忘记 OTP 密码

**如果有恢复码**:
```bash
$ ./fssh otp-reset-password  # 待实现
```

**如果没有恢复码**:
只能重新初始化（会丢失现有私钥访问权限）：
```bash
$ ./fssh init --mode otp --force
⚠️  警告: 此操作将删除现有 OTP 配置
⚠️  所有导入的私钥将无法解密
```

### Agent 启动失败

检查配置文件：
```bash
$ ls -la ~/.fssh/otp/config.enc
-rw-------  1 leo  staff  1234 Jan 15 10:30 config.enc

$ cat ~/.fssh/auth_mode.json
{
  "version": "fssh-auth/v1",
  "mode": "otp",
  "created_at": "2025-01-15T10:30:00Z"
}
```

## 安全提示

1. **启用 FileVault**: macOS 全盘加密保护配置文件
2. **使用强密码**: 至少 12 位，包含大小写字母、数字和符号
3. **备份恢复码**: 打印或存入密码管理器
4. **多设备配置**: 在第二台设备也添加 TOTP
5. **定期更换**: 定期更改 OTP 密码

## 与 Touch ID 的对比

| 特性 | Touch ID | OTP |
|-----|----------|-----|
| 设备要求 | 需 Touch ID 硬件 | 任意 Mac |
| 解锁方式 | 指纹 | 密码 + 验证码 |
| 安全性 | 硬件级 | 密码学级 |
| 跨设备迁移 | ❌ | ✅ (可导出) |
| 离线可用 | ✅ | ✅ |

## 更多帮助

- [OTP 认证方案设计文档](./otp-authentication.md)
- [软件设计文档 (SDD)](./otp-sdd.md)
- [实施总结](./otp-implementation-summary.md)

## 反馈

如有问题或建议，请提交 issue 到项目仓库。
