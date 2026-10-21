> **注意 / Note:** 本文档是早期的设计与实现记录，部分内容（如 TOTP 密钥格式、恢复码、命令用法）已过时，请以 [README](../README_CN.md) 为准。
> This is an early design/implementation record and is partly outdated (TOTP secret format, recovery codes, commands); see the [README](../README.md).

# macOS Keychain 访问授权说明

## 为什么会出现弹框？

当您运行 `fssh init` 或 `fssh import` 等命令时，macOS 可能会弹出对话框：

```
「fssh 想要使用您存储在钥匙串中的机密信息」

[拒绝] [允许]
```

或者要求您输入 macOS 用户密码来授权。

## 这是什么？

这是 **macOS 的正常安全机制**，不是错误或异常。

### 为什么需要访问 Keychain？

fssh 使用 macOS Keychain（钥匙串）来安全存储加密主密钥（master key）：

1. **生成 Master Key**：`fssh init` 时生成 32 字节随机密钥
2. **存储到 Keychain**：Master key 存储在系统 Keychain 中，受 Touch ID/密码保护
3. **加密私钥**：导入的 SSH 私钥用 master key 加密后存储在 `~/.fssh/keys/`
4. **解密时验证**：使用私钥时，先用 Touch ID 从 Keychain 获取 master key

### 安全优势

相比直接存储密钥，使用 Keychain 的优势：

- ✅ **硬件保护**：利用 macOS 系统级安全机制
- ✅ **Touch ID 集成**：生物识别验证，更安全便捷
- ✅ **防止泄露**：即使文件系统被访问，master key 也受保护
- ✅ **系统审计**：macOS 记录 Keychain 访问日志

## 何时会弹出？

### 1. 首次运行 `fssh init`

**触发场景**：
```bash
fssh init
```

**弹框原因**：
- 应用首次尝试在 Keychain 中创建项目
- macOS 需要确认用户允许 `fssh` 访问 Keychain

**操作**：
- ✅ 点击「允许」
- 或输入 macOS 用户密码授权

### 2. 首次运行 `fssh import`

**触发场景**：
```bash
fssh import --alias mykey --file ~/.ssh/id_rsa
```

**弹框原因**：
- 需要从 Keychain 读取 master key 来加密新导入的私钥
- 如果之前授权过 `fssh`，可能不会再次提示

### 3. 首次使用 SSH 连接

**触发场景**：
```bash
ssh user@server
```

**弹框原因**：
- Agent 需要解锁 master key 来签名 SSH 认证请求
- Touch ID 模式下每次签名都可能触发（取决于 TTL 设置）

## 弹框类型

### 类型 1: 简单授权

```
fssh wants to access key "fssh" in your keychain.

[Deny] [Allow]
```

**处理**：直接点击 [Allow]

### 类型 2: 密码授权

```
fssh wants to access key "fssh" in your keychain.

To allow this, enter the password for keychain "login".

Password: [________]

[Deny] [Allow]
```

**处理**：
1. 输入您的 **macOS 用户密码**（登录密码）
2. 点击 [Allow]

### 类型 3: Touch ID 授权

某些情况下，macOS 会直接弹出 Touch ID 提示：

```
Touch ID to allow fssh to access your keychain
```

**处理**：触摸 Touch ID 传感器

## 授权记录

授权后，macOS 会记住您的选择：

- **应用级授权**：fssh 可以访问它创建的 Keychain 项目
- **持久化**：除非重装系统或删除 Keychain 项目，不需要重复授权
- **可撤销**：可以在「钥匙串访问」应用中管理授权

## 查看和管理授权

### 1. 打开「钥匙串访问」应用

```bash
open -a "Keychain Access"
```

或通过 Spotlight 搜索「钥匙串访问」。

### 2. 查找 fssh 项目

1. 在左侧选择「登录」钥匙串
2. 搜索「fssh」
3. 找到服务名为「fssh」的项目

### 3. 查看访问控制

1. 双击 fssh 项目
2. 切换到「访问控制」标签
3. 可以看到：
   - 允许访问的应用列表
   - 访问权限设置

### 4. 撤销授权（如需要）

如果要撤销 fssh 的访问权限：

1. 选中 fssh 项目
2. 点击「删除」或修改访问控制

**注意**：删除后需要重新运行 `fssh init`。

## 常见问题

### Q1: 每次 SSH 都要授权，太麻烦？

**原因**：使用了安全模式（`require_touch_id_per_sign: true`）

**解决方法**：

1. **调整 TTL**（推荐）：
   ```bash
   fssh agent --unlock-ttl-seconds 3600  # 1小时内不重复验证
   ```

2. **使用便捷模式**（降低安全性）：
   ```bash
   fssh agent --require-touch-id-per-sign=false
   ```

### Q2: 忘记点「允许」，点了「拒绝」怎么办？

**解决方法**：
- macOS 会记住「拒绝」选择
- 需要在「钥匙串访问」中删除拒绝记录
- 或重新运行 `fssh init --force`

### Q3: 弹框一直不出现，程序卡住？

**可能原因**：
1. macOS 权限系统异常
2. Keychain 数据库损坏

**解决方法**：
```bash
# 1. 重启钥匙串服务
killall SecurityAgent

# 2. 检查钥匙串完整性
security verify-cert

# 3. 重新初始化 fssh
fssh init --force
```

### Q4: 是否可以完全避免弹框？

**短回答**：不建议，这会降低安全性。

**技术方案**（仅供参考，不推荐）：
- 使用 OTP 模式代替 Touch ID 模式
- 但 OTP 模式仍需要访问 Keychain（存储 OTP seed）

## 技术细节

### Keychain 存储内容

fssh 在 Keychain 中存储的数据：

```
服务名称: fssh
账户名称: master_key_v1
数据类型: Generic Password
可访问性: When Unlocked
数据内容: 32 字节 AES-256 密钥
```

### 代码位置

相关代码在：
- `internal/keychain/keychain.go` - Keychain 操作
- `internal/macos/touchid_darwin.go` - Touch ID 集成
- `cmd/fssh/otp_init.go` - 初始化流程

### 访问控制策略

当前实现：
```go
it.SetAccessible(kc.AccessibleWhenUnlocked)
```

这意味着：
- macOS 解锁时可访问
- 锁屏后需要重新验证
- 最大化安全性

## 总结

macOS Keychain 弹框是：

✅ **正常的安全机制** - 保护您的私钥安全
✅ **一次性授权** - 授权后不会频繁打扰
✅ **可配置的** - 可调整 TTL 平衡安全性和便利性
✅ **可审计的** - 系统记录所有访问日志

**建议操作**：
- 首次使用时，放心点击「允许」
- 根据需要调整 TTL 设置
- 定期检查「钥匙串访问」中的授权记录

如有其他问题，请参考主文档或提交 Issue。
