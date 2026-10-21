> **注意 / Note:** 本文档是早期的设计与实现记录，部分内容（如 TOTP 密钥格式、恢复码、命令用法）已过时，请以 [README](../README_CN.md) 为准。
> This is an early design/implementation record and is partly outdated (TOTP secret format, recovery codes, commands); see the [README](../README.md).

# OTP 认证实施指南

## 目录
1. [代码结构](#代码结构)
2. [核心模块实现](#核心模块实现)
3. [集成步骤](#集成步骤)
4. [测试用例](#测试用例)
5. [性能优化](#性能优化)

---

## 代码结构

### 新增文件

```
internal/
├── auth/
│   ├── auth.go              # AuthProvider 接口定义
│   ├── touchid.go           # Touch ID 认证实现
│   ├── otp.go               # OTP 认证实现
│   └── mode.go              # 认证模式管理
│
├── otp/
│   ├── config.go            # OTP 配置加载/保存
│   ├── totp.go              # TOTP 生成/验证
│   ├── prompt.go            # 用户交互（密码/验证码输入）
│   ├── recovery.go          # 恢复码管理
│   └── qrcode.go            # QR 码生成
│
└── macos/
    └── filevault.go         # FileVault 状态检测

cmd/fssh/
├── main.go                  # 添加 OTP 相关命令
├── otp_commands.go          # OTP 命令实现（新增）
└── mode_switch.go           # 模式切换命令（新增）
```

### 修改文件

```
internal/agent/server.go     # 使用 AuthProvider 接口
internal/agent/secure_agent.go  # 支持 OTP 缓存
internal/config/config.go    # 添加 OTP 配置字段
```

---

## 核心模块实现

### 1. AuthProvider 接口

```go
// internal/auth/auth.go
package auth

type AuthMode string

const (
    ModeTouchID AuthMode = "touchid"
    ModeOTP     AuthMode = "otp"
)

// AuthProvider 统一认证接口
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

// GetAuthProvider 自动选择认证提供者
func GetAuthProvider(masterKeyTTL int) (AuthProvider, error) {
    mode, err := LoadMode()
    if err != nil {
        return nil, err
    }

    switch mode {
    case ModeTouchID:
        provider := NewTouchIDProvider()
        if !provider.IsAvailable() {
            return nil, fmt.Errorf("Touch ID 不可用，请运行: fssh switch-to-otp")
        }
        return provider, nil

    case ModeOTP:
        provider, err := NewOTPProvider(masterKeyTTL)
        if err != nil {
            return nil, fmt.Errorf("OTP 初始化失败: %w", err)
        }
        if !provider.IsAvailable() {
            return nil, fmt.Errorf("OTP 未配置，请运行: fssh init --mode otp")
        }
        return provider, nil

    default:
        return nil, fmt.Errorf("未知认证模式: %s", mode)
    }
}

// LoadMode 加载当前认证模式
func LoadMode() (AuthMode, error) {
    path := filepath.Join(os.Getenv("HOME"), ".fssh", "auth_mode.json")

    data, err := os.ReadFile(path)
    if err != nil {
        // 默认检测 Keychain
        exists, _ := keychain.MasterKeyExists()
        if exists {
            return ModeTouchID, nil
        }
        return ModeOTP, nil
    }

    var cfg struct {
        Mode AuthMode `json:"mode"`
    }
    if err := json.Unmarshal(data, &cfg); err != nil {
        return "", err
    }

    return cfg.Mode, nil
}

// SaveMode 保存认证模式
func SaveMode(mode AuthMode) error {
    path := filepath.Join(os.Getenv("HOME"), ".fssh", "auth_mode.json")

    cfg := map[string]interface{}{
        "version":    "fssh-auth/v1",
        "mode":       mode,
        "created_at": time.Now().Format(time.RFC3339),
    }

    data, err := json.MarshalIndent(cfg, "", "  ")
    if err != nil {
        return err
    }

    return os.WriteFile(path, data, 0644)
}
```

### 2. OTP Provider 实现

```go
// internal/auth/otp.go
package auth

import (
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "sync"
    "time"

    "fssh/internal/crypt"
    "fssh/internal/log"
    "fssh/internal/otp"
    "golang.org/x/crypto/pbkdf2"
)

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

func NewOTPProvider(masterKeyTTL int) (*OTPProvider, error) {
    path := otp.ConfigPath()
    cfg, err := otp.LoadConfig(path)
    if err != nil {
        return nil, err
    }

    return &OTPProvider{
        configPath:   path,
        config:       cfg,
        masterKeyTTL: masterKeyTTL,
    }, nil
}

// unlockSeed 解锁 OTP seed（核心方法）
func (p *OTPProvider) unlockSeed() ([]byte, error) {
    p.mu.Lock()
    defer p.mu.Unlock()

    // 检查缓存
    ttl := p.config.SeedUnlockTTLSeconds
    if ttl > 0 && time.Now().Before(p.seedExpiry) {
        log.Debug("使用缓存的 OTP seed")
        return p.cachedSeed, nil
    }

    // 缓存过期，需要重新解锁
    log.Info("OTP seed 缓存已过期，需要重新解锁")

    // 1. 提示输入密码
    password, err := otp.PromptPassword("请输入 OTP 密码: ")
    if err != nil {
        return nil, err
    }

    // 2. 解码加密参数
    seedSalt, _ := base64.StdEncoding.DecodeString(p.config.SeedSalt)
    seedNonce, _ := base64.StdEncoding.DecodeString(p.config.SeedNonce)
    encryptedSeed, _ := base64.StdEncoding.DecodeString(p.config.EncryptedSeed)

    // 3. 派生解密密钥（PBKDF2）
    encKey := pbkdf2.Key([]byte(password), seedSalt, 100000, 32, sha256.New)

    // 4. 解密 OTP seed
    seed, err := crypt.DecryptAEAD(encKey, seedNonce, encryptedSeed, nil)
    if err != nil {
        return nil, fmt.Errorf("密码错误")
    }

    // 5. 更新缓存
    p.cachedSeed = seed
    if ttl > 0 {
        p.seedExpiry = time.Now().Add(time.Duration(ttl) * time.Second)
        log.Infof("OTP seed 已解锁，缓存有效期: %d秒", ttl)
    } else {
        p.seedExpiry = time.Now()
        log.Info("OTP seed 已解锁（无缓存）")
    }

    return seed, nil
}

// UnlockMasterKey 实现 AuthProvider 接口
func (p *OTPProvider) UnlockMasterKey() ([]byte, error) {
    // 检查 master key 缓存
    p.mu.Lock()
    if p.masterKeyTTL > 0 && time.Now().Before(p.masterKeyExpiry) {
        mk := p.cachedMasterKey
        p.mu.Unlock()
        log.Debug("使用缓存的 master key")
        return mk, nil
    }
    p.mu.Unlock()

    // 1. 解锁 OTP seed（可能使用缓存）
    seed, err := p.unlockSeed()
    if err != nil {
        return nil, err
    }

    // 2. 提示输入 TOTP 验证码
    code, err := otp.PromptCode("请输入6位验证码: ")
    if err != nil {
        return nil, err
    }

    // 3. 验证 TOTP
    if !otp.Verify(seed, code, p.config.Algorithm, p.config.Digits, p.config.Period) {
        return nil, fmt.Errorf("验证码错误或已过期")
    }

    log.Info("TOTP 验证成功")

    // 4. 从 seed 派生 master key
    masterKeySalt, _ := base64.StdEncoding.DecodeString(p.config.MasterKeySalt)
    masterKey := crypt.HKDF(seed, masterKeySalt, []byte("fssh-master-key-v1"), 32)

    // 5. 缓存 master key
    p.mu.Lock()
    if p.masterKeyTTL > 0 {
        p.cachedMasterKey = masterKey
        p.masterKeyExpiry = time.Now().Add(time.Duration(p.masterKeyTTL) * time.Second)
        log.Infof("Master key 已缓存，有效期: %d秒", p.masterKeyTTL)
    }
    p.mu.Unlock()

    return masterKey, nil
}

func (p *OTPProvider) IsAvailable() bool {
    return p.config != nil
}

func (p *OTPProvider) Mode() AuthMode {
    return ModeOTP
}

func (p *OTPProvider) ClearCache() {
    p.mu.Lock()
    defer p.mu.Unlock()

    // 清零敏感数据
    if p.cachedSeed != nil {
        for i := range p.cachedSeed {
            p.cachedSeed[i] = 0
        }
        p.cachedSeed = nil
    }

    if p.cachedMasterKey != nil {
        for i := range p.cachedMasterKey {
            p.cachedMasterKey[i] = 0
        }
        p.cachedMasterKey = nil
    }

    p.seedExpiry = time.Time{}
    p.masterKeyExpiry = time.Time{}

    log.Info("已清除 OTP 缓存")
}
```

### 3. TOTP 实现

```go
// internal/otp/totp.go
package otp

import (
    "crypto/hmac"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/binary"
    "fmt"
    "hash"
    "math"
    "time"
)

// Verify 验证 TOTP 验证码
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

// Generate 生成 TOTP 验证码
func Generate(seed []byte, counter int64, algorithm string, digits int) string {
    // 选择 HMAC 算法
    var h func() hash.Hash
    switch algorithm {
    case "SHA1":
        h = sha1.New
    case "SHA256":
        h = sha256.New
    case "SHA512":
        h = sha512.New
    default:
        h = sha1.New
    }

    // HOTP 算法（RFC 4226）
    mac := hmac.New(h, seed)
    binary.Write(mac, binary.BigEndian, counter)
    hs := mac.Sum(nil)

    // Dynamic truncation
    offset := hs[len(hs)-1] & 0x0f
    code := binary.BigEndian.Uint32(hs[offset:offset+4]) & 0x7fffffff
    code = code % uint32(math.Pow10(digits))

    return fmt.Sprintf("%0*d", digits, code)
}

// GetCurrentCode 获取当前验证码（用于调试）
func GetCurrentCode(seed []byte, algorithm string, digits int, period int) string {
    counter := time.Now().Unix() / int64(period)
    return Generate(seed, counter, algorithm, digits)
}

// GetTimeRemaining 获取当前验证码剩余有效时间（秒）
func GetTimeRemaining(period int) int {
    now := time.Now().Unix()
    return period - int(now%int64(period))
}
```

### 4. 用户交互

```go
// internal/otp/prompt.go
package otp

import (
    "bufio"
    "fmt"
    "os"
    "strings"

    "golang.org/x/term"
)

// PromptPassword 安全地提示输入密码（不回显）
func PromptPassword(prompt string) (string, error) {
    fmt.Print(prompt)
    password, err := term.ReadPassword(int(os.Stdin.Fd()))
    fmt.Println()
    if err != nil {
        return "", err
    }

    return string(password), nil
}

// PromptCode 提示输入 TOTP 验证码
func PromptCode(prompt string) (string, error) {
    fmt.Print(prompt)

    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    code := strings.TrimSpace(scanner.Text())

    if err := scanner.Err(); err != nil {
        return "", err
    }

    // 验证格式（6或8位数字）
    if len(code) != 6 && len(code) != 8 {
        return "", fmt.Errorf("验证码必须是6位或8位数字")
    }

    for _, c := range code {
        if c < '0' || c > '9' {
            return "", fmt.Errorf("验证码只能包含数字")
        }
    }

    return code, nil
}

// PromptConfirm 提示用户确认（y/n）
func PromptConfirm(prompt string) bool {
    fmt.Printf("%s (y/n): ", prompt)

    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    answer := strings.ToLower(strings.TrimSpace(scanner.Text()))

    return answer == "y" || answer == "yes"
}
```

### 5. OTP 配置管理

```go
// internal/otp/config.go
package otp

import (
    "encoding/json"
    "os"
    "path/filepath"
)

type Config struct {
    Version              string   `json:"version"`
    Algorithm            string   `json:"algorithm"`
    Digits               int      `json:"digits"`
    Period               int      `json:"period"`
    EncryptedSeed        string   `json:"encrypted_seed"`
    SeedSalt             string   `json:"seed_salt"`
    SeedNonce            string   `json:"seed_nonce"`
    MasterKeySalt        string   `json:"master_key_salt"`
    SeedUnlockTTLSeconds int      `json:"seed_unlock_ttl_seconds"`
    RecoveryCodesHash    []string `json:"recovery_codes_hash"`
    CreatedAt            string   `json:"created_at"`
}

// ConfigPath 返回 OTP 配置文件路径
func ConfigPath() string {
    home, _ := os.UserHomeDir()
    return filepath.Join(home, ".fssh", "otp", "config.enc")
}

// LoadConfig 加载 OTP 配置
func LoadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var cfg Config
    if err := json.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }

    // 验证配置版本
    if cfg.Version != "fssh-otp/v1" {
        return nil, fmt.Errorf("不支持的配置版本: %s", cfg.Version)
    }

    return &cfg, nil
}

// SaveConfig 保存 OTP 配置
func SaveConfig(cfg *Config) error {
    path := ConfigPath()

    // 确保目录存在
    dir := filepath.Dir(path)
    if err := os.MkdirAll(dir, 0700); err != nil {
        return err
    }

    data, err := json.MarshalIndent(cfg, "", "  ")
    if err != nil {
        return err
    }

    // 写入文件，权限 0600（仅当前用户可读写）
    return os.WriteFile(path, data, 0600)
}

// UpdateConfig 更新配置字段
func UpdateConfig(updateFn func(*Config) error) error {
    cfg, err := LoadConfig(ConfigPath())
    if err != nil {
        return err
    }

    if err := updateFn(cfg); err != nil {
        return err
    }

    return SaveConfig(cfg)
}
```

### 6. QR 码生成

```go
// internal/otp/qrcode.go
package otp

import (
    "encoding/base32"
    "fmt"
    "net/url"

    "github.com/skip2/go-qrcode"
)

// GenerateQRCode 生成 TOTP QR 码
func GenerateQRCode(seed []byte, issuer string, account string, algorithm string, digits int, period int) (string, error) {
    // 构造 otpauth:// URL
    uri := GenerateOTPAuthURL(seed, issuer, account, algorithm, digits, period)

    // 生成 ASCII QR 码
    qr, err := qrcode.New(uri, qrcode.Medium)
    if err != nil {
        return "", err
    }

    return qr.ToSmallString(false), nil
}

// GenerateOTPAuthURL 生成 otpauth:// URL
func GenerateOTPAuthURL(seed []byte, issuer string, account string, algorithm string, digits int, period int) string {
    secret := base32.StdEncoding.EncodeToString(seed)

    params := url.Values{}
    params.Set("secret", secret)
    params.Set("issuer", issuer)
    params.Set("algorithm", algorithm)
    params.Set("digits", fmt.Sprintf("%d", digits))
    params.Set("period", fmt.Sprintf("%d", period))

    return fmt.Sprintf("otpauth://totp/%s:%s?%s",
        url.PathEscape(issuer),
        url.PathEscape(account),
        params.Encode())
}

// DisplayOTPSetup 显示 OTP 设置信息
func DisplayOTPSetup(seed []byte, algorithm string, digits int, period int) error {
    hostname, _ := os.Hostname()
    user := os.Getenv("USER")
    account := fmt.Sprintf("%s@%s", user, hostname)

    // 生成 QR 码
    qrCode, err := GenerateQRCode(seed, "fssh", account, algorithm, digits, period)
    if err != nil {
        return err
    }

    // 显示 QR 码
    fmt.Println()
    fmt.Println("请使用认证器应用扫描二维码：")
    fmt.Println()
    fmt.Println(qrCode)
    fmt.Println()

    // 显示手动配置信息
    secret := base32.StdEncoding.EncodeToString(seed)
    fmt.Println("或手动添加：")
    fmt.Printf("  发行者: fssh\n")
    fmt.Printf("  账户: %s\n", account)
    fmt.Printf("  密钥: %s\n", secret)
    fmt.Printf("  类型: 基于时间\n")
    fmt.Printf("  算法: %s\n", algorithm)
    fmt.Printf("  位数: %d\n", digits)
    fmt.Printf("  间隔: %d秒\n", period)
    fmt.Println()

    return nil
}
```

### 7. 恢复码管理

```go
// internal/otp/recovery.go
package otp

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "strings"
)

const recoveryCodeLength = 16 // XXXX-XXXX-XXXX-XXXX

// GenerateRecoveryCodes 生成恢复码
func GenerateRecoveryCodes(count int) ([]string, error) {
    codes := make([]string, count)

    for i := 0; i < count; i++ {
        code, err := generateSingleRecoveryCode()
        if err != nil {
            return nil, err
        }
        codes[i] = code
    }

    return codes, nil
}

func generateSingleRecoveryCode() (string, error) {
    // 字符集：大写字母和数字（去除易混淆字符 0/O, 1/I/L）
    const charset = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

    bytes := make([]byte, recoveryCodeLength)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }

    parts := make([]string, 4)
    for i := 0; i < 4; i++ {
        part := ""
        for j := 0; j < 4; j++ {
            idx := int(bytes[i*4+j]) % len(charset)
            part += string(charset[idx])
        }
        parts[i] = part
    }

    return strings.Join(parts, "-"), nil
}

// HashRecoveryCodes 计算恢复码的哈希
func HashRecoveryCodes(codes []string) []string {
    hashes := make([]string, len(codes))

    for i, code := range codes {
        hash := sha256.Sum256([]byte(code))
        hashes[i] = hex.EncodeToString(hash[:])
    }

    return hashes
}

// VerifyRecoveryCode 验证恢复码
func VerifyRecoveryCode(code string, hashes []string) (bool, int) {
    hash := sha256.Sum256([]byte(code))
    codeHash := hex.EncodeToString(hash[:])

    for i, h := range hashes {
        if h == codeHash {
            return true, i
        }
    }

    return false, -1
}

// DisplayRecoveryCodes 显示恢复码
func DisplayRecoveryCodes(codes []string) {
    fmt.Println()
    fmt.Println("恢复码（请安全保存，打印或存入密码管理器）：")
    fmt.Println()

    for i, code := range codes {
        fmt.Printf("  %2d. %s\n", i+1, code)
    }

    fmt.Println()
    fmt.Println("⚠️  重要提示：")
    fmt.Println("  - 每个恢复码仅可使用一次")
    fmt.Println("  - 使用后该恢复码将立即失效")
    fmt.Println("  - 请妥善保管，丢失无法找回")
    fmt.Println()
}
```

---

## 集成步骤

### Step 1: Agent 启动集成

```go
// internal/agent/server.go
func StartWithOptions(cfg *config.Config) error {
    log.Info("启动 fssh SSH 认证代理")

    // 获取认证提供者
    authProvider, err := auth.GetAuthProvider(cfg.UnlockTTLSeconds)
    if err != nil {
        return fmt.Errorf("初始化认证失败: %w", err)
    }

    log.Infof("认证模式: %s", authProvider.Mode())

    // OTP 模式：启动时预先解锁 seed
    if authProvider.Mode() == auth.ModeOTP {
        if err := preUnlockOTP(authProvider); err != nil {
            return err
        }
    }

    // 创建 agent
    var agent Agent
    if cfg.RequireAuthPerSign {
        agent = NewSecureAgent(authProvider, cfg.UnlockTTLSeconds)
        log.Info("安全模式: 每次签名需要认证")
    } else {
        mk, err := authProvider.UnlockMasterKey()
        if err != nil {
            return fmt.Errorf("认证失败: %w", err)
        }
        agent = NewConvenienceAgent(mk)
        log.Info("便利模式: 启动时认证一次")
    }

    // 启动 agent 服务
    return serveAgent(agent, cfg.Socket)
}

func preUnlockOTP(provider auth.AuthProvider) error {
    fmt.Println()
    fmt.Println("OTP 认证初始化")
    fmt.Println("==============")

    // 调用 UnlockMasterKey，会提示输入密码和验证码
    _, err := provider.UnlockMasterKey()
    if err != nil {
        return err
    }

    fmt.Println()
    fmt.Println("✓ OTP 认证成功")
    fmt.Println("✓ Agent 已启动")
    fmt.Println()

    return nil
}
```

### Step 2: SecureAgent 修改

```go
// internal/agent/secure_agent.go
type secureAgent struct {
    authProvider auth.AuthProvider  // 使用接口
    metas        []store.EncryptedFile
    ttl          int
}

func NewSecureAgent(provider auth.AuthProvider, ttl int) *secureAgent {
    return &secureAgent{
        authProvider: provider,
        ttl:          ttl,
    }
}

func (a *secureAgent) Sign(pubKey ssh.PublicKey, data []byte) (*ssh.Signature, error) {
    // 获取 master key（可能触发认证）
    mk, err := a.authProvider.UnlockMasterKey()
    if err != nil {
        return nil, fmt.Errorf("认证失败: %w", err)
    }

    // 找到对应的私钥文件
    fp := ssh.FingerprintSHA256(pubKey)
    var alias string
    for _, meta := range a.metas {
        if meta.Fingerprint == fp {
            alias = meta.Alias
            break
        }
    }

    if alias == "" {
        return nil, fmt.Errorf("未找到私钥: %s", fp)
    }

    // 解密私钥
    rec, err := store.LoadDecryptedRecord(alias, mk)
    if err != nil {
        return nil, err
    }

    // 签名
    pk, _ := x509.ParsePKCS8PrivateKey(rec.PKCS8DER)
    signer, _ := ssh.NewSignerFromKey(pk)

    return signer.Sign(rand.Reader, data)
}
```

---

## 测试用例

### 单元测试

```go
// internal/otp/totp_test.go
package otp

import (
    "encoding/base32"
    "testing"
    "time"
)

func TestTOTPGenerate(t *testing.T) {
    // RFC 6238 测试向量
    seed := []byte("12345678901234567890")

    testCases := []struct {
        time     int64
        expected string
    }{
        {59, "94287082"},
        {1111111109, "07081804"},
        {1111111111, "14050471"},
        {1234567890, "89005924"},
    }

    for _, tc := range testCases {
        counter := tc.time / 30
        code := Generate(seed, counter, "SHA1", 8)
        if code != tc.expected {
            t.Errorf("time=%d: expected %s, got %s", tc.time, tc.expected, code)
        }
    }
}

func TestTOTPVerify(t *testing.T) {
    seed := []byte("testseed12345678")

    // 生成当前时间的验证码
    counter := time.Now().Unix() / 30
    code := Generate(seed, counter, "SHA1", 6)

    // 验证应该成功
    if !Verify(seed, code, "SHA1", 6, 30) {
        t.Error("当前验证码验证失败")
    }

    // 错误的验证码应该失败
    if Verify(seed, "000000", "SHA1", 6, 30) {
        t.Error("错误的验证码验证成功")
    }
}

func TestTOTPTimeWindow(t *testing.T) {
    seed := []byte("testseed12345678")

    // 生成前一个窗口的验证码
    counter := time.Now().Unix()/30 - 1
    oldCode := Generate(seed, counter, "SHA1", 6)

    // 应该仍然能验证（±1 窗口容错）
    if !Verify(seed, oldCode, "SHA1", 6, 30) {
        t.Error("前一个时间窗口的验证码验证失败")
    }
}
```

```go
// internal/otp/recovery_test.go
package otp

import (
    "testing"
)

func TestGenerateRecoveryCodes(t *testing.T) {
    codes, err := GenerateRecoveryCodes(10)
    if err != nil {
        t.Fatalf("生成恢复码失败: %v", err)
    }

    if len(codes) != 10 {
        t.Errorf("期望10个恢复码，得到 %d", len(codes))
    }

    // 检查格式: XXXX-XXXX-XXXX-XXXX
    for _, code := range codes {
        if len(code) != 19 { // 4*4 + 3*'-'
            t.Errorf("恢复码格式错误: %s", code)
        }
    }
}

func TestVerifyRecoveryCode(t *testing.T) {
    codes, _ := GenerateRecoveryCodes(5)
    hashes := HashRecoveryCodes(codes)

    // 验证第一个恢复码
    valid, idx := VerifyRecoveryCode(codes[0], hashes)
    if !valid || idx != 0 {
        t.Error("恢复码验证失败")
    }

    // 错误的恢复码应该失败
    valid, _ = VerifyRecoveryCode("AAAA-BBBB-CCCC-DDDD", hashes)
    if valid {
        t.Error("错误的恢复码验证成功")
    }
}
```

### 集成测试

```bash
#!/bin/bash
# test_otp_flow.sh

set -e

echo "=== OTP 认证集成测试 ==="

# 清理旧配置
rm -rf ~/.fssh/otp
rm -f ~/.fssh/auth_mode.json

# 1. 初始化 OTP 模式
echo "1. 初始化 OTP 模式..."
echo -e "testpassword123\ntestpassword123\n" | fssh init --mode otp

# 2. 验证配置文件
echo "2. 检查配置文件..."
test -f ~/.fssh/otp/config.enc || { echo "配置文件不存在"; exit 1; }
test "$(stat -f %A ~/.fssh/otp/config.enc)" = "600" || { echo "配置文件权限错误"; exit 1; }

# 3. 导入测试私钥
echo "3. 导入 SSH 私钥..."
ssh-keygen -t rsa -f /tmp/test_key -N "" -q
echo -e "testpassword123\n$(fssh otp-show --current-code)\n" | fssh import -alias test -file /tmp/test_key

# 4. 启动 agent
echo "4. 启动 agent..."
echo -e "testpassword123\n$(fssh otp-show --current-code)\n" | fssh agent &
AGENT_PID=$!
sleep 2

# 5. 测试 SSH 连接
echo "5. 测试 agent 功能..."
export SSH_AUTH_SOCK=~/.fssh/agent.sock
ssh-add -l | grep test || { echo "私钥未加载"; exit 1; }

# 6. 清理
echo "6. 清理测试环境..."
kill $AGENT_PID
rm -f /tmp/test_key*

echo "✓ 所有测试通过"
```

---

## 性能优化

### 1. PBKDF2 迭代次数优化

```go
// 根据硬件性能动态调整迭代次数
func OptimalPBKDF2Iterations() int {
    start := time.Now()

    // 测试 10,000 次迭代的性能
    pbkdf2.Key([]byte("test"), []byte("salt"), 10000, 32, sha256.New)

    elapsed := time.Since(start).Milliseconds()

    // 目标: 100ms 解密时间
    targetTime := 100
    iterations := 10000 * targetTime / int(elapsed)

    // 限制范围: 50,000 ~ 200,000
    if iterations < 50000 {
        iterations = 50000
    } else if iterations > 200000 {
        iterations = 200000
    }

    return iterations
}
```

### 2. 缓存预热

```go
// Agent 启动时预先解锁，避免首次 SSH 时等待
func (p *OTPProvider) Preheat() error {
    _, err := p.UnlockMasterKey()
    return err
}
```

### 3. 内存安全清理

```go
// 使用 runtime.KeepAlive 防止编译器优化掉清零操作
func secureClear(data []byte) {
    for i := range data {
        data[i] = 0
    }
    runtime.KeepAlive(data)
}

func (p *OTPProvider) ClearCache() {
    p.mu.Lock()
    defer p.mu.Unlock()

    if p.cachedSeed != nil {
        secureClear(p.cachedSeed)
        p.cachedSeed = nil
    }

    if p.cachedMasterKey != nil {
        secureClear(p.cachedMasterKey)
        p.cachedMasterKey = nil
    }
}
```

---

## 依赖管理

```bash
# 添加依赖
go get github.com/pquerna/otp@v1.4.0
go get github.com/skip2/go-qrcode@v0.0.0-20200617195104-da1b6568686e
go get golang.org/x/crypto@latest
go get golang.org/x/term@latest

# 更新 go.mod
go mod tidy
```

---

## 完成标准

### Phase 1 完成标准
- [ ] 所有单元测试通过
- [ ] 集成测试脚本通过
- [ ] 可以通过 OTP 模式初始化并连接 SSH
- [ ] 代码覆盖率 > 80%

### Phase 2 完成标准
- [ ] QR 码正常显示
- [ ] 恢复码生成和使用正常
- [ ] 所有配置命令正常工作
- [ ] 文档完整

### Phase 3 完成标准
- [ ] Touch ID ↔ OTP 切换无数据丢失
- [ ] 备份和恢复功能正常
- [ ] FileVault 检测正确
- [ ] 性能满足要求（解密 < 200ms）

---

本文档提供了 OTP 认证的完整实施指南，包括代码结构、核心实现、测试用例和性能优化建议。
