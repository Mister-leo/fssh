package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"runtime"
	"sync"
	"time"

	"fssh/internal/crypt"
	"fssh/internal/log"
	"fssh/internal/otp"

	"golang.org/x/crypto/pbkdf2"
)

// OTPProvider OTP 认证提供者
// 实现基于密码和 TOTP 验证码的双层认证
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
	masterKeyTTL    int // Master key 缓存时间（秒）
}

// NewOTPProvider 创建 OTP 认证提供者
func NewOTPProvider(masterKeyTTL int) (*OTPProvider, error) {
	path := otp.ConfigPath()
	cfg, err := otp.LoadConfig(path)
	if err != nil {
		return nil, fmt.Errorf("加载 OTP 配置失败: %w", err)
	}

	return &OTPProvider{
		configPath:   path,
		config:       cfg,
		masterKeyTTL: masterKeyTTL,
	}, nil
}

// unlockSeed 解锁 OTP seed（私有方法）
// 这是第一层认证：密码解密 OTP seed
func (p *OTPProvider) unlockSeed() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 检查缓存
	ttl := p.config.SeedUnlockTTLSeconds
	if ttl > 0 && time.Now().Before(p.seedExpiry) {
		log.Debug("OTP seed 缓存命中", map[string]interface{}{
			"expires_at": p.seedExpiry.UTC().Format(time.RFC3339),
		})
		return p.cachedSeed, nil
	}

	// 缓存过期，需要重新解锁
	log.Info("OTP seed 缓存已过期，需要重新解锁", nil)

	// 1. 提示输入密码
	password, err := otp.PromptPassword("请输入 OTP 密码: ")
	if err != nil {
		return nil, fmt.Errorf("读取密码失败: %w", err)
	}

	// 2. 解码加密参数
	seedSalt, err := base64.StdEncoding.DecodeString(p.config.SeedSalt)
	if err != nil {
		return nil, fmt.Errorf("解码 seed salt 失败: %w", err)
	}

	seedNonce, err := base64.StdEncoding.DecodeString(p.config.SeedNonce)
	if err != nil {
		return nil, fmt.Errorf("解码 seed nonce 失败: %w", err)
	}

	encryptedSeed, err := base64.StdEncoding.DecodeString(p.config.EncryptedSeed)
	if err != nil {
		return nil, fmt.Errorf("解码加密 seed 失败: %w", err)
	}

	// 3. 派生解密密钥（PBKDF2）
	log.Debug("派生解密密钥（PBKDF2 100k 迭代）", nil)
	encKey := pbkdf2.Key([]byte(password), seedSalt, 100000, 32, sha256.New)

	// 4. 解密 OTP seed
	seed, err := crypt.DecryptAEAD(encKey, seedNonce, encryptedSeed, nil)
	if err != nil {
		return nil, fmt.Errorf("密码错误或配置文件损坏")
	}

	log.Info("OTP seed 已解锁", nil)

	// 5. 更新缓存
	p.cachedSeed = seed
	if ttl > 0 {
		p.seedExpiry = time.Now().Add(time.Duration(ttl) * time.Second)
		log.Info("OTP seed 已缓存", map[string]interface{}{
			"ttl_seconds": ttl,
			"expires_at":  p.seedExpiry.UTC().Format(time.RFC3339),
		})
	} else {
		p.seedExpiry = time.Now()
		log.Info("OTP seed 不缓存（TTL=0）", nil)
	}

	return seed, nil
}

// UnlockMasterKey 实现 AuthProvider 接口
// 这是完整的双层认证流程：
// 1. 密码解锁 OTP seed（可能使用缓存）
// 2. TOTP 验证码验证（动态认证）
// 3. 从 seed 派生 master key
func (p *OTPProvider) UnlockMasterKey() ([]byte, error) {
	// 检查 master key 缓存
	p.mu.Lock()
	if p.masterKeyTTL > 0 && time.Now().Before(p.masterKeyExpiry) {
		mk := p.cachedMasterKey
		p.mu.Unlock()
		log.Debug("Master key 缓存命中", map[string]interface{}{
			"expires_at": p.masterKeyExpiry.UTC().Format(time.RFC3339),
		})
		return mk, nil
	}
	p.mu.Unlock()

	log.Info("Master key 缓存过期，需要重新认证", nil)

	// 1. 解锁 OTP seed（可能使用缓存）
	seed, err := p.unlockSeed()
	if err != nil {
		return nil, err
	}

	// 2. 提示输入 TOTP 验证码
	code, err := otp.PromptCode(fmt.Sprintf("请输入%d位验证码: ", p.config.Digits))
	if err != nil {
		return nil, fmt.Errorf("读取验证码失败: %w", err)
	}

	// 3. 验证 TOTP
	log.Debug("验证 TOTP 验证码", nil)
	valid := otp.Verify(seed, code, p.config.Algorithm, p.config.Digits, p.config.Period)
	if !valid {
		return nil, fmt.Errorf("验证码错误或已过期")
	}

	log.Info("TOTP 验证成功", nil)

	// 4. 从 seed 派生 master key
	masterKeySalt, err := base64.StdEncoding.DecodeString(p.config.MasterKeySalt)
	if err != nil {
		return nil, fmt.Errorf("解码 master key salt 失败: %w", err)
	}

	log.Debug("派生 master key (HKDF)", nil)
	masterKey := crypt.HKDF(seed, masterKeySalt, []byte("fssh-master-key-v1"), 32)

	// 5. 缓存 master key
	p.mu.Lock()
	if p.masterKeyTTL > 0 {
		p.cachedMasterKey = masterKey
		p.masterKeyExpiry = time.Now().Add(time.Duration(p.masterKeyTTL) * time.Second)
		log.Info("Master key 已缓存", map[string]interface{}{
			"ttl_seconds": p.masterKeyTTL,
			"expires_at":  p.masterKeyExpiry.UTC().Format(time.RFC3339),
		})
	}
	p.mu.Unlock()

	return masterKey, nil
}

// IsAvailable 实现 AuthProvider 接口
func (p *OTPProvider) IsAvailable() bool {
	return p.config != nil && otp.ConfigExists()
}

// Mode 实现 AuthProvider 接口
func (p *OTPProvider) Mode() AuthMode {
	return ModeOTP
}

// ClearCache 实现 AuthProvider 接口
// 安全清零内存中的敏感数据
func (p *OTPProvider) ClearCache() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 清零 OTP seed
	if p.cachedSeed != nil {
		secureClear(p.cachedSeed)
		p.cachedSeed = nil
	}

	// 清零 master key
	if p.cachedMasterKey != nil {
		secureClear(p.cachedMasterKey)
		p.cachedMasterKey = nil
	}

	// 清除过期时间
	p.seedExpiry = time.Time{}
	p.masterKeyExpiry = time.Time{}

	log.Info("OTP 缓存已清除", nil)
}

// secureClear 安全清零字节数组
// 使用 runtime.KeepAlive 防止编译器优化掉清零操作
func secureClear(data []byte) {
	for i := range data {
		data[i] = 0
	}
	runtime.KeepAlive(data)
}
