package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"fssh/internal/crypt"
	"fssh/internal/i18n"
	"fssh/internal/log"
	"fssh/internal/otp"
)

const (
	otpMaxAttempts = 3
	masterKeyInfo  = "fssh-master-key-v1"
)

// OTPProvider OTP 认证提供者
// 实现基于密码和 TOTP 验证码的双层认证
type OTPProvider struct {
	configPath string

	// authMu 在整个认证流程中持有：同一时刻只显示一个输入框，并发请求等待第一个结果
	authMu sync.Mutex

	// mu 保护以下字段
	mu     sync.Mutex
	config *otp.Config

	// OTP seed 缓存（密码输入频率）
	cachedSeed []byte
	seedExpiry time.Time

	// Master key 缓存（验证码输入频率）
	cachedMasterKey []byte
	masterKeyExpiry time.Time
	masterKeyTTL    int // Master key 缓存时间（秒）

	legacyWarned bool

	now func() time.Time
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
		now:          time.Now,
	}, nil
}

// reloadConfig 每次认证前重新读取配置，使 rekey / 改密码 / 恢复后无需重启 agent
func (p *OTPProvider) reloadConfig() *otp.Config {
	cfg, err := otp.LoadConfig(p.configPath)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		log.Warn("重新加载 OTP 配置失败，使用内存中的配置", map[string]interface{}{"error": err.Error()})
		return p.config
	}
	p.config = cfg
	return cfg
}

// unlockSeed 第一层认证：密码解密 OTP seed（可能使用缓存）
func (p *OTPProvider) unlockSeed(req Request, cfg *otp.Config) ([]byte, error) {
	ttl := cfg.SeedUnlockTTLSeconds

	p.mu.Lock()
	if ttl > 0 && p.cachedSeed != nil && p.now().Before(p.seedExpiry) {
		seed := append([]byte(nil), p.cachedSeed...)
		p.mu.Unlock()
		log.Debug("OTP seed 缓存命中", nil)
		return seed, nil
	}
	p.mu.Unlock()

	pr := req.prompter()
	hint := ""
	for attempt := 1; ; attempt++ {
		password, err := pr.Password(hint + req.reason() + "\n\n" + i18n.T("otp.prompt_password"))
		if err != nil {
			return nil, err
		}
		seed, err := otp.DecryptSeed(cfg, password)
		if err == nil {
			if ttl > 0 {
				p.mu.Lock()
				p.cachedSeed = append([]byte(nil), seed...)
				p.seedExpiry = p.now().Add(time.Duration(ttl) * time.Second)
				p.mu.Unlock()
			}
			log.Info("OTP seed 已解锁", map[string]interface{}{"ttl_seconds": ttl})
			return seed, nil
		}
		if attempt >= otpMaxAttempts {
			return nil, errors.New(i18n.T("otp.err_password"))
		}
		hint = i18n.T("otp.retry_password") + "\n"
	}
}

// verifyCode 第二层认证：TOTP 验证码
func (p *OTPProvider) verifyCode(req Request, cfg *otp.Config, seed []byte) error {
	pr := req.prompter()
	hint := ""
	for attempt := 1; ; attempt++ {
		code, err := pr.Text(hint + req.reason() + "\n\n" + i18n.T("otp.prompt_code", cfg.Digits))
		if err != nil {
			return err
		}
		code = strings.TrimSpace(code)
		if validCodeFormat(code, cfg.Digits) && otp.Verify(seed, code, cfg.Algorithm, cfg.Digits, cfg.Period) {
			log.Info("TOTP 验证成功", nil)
			return nil
		}
		if attempt >= otpMaxAttempts {
			return errors.New(i18n.T("otp.err_code"))
		}
		hint = i18n.T("otp.retry_code") + "\n"
	}
}

func validCodeFormat(code string, digits int) bool {
	if len(code) != digits {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// authenticate 完整的双层认证，返回 seed 和派生的 master key。调用方需持有 authMu
func (p *OTPProvider) authenticate(req Request) (seed, masterKey []byte, err error) {
	cfg := p.reloadConfig()

	seed, err = p.unlockSeed(req, cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := p.verifyCode(req, cfg, seed); err != nil {
		return nil, nil, err
	}

	salt, err := base64.StdEncoding.DecodeString(cfg.MasterKeySalt)
	if err != nil {
		return nil, nil, fmt.Errorf("解码 master key salt 失败: %w", err)
	}
	masterKey = crypt.HKDF(seed, salt, []byte(masterKeyInfo), 32)

	p.warnLegacyRecovery(req, cfg)
	return seed, masterKey, nil
}

// warnLegacyRecovery 旧版恢复码无法使用，每个进程提示一次
func (p *OTPProvider) warnLegacyRecovery(req Request, cfg *otp.Config) {
	p.mu.Lock()
	warn := cfg.LegacyRecovery() && !p.legacyWarned
	p.legacyWarned = p.legacyWarned || warn
	p.mu.Unlock()
	if warn {
		req.prompter().Notify("fssh", i18n.T("otp.legacy_recovery"))
	}
}

// UnlockMasterKey 实现 AuthProvider 接口
// 1. 密码解锁 OTP seed（可能使用缓存）
// 2. TOTP 验证码验证
// 3. 从 seed 派生 master key
func (p *OTPProvider) UnlockMasterKey(req Request) ([]byte, error) {
	p.authMu.Lock()
	defer p.authMu.Unlock()

	if !req.NoCache {
		p.mu.Lock()
		if p.masterKeyTTL > 0 && p.cachedMasterKey != nil && p.now().Before(p.masterKeyExpiry) {
			mk := append([]byte(nil), p.cachedMasterKey...)
			p.mu.Unlock()
			log.Debug("Master key 缓存命中", nil)
			return mk, nil
		}
		p.mu.Unlock()
	}

	_, mk, err := p.authenticate(req)
	if err != nil {
		return nil, err
	}

	if !req.NoCache && p.masterKeyTTL > 0 {
		p.mu.Lock()
		p.cachedMasterKey = append([]byte(nil), mk...)
		p.masterKeyExpiry = p.now().Add(time.Duration(p.masterKeyTTL) * time.Second)
		p.mu.Unlock()
		log.Info("Master key 已缓存", map[string]interface{}{"ttl_seconds": p.masterKeyTTL})
	}
	return mk, nil
}

// VerifySeed 完整认证（密码 + 验证码）后返回 seed，用于修改密码、重新生成恢复码
func (p *OTPProvider) VerifySeed(req Request) ([]byte, error) {
	p.authMu.Lock()
	defer p.authMu.Unlock()
	seed, _, err := p.authenticate(req)
	return seed, err
}

// PrepareRekey 实现 AuthProvider 接口
// seed 不变（无需重新绑定验证器），更换 master key salt 得到新的 master key
func (p *OTPProvider) PrepareRekey(req Request) (*Rekey, error) {
	p.authMu.Lock()
	defer p.authMu.Unlock()

	seed, old, err := p.authenticate(req)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	newKey := crypt.HKDF(seed, salt, []byte(masterKeyInfo), 32)
	saltB64 := base64.StdEncoding.EncodeToString(salt)

	return &Rekey{
		OldKey: old,
		NewKey: newKey,
		Commit: func() error {
			if err := otp.UpdateConfig(func(c *otp.Config) error {
				c.MasterKeySalt = saltB64
				return nil
			}); err != nil {
				return err
			}
			p.ClearCache()
			return nil
		},
	}, nil
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

	if p.cachedSeed != nil {
		secureClear(p.cachedSeed)
		p.cachedSeed = nil
	}
	if p.cachedMasterKey != nil {
		secureClear(p.cachedMasterKey)
		p.cachedMasterKey = nil
	}
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
