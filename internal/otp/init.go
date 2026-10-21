package otp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"time"

	"fssh/internal/crypt"
	"fssh/internal/i18n"
)

// InitOptions OTP 初始化选项
type InitOptions struct {
	Password         string // OTP 密码
	SeedUnlockTTL    int    // OTP seed 缓存时间（秒）
	Algorithm        string // TOTP 算法: SHA1, SHA256, SHA512
	Digits           int    // 验证码位数: 6 或 8
	Period           int    // TOTP 时间窗口（秒）
	GenerateRecovery bool   // 是否生成恢复码
}

// DefaultInitOptions 返回默认初始化选项
func DefaultInitOptions() *InitOptions {
	return &InitOptions{
		SeedUnlockTTL:    3600, // 1小时
		Algorithm:        "SHA1",
		Digits:           6,
		Period:           30,
		GenerateRecovery: true,
	}
}

// NewConfig builds an OTP configuration in memory: a random seed encrypted
// with opts.Password and, if requested, recovery codes. Nothing is saved, so
// callers can verify the authenticator works before committing.
func NewConfig(opts *InitOptions) (cfg *Config, seed []byte, recoveryCodes []string, err error) {
	// 1. 生成随机 OTP seed (20 字节，标准 TOTP seed 长度)
	seed = make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, nil, fmt.Errorf("generate OTP seed: %w", err)
	}

	masterKeySalt := make([]byte, 32)
	if _, err := rand.Read(masterKeySalt); err != nil {
		return nil, nil, nil, fmt.Errorf("generate master key salt: %w", err)
	}

	cfg = &Config{
		Version:              "fssh-otp/v1",
		Algorithm:            opts.Algorithm,
		Digits:               opts.Digits,
		Period:               opts.Period,
		MasterKeySalt:        base64.StdEncoding.EncodeToString(masterKeySalt),
		SeedUnlockTTLSeconds: opts.SeedUnlockTTL,
		CreatedAt:            time.Now().Format(time.RFC3339),
	}

	// 2. 使用密码加密 seed（内含密码强度校验）
	if err := SetPassword(cfg, opts.Password, seed); err != nil {
		return nil, nil, nil, err
	}

	// 3. 生成恢复码，每个恢复码都单独加密一份 seed
	if opts.GenerateRecovery {
		recoveryCodes, err = SetRecoveryCodes(cfg, seed, DefaultRecoveryCodes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("generate recovery codes: %w", err)
		}
	}
	return cfg, seed, recoveryCodes, nil
}

// Initialize 初始化并保存 OTP 配置
func Initialize(opts *InitOptions) (seed []byte, recoveryCodes []string, err error) {
	cfg, seed, recoveryCodes, err := NewConfig(opts)
	if err != nil {
		return nil, nil, err
	}
	if err := SaveConfig(cfg); err != nil {
		return nil, nil, err
	}
	return seed, recoveryCodes, nil
}

// MasterKey derives the master key from the seed: HKDF-SHA256 with the
// config's salt. Must match auth.OTPProvider.
func MasterKey(cfg *Config, seed []byte) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(cfg.MasterKeySalt)
	if err != nil {
		return nil, fmt.Errorf("decode master key salt: %w", err)
	}
	return crypt.HKDF(seed, salt, []byte("fssh-master-key-v1"), 32), nil
}

// Account returns the label shown in authenticator apps, e.g. "alice@macbook".
func Account() string {
	hostname, _ := os.Hostname()
	return fmt.Sprintf("%s@%s", os.Getenv("USER"), hostname)
}

// DisplaySecret prints the TOTP secret in Base32, the otpauth:// URI and,
// when qrencode is installed, a scannable QR code.
func DisplaySecret(seed []byte, algorithm string, digits int, period int) {
	uri := OTPAuthURI(seed, Account(), algorithm, digits, period)

	fmt.Println(i18n.T("otp.secret_title"))
	fmt.Printf("  %s fssh\n", i18n.T("otp.secret_issuer"))
	fmt.Printf("  %s %s\n", i18n.T("otp.secret_account"), Account())
	fmt.Printf("  %s %s\n", i18n.T("otp.secret_key"), SecretBase32(seed))
	fmt.Printf("  %s %s / %d / %ds\n", i18n.T("otp.secret_params"), algorithm, digits, period)
	fmt.Println()
	fmt.Println(i18n.T("otp.secret_uri"))
	fmt.Println("  " + uri)
	fmt.Println()

	if path, err := exec.LookPath("qrencode"); err == nil {
		cmd := exec.Command(path, "-t", "ANSIUTF8", uri)
		cmd.Stdout = os.Stdout
		if cmd.Run() == nil {
			fmt.Println()
			return
		}
	}
	fmt.Println(i18n.T("otp.secret_qr_hint"))
	fmt.Println()
}

// DisplayInitResult 显示初始化结果
func DisplayInitResult(seed []byte, recoveryCodes []string, algorithm string, digits int, period int) error {
	fmt.Println()
	fmt.Println(i18n.T("otp.init_done"))
	fmt.Println()

	DisplaySecret(seed, algorithm, digits, period)
	fmt.Println(i18n.T("otp.init_add_to_app"))
	fmt.Println()

	if len(recoveryCodes) > 0 {
		DisplayRecoveryCodes(recoveryCodes)
	}

	fmt.Println(i18n.T("otp.init_saved", ConfigPath()))
	fmt.Println()
	fmt.Println(i18n.T("otp.init_security"))
	fmt.Println()
	fmt.Println(i18n.T("otp.init_next"))
	fmt.Println()

	return nil
}
