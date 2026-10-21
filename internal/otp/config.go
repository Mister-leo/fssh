package otp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config OTP 配置结构
// 存储加密的 OTP seed 和相关参数
type Config struct {
	// 版本标识
	Version string `json:"version"`

	// TOTP 参数
	Algorithm string `json:"algorithm"` // SHA1, SHA256, SHA512
	Digits    int    `json:"digits"`    // 6 或 8
	Period    int    `json:"period"`    // 时间窗口（秒），通常是 30

	// 加密的 OTP seed
	EncryptedSeed string `json:"encrypted_seed"` // Base64 编码的密文
	SeedSalt      string `json:"seed_salt"`      // Base64 编码的 PBKDF2 salt (32 bytes)
	SeedNonce     string `json:"seed_nonce"`     // Base64 编码的 AES-GCM nonce (12 bytes)

	// Master Key 派生参数
	MasterKeySalt string `json:"master_key_salt"` // Base64 编码的 HKDF salt (32 bytes)

	// 缓存配置
	SeedUnlockTTLSeconds int `json:"seed_unlock_ttl_seconds"` // OTP seed 缓存时间（秒）

	// 恢复码：SHA-256 哈希用于定位，RecoveryWrapped[i] 是用第 i 个恢复码加密的 seed 副本
	// 旧版本只有哈希，无法用于恢复（见 LegacyRecovery）
	RecoveryCodesHash []string      `json:"recovery_codes_hash"`
	RecoveryWrapped   []WrappedSeed `json:"recovery_wrapped,omitempty"`

	// 创建时间
	CreatedAt string `json:"created_at"`
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
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 验证配置版本
	if cfg.Version != "fssh-otp/v1" {
		return nil, fmt.Errorf("不支持的配置版本: %s", cfg.Version)
	}

	// 验证必要字段
	if cfg.EncryptedSeed == "" || cfg.SeedSalt == "" || cfg.SeedNonce == "" {
		return nil, fmt.Errorf("配置文件损坏：缺少必要字段")
	}

	return &cfg, nil
}

// SaveConfig 保存 OTP 配置
func SaveConfig(cfg *Config) error {
	path := ConfigPath()

	// 确保目录存在
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}

	// 序列化配置
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	// 写入文件，权限 0600（仅当前用户可读写）
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}

	return nil
}

// ConfigExists 检查配置文件是否存在
func ConfigExists() bool {
	_, err := os.Stat(ConfigPath())
	return err == nil
}

// UpdateConfig 更新配置字段
// 使用回调函数修改配置，然后保存
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
