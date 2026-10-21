package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fssh/internal/keychain"
)

// AuthMode 认证模式类型
type AuthMode string

const (
	ModeTouchID AuthMode = "touchid"
	ModeOTP     AuthMode = "otp"
)

// AuthProvider 统一认证接口
// 为 Touch ID 和 OTP 两种认证方式提供统一的抽象
type AuthProvider interface {
	// UnlockMasterKey 解锁并返回 master key
	// 可能需要用户交互（Touch ID 或密码+验证码）
	UnlockMasterKey() ([]byte, error)

	// IsAvailable 检查认证方式是否可用
	// Touch ID: 检查设备是否支持
	// OTP: 检查配置文件是否存在
	IsAvailable() bool

	// Mode 返回当前认证模式
	Mode() AuthMode

	// ClearCache 清除缓存的敏感数据
	ClearCache()
}

// GetAuthProvider 自动选择并创建认证提供者
// 根据 auth_mode.json 或系统环境自动选择 Touch ID 或 OTP
func GetAuthProvider(masterKeyTTL int) (AuthProvider, error) {
	mode, err := LoadMode()
	if err != nil {
		return nil, fmt.Errorf("加载认证模式失败: %w", err)
	}

	switch mode {
	case ModeTouchID:
		provider := NewTouchIDProvider(masterKeyTTL)
		if !provider.IsAvailable() {
			return nil, errors.New("Touch ID 模式未初始化：Keychain 中没有 master key，请运行: fssh init")
		}
		return provider, nil

	case ModeOTP:
		provider, err := NewOTPProvider(masterKeyTTL)
		if err != nil {
			return nil, fmt.Errorf("OTP 初始化失败: %w", err)
		}
		if !provider.IsAvailable() {
			return nil, errors.New("OTP 未配置，请运行: fssh init --mode otp")
		}
		return provider, nil

	default:
		return nil, fmt.Errorf("未知认证模式: %s", mode)
	}
}

// modeConfig 认证模式配置文件结构
type modeConfig struct {
	Version   string   `json:"version"`
	Mode      AuthMode `json:"mode"`
	CreatedAt string   `json:"created_at"`
}

// LoadMode 加载当前认证模式
// 读取 ~/.fssh/auth_mode.json，如果不存在则根据 Keychain 自动检测
func LoadMode() (AuthMode, error) {
	path := modeConfigPath()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// 文件不存在，尝试自动检测
			// 如果 Keychain 中有 master key，默认使用 Touch ID
			exists, _ := keychain.MasterKeyExists()
			if exists {
				return ModeTouchID, nil
			}
			// 否则默认使用 OTP
			return ModeOTP, nil
		}
		return "", fmt.Errorf("读取认证模式配置失败: %w", err)
	}

	var cfg modeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("解析认证模式配置失败: %w", err)
	}

	// 验证版本
	if cfg.Version != "fssh-auth/v1" {
		return "", fmt.Errorf("不支持的认证模式配置版本: %s", cfg.Version)
	}

	return cfg.Mode, nil
}

// SaveMode 保存认证模式
func SaveMode(mode AuthMode) error {
	path := modeConfigPath()

	cfg := modeConfig{
		Version:   "fssh-auth/v1",
		Mode:      mode,
		CreatedAt: time.Now().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化认证模式配置失败: %w", err)
	}

	// 确保目录存在
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("保存认证模式配置失败: %w", err)
	}
	// WriteFile 不会修改已存在文件的权限，旧版本创建的文件是 0644
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("设置认证模式配置权限失败: %w", err)
	}

	return nil
}

// modeConfigPath 返回认证模式配置文件路径
func modeConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".fssh", "auth_mode.json")
}
