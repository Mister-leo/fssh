package otp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"fssh/internal/i18n"
)

const recoveryCodeLength = 16 // XXXX-XXXX-XXXX-XXXX

// DefaultRecoveryCodes is the number of recovery codes generated.
const DefaultRecoveryCodes = 10

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

// generateSingleRecoveryCode 生成单个恢复码
// 格式: XXXX-XXXX-XXXX-XXXX（去除易混淆字符）
func generateSingleRecoveryCode() (string, error) {
	// 字符集：大写字母和数字（去除易混淆字符 0/O, 1/I/L）
	const charset = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

	bytes := make([]byte, recoveryCodeLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
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

// NormalizeRecoveryCode accepts user input in any case, with or without
// dashes and spaces, and returns the canonical XXXX-XXXX-XXXX-XXXX form.
func NormalizeRecoveryCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	raw := b.String()
	if len(raw) != recoveryCodeLength {
		return raw
	}
	return raw[0:4] + "-" + raw[4:8] + "-" + raw[8:12] + "-" + raw[12:16]
}

// HashRecoveryCodes 计算恢复码的哈希
// 哈希只用于快速定位对应的加密副本
func HashRecoveryCodes(codes []string) []string {
	hashes := make([]string, len(codes))

	for i, code := range codes {
		hash := sha256.Sum256([]byte(code))
		hashes[i] = hex.EncodeToString(hash[:])
	}

	return hashes
}

// VerifyRecoveryCode 验证恢复码
// 返回是否有效和在哈希列表中的索引
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

// SetRecoveryCodes generates n new recovery codes, each able to decrypt the
// seed on its own, and replaces any existing codes in cfg.
func SetRecoveryCodes(cfg *Config, seed []byte, n int) ([]string, error) {
	codes, err := GenerateRecoveryCodes(n)
	if err != nil {
		return nil, err
	}
	wrapped := make([]WrappedSeed, n)
	for i, c := range codes {
		if wrapped[i], err = sealSeed(c, seed); err != nil {
			return nil, fmt.Errorf("encrypt seed for recovery code: %w", err)
		}
	}
	cfg.RecoveryCodesHash = HashRecoveryCodes(codes)
	cfg.RecoveryWrapped = wrapped
	return codes, nil
}

// RecoverSeed decrypts the seed with a recovery code and returns the index of
// the code so the caller can remove it after use.
func RecoverSeed(cfg *Config, code string) ([]byte, int, error) {
	code = NormalizeRecoveryCode(code)
	ok, idx := VerifyRecoveryCode(code, cfg.RecoveryCodesHash)
	if !ok || idx >= len(cfg.RecoveryWrapped) {
		return nil, -1, ErrInvalidRecoveryCode
	}
	seed, err := openSeed(code, cfg.RecoveryWrapped[idx])
	if err != nil {
		return nil, -1, ErrInvalidRecoveryCode
	}
	return seed, idx, nil
}

// RemoveRecoveryCode deletes a used recovery code.
func RemoveRecoveryCode(cfg *Config, idx int) {
	if idx < 0 || idx >= len(cfg.RecoveryCodesHash) || idx >= len(cfg.RecoveryWrapped) {
		return
	}
	cfg.RecoveryCodesHash = append(cfg.RecoveryCodesHash[:idx], cfg.RecoveryCodesHash[idx+1:]...)
	cfg.RecoveryWrapped = append(cfg.RecoveryWrapped[:idx], cfg.RecoveryWrapped[idx+1:]...)
}

// LegacyRecovery reports whether cfg still holds hash-only recovery codes
// from older versions, which cannot recover the seed.
func (cfg *Config) LegacyRecovery() bool {
	return len(cfg.RecoveryCodesHash) > 0 && len(cfg.RecoveryWrapped) != len(cfg.RecoveryCodesHash)
}

// DisplayRecoveryCodes 显示恢复码
func DisplayRecoveryCodes(codes []string) {
	fmt.Println(i18n.T("otp.recovery_title"))
	fmt.Println()

	for i, code := range codes {
		fmt.Printf("  %2d. %s\n", i+1, code)
	}

	fmt.Println()
	fmt.Println(i18n.T("otp.recovery_notes"))
	fmt.Println()
}
