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
// 支持 ±1 个时间窗口容错（±30秒），防止时钟偏移
func Verify(seed []byte, userCode string, algorithm string, digits int, period int) bool {
	_, ok := VerifyCounter(seed, userCode, algorithm, digits, period)
	return ok
}

// VerifyCounter is Verify that also returns the matched time step, so
// callers can reject a code that was already used (replay).
func VerifyCounter(seed []byte, userCode string, algorithm string, digits int, period int) (int64, bool) {
	if period <= 0 {
		period = 30
	}
	counter := time.Now().Unix() / int64(period)

	// 允许 ±1 个时间窗口（±30秒容错）
	for offset := int64(-1); offset <= 1; offset++ {
		expected := Generate(seed, counter+offset, algorithm, digits)
		if hmac.Equal([]byte(userCode), []byte(expected)) {
			return counter + offset, true
		}
	}
	return 0, false
}

// Generate 生成 TOTP 验证码
// 实现 RFC 6238 (TOTP) 和 RFC 4226 (HOTP) 标准
func Generate(seed []byte, counter int64, algorithm string, digits int) string {
	// 选择 HMAC 算法
	var hashFunc func() hash.Hash
	switch algorithm {
	case "SHA1":
		hashFunc = sha1.New
	case "SHA256":
		hashFunc = sha256.New
	case "SHA512":
		hashFunc = sha512.New
	default:
		hashFunc = sha1.New
	}

	// HOTP 算法（RFC 4226）
	mac := hmac.New(hashFunc, seed)
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter))
	mac.Write(counterBytes)
	hs := mac.Sum(nil)

	// Dynamic truncation
	offset := hs[len(hs)-1] & 0x0f
	truncatedHash := binary.BigEndian.Uint32(hs[offset:offset+4]) & 0x7fffffff

	// 计算验证码
	code := truncatedHash % uint32(math.Pow10(digits))

	// 格式化为固定位数的字符串（前导零）
	return fmt.Sprintf("%0*d", digits, code)
}

// GetCurrentCode 获取当前时间的验证码
// 用于显示当前验证码（调试或用户查看）
func GetCurrentCode(seed []byte, algorithm string, digits int, period int) string {
	now := time.Now().Unix()
	counter := now / int64(period)
	return Generate(seed, counter, algorithm, digits)
}

// GetTimeRemaining 获取当前验证码剩余有效时间（秒）
func GetTimeRemaining(period int) int {
	now := time.Now().Unix()
	return period - int(now%int64(period))
}
