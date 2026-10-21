package auth

import (
	"sync"
	"time"

	"fssh/internal/keychain"
	"fssh/internal/log"
)

// TouchIDProvider Touch ID 认证提供者
// 使用 macOS Keychain 和 Touch ID 进行认证
type TouchIDProvider struct {
	ttl time.Duration // master key 缓存时间，0 表示不缓存

	// mu 在整个解锁过程中持有，使并发签名请求只触发一次 Touch ID
	mu        sync.Mutex
	cachedKey []byte
	expiry    time.Time

	// 测试时可替换
	unlock func() ([]byte, error)
	now    func() time.Time
}

// NewTouchIDProvider 创建 Touch ID 认证提供者
// ttlSeconds: 解锁后 master key 的缓存时间（秒），0 表示每次都需要 Touch ID
func NewTouchIDProvider(ttlSeconds int) *TouchIDProvider {
	if ttlSeconds < 0 {
		ttlSeconds = 0
	}
	return &TouchIDProvider{
		ttl:    time.Duration(ttlSeconds) * time.Second,
		unlock: keychain.LoadMasterKey,
		now:    time.Now,
	}
}

// UnlockMasterKey 实现 AuthProvider 接口
// 缓存有效时直接返回，否则通过 Touch ID 从 Keychain 加载 master key
func (p *TouchIDProvider) UnlockMasterKey() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ttl > 0 && p.cachedKey != nil && p.now().Before(p.expiry) {
		log.Debug("Master key 缓存命中", map[string]interface{}{
			"expires_at": p.expiry.UTC().Format(time.RFC3339),
		})
		// 返回副本：ClearCache 清零缓存时不影响正在使用 key 的调用方
		return append([]byte(nil), p.cachedKey...), nil
	}

	mk, err := p.unlock()
	if err != nil {
		return nil, err
	}

	if p.ttl > 0 {
		p.cachedKey = append([]byte(nil), mk...)
		p.expiry = p.now().Add(p.ttl)
		log.Info("Master key 已缓存", map[string]interface{}{
			"ttl_seconds": int(p.ttl / time.Second),
			"expires_at":  p.expiry.UTC().Format(time.RFC3339),
		})
	}
	return mk, nil
}

// IsAvailable 实现 AuthProvider 接口
// 检查 Keychain 中是否存在 master key
func (p *TouchIDProvider) IsAvailable() bool {
	exists, err := keychain.MasterKeyExists()
	return err == nil && exists
}

// Mode 实现 AuthProvider 接口
func (p *TouchIDProvider) Mode() AuthMode {
	return ModeTouchID
}

// ClearCache 实现 AuthProvider 接口
// 安全清零缓存的 master key，下次签名需要重新 Touch ID
func (p *TouchIDProvider) ClearCache() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cachedKey != nil {
		secureClear(p.cachedKey)
		p.cachedKey = nil
	}
	p.expiry = time.Time{}
}
