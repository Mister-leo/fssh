package auth

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock 可手动推进的时钟
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestProvider 返回使用假 unlock 和假时钟的 provider，以及 unlock 调用计数
func newTestProvider(ttlSeconds int, unlock func() ([]byte, error)) (*TouchIDProvider, *fakeClock, *int32) {
	var calls int32
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	p := NewTouchIDProvider(ttlSeconds)
	p.now = clock.now
	p.unlock = func(string) ([]byte, error) {
		atomic.AddInt32(&calls, 1)
		return unlock()
	}
	return p, clock, &calls
}

func testKey() ([]byte, error) { return bytes.Repeat([]byte{0xAB}, 32), nil }

func TestTouchIDCacheHitWithinTTL(t *testing.T) {
	p, clock, calls := newTestProvider(600, testKey)

	for i := 0; i < 5; i++ {
		mk, err := p.UnlockMasterKey(Request{})
		if err != nil {
			t.Fatalf("unlock #%d: %v", i, err)
		}
		if len(mk) != 32 {
			t.Fatalf("unlock #%d: key len = %d", i, len(mk))
		}
		clock.advance(time.Minute)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("Touch ID prompts = %d, want 1", got)
	}
}

func TestTouchIDCacheExpires(t *testing.T) {
	p, clock, calls := newTestProvider(600, testKey)

	if _, err := p.UnlockMasterKey(Request{}); err != nil {
		t.Fatal(err)
	}
	clock.advance(600 * time.Second)
	if _, err := p.UnlockMasterKey(Request{}); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Fatalf("Touch ID prompts = %d, want 2 (cache should expire at TTL)", got)
	}
}

func TestTouchIDZeroTTLAlwaysPrompts(t *testing.T) {
	p, _, calls := newTestProvider(0, testKey)

	for i := 0; i < 3; i++ {
		if _, err := p.UnlockMasterKey(Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt32(calls); got != 3 {
		t.Fatalf("Touch ID prompts = %d, want 3", got)
	}
}

func TestTouchIDFailureNotCached(t *testing.T) {
	fail := true
	p, _, calls := newTestProvider(600, func() ([]byte, error) {
		if fail {
			return nil, errors.New("biometry/user presence failed")
		}
		return testKey()
	})

	if _, err := p.UnlockMasterKey(Request{}); err == nil {
		t.Fatal("expected error when Touch ID is cancelled")
	}
	fail = false
	if _, err := p.UnlockMasterKey(Request{}); err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Fatalf("Touch ID prompts = %d, want 2", got)
	}
}

func TestTouchIDConcurrentRequestsPromptOnce(t *testing.T) {
	p, _, calls := newTestProvider(600, func() ([]byte, error) {
		time.Sleep(50 * time.Millisecond) // 模拟用户按指纹的耗时
		return testKey()
	})

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.UnlockMasterKey(Request{}); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("Touch ID prompts = %d, want 1 for concurrent signatures", got)
	}
}

func TestTouchIDClearCache(t *testing.T) {
	p, _, calls := newTestProvider(600, testKey)

	first, err := p.UnlockMasterKey(Request{})
	if err != nil {
		t.Fatal(err)
	}
	cached, err := p.UnlockMasterKey(Request{})
	if err != nil {
		t.Fatal(err)
	}
	p.ClearCache()

	// 已返回给调用方的 key 不应被清零
	if !bytes.Equal(first, cached) || bytes.Equal(cached, make([]byte, 32)) {
		t.Fatal("ClearCache must not zero keys already handed to callers")
	}
	if _, err := p.UnlockMasterKey(Request{}); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Fatalf("Touch ID prompts = %d, want 2 after ClearCache", got)
	}
}

func TestTouchIDNoCacheAlwaysPromptsAndDoesNotCache(t *testing.T) {
	p, _, calls := newTestProvider(600, testKey)

	for i := 0; i < 2; i++ {
		if _, err := p.UnlockMasterKey(Request{NoCache: true}); err != nil {
			t.Fatal(err)
		}
	}
	// a NoCache unlock must not fill the cache for later requests
	if _, err := p.UnlockMasterKey(Request{}); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(calls); got != 3 {
		t.Fatalf("Touch ID prompts = %d, want 3", got)
	}
}

func TestTouchIDPassesReason(t *testing.T) {
	p := NewTouchIDProvider(0)
	var got string
	p.unlock = func(reason string) ([]byte, error) { got = reason; return testKey() }

	if _, err := p.UnlockMasterKey(Request{Reason: "ssh wants key work"}); err != nil {
		t.Fatal(err)
	}
	if got != "ssh wants key work" {
		t.Fatalf("reason = %q", got)
	}
	if _, err := p.UnlockMasterKey(Request{}); err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("empty Request.Reason must fall back to a default reason")
	}
}

func TestTouchIDPrepareRekey(t *testing.T) {
	p, _, calls := newTestProvider(600, testKey)
	var stored []byte
	p.store = func(k []byte) error { stored = append([]byte(nil), k...); return nil }

	// warm the cache, rekey must still authenticate
	if _, err := p.UnlockMasterKey(Request{}); err != nil {
		t.Fatal(err)
	}
	rk, err := p.PrepareRekey(Request{})
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Fatalf("rekey must authenticate even with a warm cache, prompts = %d", got)
	}
	if bytes.Equal(rk.OldKey, rk.NewKey) || len(rk.NewKey) != 32 {
		t.Fatal("new key must be a fresh 32-byte key")
	}
	if stored != nil {
		t.Fatal("new key stored before Commit")
	}
	if err := rk.Commit(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, rk.NewKey) {
		t.Fatal("Commit did not store the new key")
	}
	if p.cachedKey != nil {
		t.Fatal("Commit must clear the cached old key")
	}
}
