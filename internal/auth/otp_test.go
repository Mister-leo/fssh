package auth

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"

	"fssh/internal/i18n"
	"fssh/internal/otp"
)

// fakePrompter answers OTP prompts and records what was asked.
type fakePrompter struct {
	mu        sync.Mutex
	passwords []string // consumed in order; the last one repeats
	seed      []byte   // when set, Text answers with the current TOTP code
	code      string   // fixed code when seed is nil
	asked     []string
	notified  []string
}

func (f *fakePrompter) Password(msg string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, "password:"+msg)
	if len(f.passwords) == 0 {
		return "", errors.New("no password")
	}
	p := f.passwords[0]
	if len(f.passwords) > 1 {
		f.passwords = f.passwords[1:]
	}
	return p, nil
}

func (f *fakePrompter) Text(msg string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, "code:"+msg)
	if f.seed != nil {
		return otp.GetCurrentCode(f.seed, "SHA1", 6, 30), nil
	}
	return f.code, nil
}

func (f *fakePrompter) Notify(title, msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notified = append(f.notified, msg)
}

func (f *fakePrompter) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, a := range f.asked {
		if strings.HasPrefix(a, prefix) {
			n++
		}
	}
	return n
}

const testPassword = "correct horse battery"

// nopCounters disables replay protection for tests that need several codes
// within one 30-second window.
type nopCounters struct{}

func (nopCounters) Last() int64        { return 0 }
func (nopCounters) Record(int64) error { return nil }

func newTestOTPProvider(t *testing.T, ttl int) *OTPProvider {
	t.Helper()
	p, err := NewOTPProvider(ttl)
	if err != nil {
		t.Fatal(err)
	}
	p.counters = nopCounters{}
	return p
}

// setupOTP initializes OTP in a temp HOME. seedTTL controls password caching.
func setupOTP(t *testing.T, seedTTL int, recovery bool) []byte {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	seed, _, err := otp.Initialize(&otp.InitOptions{
		Password:         testPassword,
		SeedUnlockTTL:    seedTTL,
		Algorithm:        "SHA1",
		Digits:           6,
		Period:           30,
		GenerateRecovery: recovery,
	})
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

func TestOTPUnlockAndMasterKeyCache(t *testing.T) {
	seed := setupOTP(t, 3600, false)
	p := newTestOTPProvider(t, 600)
	fp := &fakePrompter{passwords: []string{testPassword}, seed: seed}

	mk1, err := p.UnlockMasterKey(Request{Reason: "ssh wants key work", Prompter: fp})
	if err != nil {
		t.Fatal(err)
	}
	mk2, err := p.UnlockMasterKey(Request{Prompter: fp})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mk1, mk2) || len(mk1) != 32 {
		t.Fatal("cached master key differs")
	}
	if fp.count("password:") != 1 || fp.count("code:") != 1 {
		t.Fatalf("prompts = %v, want one password and one code", fp.asked)
	}
	if !strings.Contains(fp.asked[0], "ssh wants key work") {
		t.Fatalf("prompt does not show the reason: %q", fp.asked[0])
	}
}

func TestOTPNoCacheAsksCodeButReusesPassword(t *testing.T) {
	seed := setupOTP(t, 3600, false)
	p := newTestOTPProvider(t, 600)
	fp := &fakePrompter{passwords: []string{testPassword}, seed: seed}

	for i := 0; i < 2; i++ {
		if _, err := p.UnlockMasterKey(Request{NoCache: true, Prompter: fp}); err != nil {
			t.Fatal(err)
		}
	}
	// password is covered by the seed cache, but every forwarded request needs a code
	if fp.count("password:") != 1 || fp.count("code:") != 2 {
		t.Fatalf("prompts = %v", fp.asked)
	}
}

func TestOTPWrongPasswordRetriesThenFails(t *testing.T) {
	seed := setupOTP(t, 0, false)
	p := newTestOTPProvider(t, 0)

	fp := &fakePrompter{passwords: []string{"wrong-password-1", testPassword}, seed: seed}
	if _, err := p.UnlockMasterKey(Request{Prompter: fp}); err != nil {
		t.Fatalf("second attempt should succeed: %v", err)
	}
	if fp.count("password:") != 2 || !strings.Contains(fp.asked[1], i18n.T("otp.retry_password")) {
		t.Fatalf("prompts = %v", fp.asked)
	}

	fp = &fakePrompter{passwords: []string{"wrong-password-1"}, seed: seed}
	if _, err := p.UnlockMasterKey(Request{Prompter: fp}); err == nil {
		t.Fatal("expected failure after repeated wrong passwords")
	}
	if fp.count("password:") != otpMaxAttempts || fp.count("code:") != 0 {
		t.Fatalf("prompts = %v", fp.asked)
	}
}

func TestOTPWrongCodeFails(t *testing.T) {
	setupOTP(t, 0, false)
	p := newTestOTPProvider(t, 0)
	fp := &fakePrompter{passwords: []string{testPassword}, code: "000000"}
	if _, err := p.UnlockMasterKey(Request{Prompter: fp}); err == nil {
		t.Fatal("wrong code accepted")
	}
	if fp.count("code:") != otpMaxAttempts {
		t.Fatalf("code prompts = %d, want %d", fp.count("code:"), otpMaxAttempts)
	}
}

func TestOTPConcurrentRequestsShowOneDialog(t *testing.T) {
	seed := setupOTP(t, 3600, false)
	p := newTestOTPProvider(t, 600)
	fp := &fakePrompter{passwords: []string{testPassword}, seed: seed}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.UnlockMasterKey(Request{Prompter: fp}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if fp.count("password:") != 1 || fp.count("code:") != 1 {
		t.Fatalf("prompts = %v, want exactly one of each", fp.asked)
	}
}

func TestOTPPrepareRekey(t *testing.T) {
	seed := setupOTP(t, 3600, false)
	p := newTestOTPProvider(t, 600)
	fp := &fakePrompter{passwords: []string{testPassword}, seed: seed}

	before, err := p.UnlockMasterKey(Request{Prompter: fp})
	if err != nil {
		t.Fatal(err)
	}
	rk, err := p.PrepareRekey(Request{Prompter: fp})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rk.OldKey, before) || bytes.Equal(rk.NewKey, before) {
		t.Fatal("rekey keys are wrong")
	}
	if err := rk.Commit(); err != nil {
		t.Fatal(err)
	}
	// after commit the provider (reloading config) must derive the new key
	after, err := p.UnlockMasterKey(Request{Prompter: fp})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, rk.NewKey) {
		t.Fatal("after commit, unlock does not yield the new master key")
	}
}

func TestOTPLegacyRecoveryWarnsOnce(t *testing.T) {
	seed := setupOTP(t, 3600, false)
	// simulate a config written by an older version: hashes only
	if err := otp.UpdateConfig(func(c *otp.Config) error {
		c.RecoveryCodesHash = []string{"deadbeef"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p := newTestOTPProvider(t, 0)
	fp := &fakePrompter{passwords: []string{testPassword}, seed: seed}
	for i := 0; i < 2; i++ {
		if _, err := p.UnlockMasterKey(Request{Prompter: fp}); err != nil {
			t.Fatal(err)
		}
	}
	if len(fp.notified) != 1 {
		t.Fatalf("legacy recovery notices = %d, want 1", len(fp.notified))
	}
}

func TestOTPRejectsReplayedCode(t *testing.T) {
	seed := setupOTP(t, 3600, false)
	p, err := NewOTPProvider(0) // real file-backed replay guard
	if err != nil {
		t.Fatal(err)
	}
	code := otp.GetCurrentCode(seed, "SHA1", 6, 30)
	fp := &fakePrompter{passwords: []string{testPassword}, code: code}

	if _, err := p.UnlockMasterKey(Request{Prompter: fp}); err != nil {
		t.Fatalf("first use: %v", err)
	}
	// a new process (fresh provider) must not accept the same code either
	p2, _ := NewOTPProvider(0)
	fp2 := &fakePrompter{passwords: []string{testPassword}, code: code}
	if _, err := p2.UnlockMasterKey(Request{Prompter: fp2}); err == nil {
		t.Fatal("replayed TOTP code accepted")
	}
	if !strings.Contains(strings.Join(fp2.asked, "\n"), i18n.T("otp.retry_code_used")) {
		t.Fatalf("user not told the code was already used: %v", fp2.asked)
	}
}
