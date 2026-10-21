package otp

import (
	"bytes"
	"encoding/base32"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// RFC 6238 Appendix B test vectors (8 digits).
func TestTOTPRFC6238Vectors(t *testing.T) {
	seeds := map[string][]byte{
		"SHA1":   []byte("12345678901234567890"),
		"SHA256": []byte("12345678901234567890123456789012"),
		"SHA512": []byte("1234567890123456789012345678901234567890123456789012345678901234"),
	}
	cases := []struct {
		t    int64
		algo string
		want string
	}{
		{59, "SHA1", "94287082"},
		{59, "SHA256", "46119246"},
		{59, "SHA512", "90693936"},
		{1111111109, "SHA1", "07081804"},
		{1111111109, "SHA256", "68084774"},
		{1111111109, "SHA512", "25091201"},
		{20000000000, "SHA1", "65353130"},
		{20000000000, "SHA256", "77737706"},
		{20000000000, "SHA512", "47863826"},
	}
	for _, c := range cases {
		if got := Generate(seeds[c.algo], c.t/30, c.algo, 8); got != c.want {
			t.Errorf("T=%d %s: got %s, want %s", c.t, c.algo, got, c.want)
		}
	}
}

func TestSecretIsBase32(t *testing.T) {
	seed := []byte("12345678901234567890")
	s := SecretBase32(seed)
	if s != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Fatalf("SecretBase32 = %q", s)
	}
	back, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil || !bytes.Equal(back, seed) {
		t.Fatal("secret does not round-trip through Base32")
	}

	uri := OTPAuthURI(seed, "alice@mac", "SHA1", 6, 30)
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("bad URI %q: %v", uri, err)
	}
	q := u.Query()
	if q.Get("secret") != s || q.Get("issuer") != "fssh" || q.Get("digits") != "6" || q.Get("period") != "30" {
		t.Fatalf("bad URI query: %q", uri)
	}
	if !strings.HasPrefix(u.Path, "/fssh:alice@mac") {
		t.Fatalf("bad URI label: %q", u.Path)
	}
}

func TestPasswordSeedRoundTrip(t *testing.T) {
	seed := []byte("12345678901234567890")
	cfg := &Config{}
	if err := SetPassword(cfg, "short", seed); err == nil {
		t.Fatal("weak password accepted")
	}
	if err := SetPassword(cfg, "a long enough password", seed); err != nil {
		t.Fatal(err)
	}
	got, err := DecryptSeed(cfg, "a long enough password")
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("DecryptSeed = %v, %v", got, err)
	}
	if _, err := DecryptSeed(cfg, "wrong password!!"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: err = %v", err)
	}
}

func TestRecoveryCodes(t *testing.T) {
	seed := []byte("12345678901234567890")
	cfg := &Config{}
	codes, err := SetRecoveryCodes(cfg, seed, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 3 || len(cfg.RecoveryWrapped) != 3 || cfg.LegacyRecovery() {
		t.Fatal("unexpected recovery state")
	}

	// users may type lowercase, without dashes, with spaces
	sloppy := strings.ToLower(strings.ReplaceAll(codes[1], "-", " "))
	got, idx, err := RecoverSeed(cfg, sloppy)
	if err != nil || idx != 1 || !bytes.Equal(got, seed) {
		t.Fatalf("RecoverSeed = %v, %d, %v", got, idx, err)
	}

	RemoveRecoveryCode(cfg, idx)
	if _, _, err := RecoverSeed(cfg, codes[1]); !errors.Is(err, ErrInvalidRecoveryCode) {
		t.Fatal("a used recovery code must not work twice")
	}
	if _, _, err := RecoverSeed(cfg, codes[0]); err != nil {
		t.Fatalf("other codes must keep working: %v", err)
	}
	if _, _, err := RecoverSeed(cfg, "AAAA-BBBB-CCCC-DDDD"); !errors.Is(err, ErrInvalidRecoveryCode) {
		t.Fatal("unknown code accepted")
	}
}

func TestLegacyRecoveryDetection(t *testing.T) {
	legacy := &Config{RecoveryCodesHash: HashRecoveryCodes([]string{"AAAA-BBBB-CCCC-DDDD"})}
	if !legacy.LegacyRecovery() {
		t.Fatal("hash-only config should be legacy")
	}
	if _, _, err := RecoverSeed(legacy, "AAAA-BBBB-CCCC-DDDD"); !errors.Is(err, ErrInvalidRecoveryCode) {
		t.Fatal("legacy codes cannot recover the seed")
	}
	if (&Config{}).LegacyRecovery() {
		t.Fatal("config without codes is not legacy")
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	for in, want := range map[string]string{
		"abcd-efgh-jkmn-pqrs":   "ABCD-EFGH-JKMN-PQRS",
		"ABCDEFGHJKMNPQRS":      "ABCD-EFGH-JKMN-PQRS",
		" abcd efgh jkmn pqrs ": "ABCD-EFGH-JKMN-PQRS",
		"short":                 "SHORT",
	} {
		if got := NormalizeRecoveryCode(in); got != want {
			t.Errorf("NormalizeRecoveryCode(%q) = %q, want %q", in, got, want)
		}
	}
}
