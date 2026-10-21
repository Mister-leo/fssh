package crypt

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// RFC 5869 Appendix A.1 (HKDF-SHA256, basic test case).
func TestHKDFRFC5869(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	if got := hex.EncodeToString(HKDF(ikm, salt, info, 42)); got != want {
		t.Fatalf("HKDF = %s, want %s", got, want)
	}
}

func TestAEADRoundTripAndTamper(t *testing.T) {
	key, _ := RandBytes(rand.Reader, 32)
	nonce, _ := RandBytes(rand.Reader, 12)
	pt := []byte("private key bytes")
	ct, err := EncryptAEAD(key, nonce, pt, []byte("SHA256:fp"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptAEAD(key, nonce, ct, []byte("SHA256:fp"))
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("round trip: %q, %v", got, err)
	}
	// the fingerprint is authenticated: swapping records between keys fails
	if _, err := DecryptAEAD(key, nonce, ct, []byte("SHA256:other")); err == nil {
		t.Fatal("wrong AAD accepted")
	}
	ct[0] ^= 1
	if _, err := DecryptAEAD(key, nonce, ct, []byte("SHA256:fp")); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
