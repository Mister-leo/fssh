package otp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"fssh/internal/crypt"

	"golang.org/x/crypto/pbkdf2"
)

var (
	ErrWrongPassword       = errors.New("wrong OTP password or corrupted config")
	ErrInvalidRecoveryCode = errors.New("invalid or already used recovery code")
)

const pbkdf2Iterations = 100000

// WrappedSeed is the OTP seed encrypted with a key derived from a secret
// (the password or a recovery code) via PBKDF2-SHA256.
type WrappedSeed struct {
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func sealSeed(secret string, seed []byte) (WrappedSeed, error) {
	salt := make([]byte, 32)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return WrappedSeed{}, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return WrappedSeed{}, err
	}
	key := pbkdf2.Key([]byte(secret), salt, pbkdf2Iterations, 32, sha256.New)
	ct, err := crypt.EncryptAEAD(key, nonce, seed, nil)
	if err != nil {
		return WrappedSeed{}, err
	}
	return WrappedSeed{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

func openSeed(secret string, w WrappedSeed) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(w.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(w.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(w.Ciphertext)
	if err != nil {
		return nil, err
	}
	key := pbkdf2.Key([]byte(secret), salt, pbkdf2Iterations, 32, sha256.New)
	return crypt.DecryptAEAD(key, nonce, ct, nil)
}

// DecryptSeed decrypts the OTP seed with the user's password.
func DecryptSeed(cfg *Config, password string) ([]byte, error) {
	seed, err := openSeed(password, WrappedSeed{Salt: cfg.SeedSalt, Nonce: cfg.SeedNonce, Ciphertext: cfg.EncryptedSeed})
	if err != nil {
		return nil, ErrWrongPassword
	}
	return seed, nil
}

// SetPassword re-encrypts the seed under a new password (fresh salt and nonce).
func SetPassword(cfg *Config, password string, seed []byte) error {
	if err := ValidatePasswordStrength(password); err != nil {
		return err
	}
	w, err := sealSeed(password, seed)
	if err != nil {
		return fmt.Errorf("encrypt OTP seed: %w", err)
	}
	cfg.SeedSalt, cfg.SeedNonce, cfg.EncryptedSeed = w.Salt, w.Nonce, w.Ciphertext
	return nil
}

// SecretBase32 encodes the seed the way authenticator apps expect (RFC 4648
// Base32 without padding).
func SecretBase32(seed []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
}

// OTPAuthURI builds the otpauth:// URI understood by authenticator apps and QR codes.
func OTPAuthURI(seed []byte, account, algorithm string, digits, period int) string {
	q := url.Values{}
	q.Set("secret", SecretBase32(seed))
	q.Set("issuer", "fssh")
	q.Set("algorithm", algorithm)
	q.Set("digits", strconv.Itoa(digits))
	q.Set("period", strconv.Itoa(period))
	return "otpauth://totp/" + url.PathEscape("fssh:"+account) + "?" + q.Encode()
}
