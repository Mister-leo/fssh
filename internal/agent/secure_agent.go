package agentserver

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"encoding/json"
	"fssh/internal/keychain"
	"fssh/internal/log"
	"fssh/internal/store"

	"golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

type secureAgent struct {
	metas  []store.EncryptedFile
	mu     sync.Mutex
	cached []byte
	expiry time.Time
	ttl    int
}

func newSecureAgentWithTTL(ttlSeconds int) (*secureAgent, error) {
	dir := store.KeysDir()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	var metas []store.EncryptedFile
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".enc" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m store.EncryptedFile
		if err := jsonUnmarshal(b, &m); err != nil {
			continue
		}
		metas = append(metas, m)
	}
	return &secureAgent{metas: metas, ttl: ttlSeconds}, nil
}

func (a *secureAgent) List() ([]*xagent.Key, error) {
	var ks []*xagent.Key
	for _, m := range a.metas {
		if m.PubKey == "" {
			continue
		}
		pb, err := base64.StdEncoding.DecodeString(m.PubKey)
		if err != nil {
			continue
		}
		pk, err := ssh.ParsePublicKey(pb)
		if err != nil {
			continue
		}
		ks = append(ks, &xagent.Key{Format: pk.Type(), Blob: pk.Marshal(), Comment: m.Alias})
	}
	return ks, nil
}

func (a *secureAgent) Sign(pubkey ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	fp := ssh.FingerprintSHA256(pubkey)
	var alias string
	for _, m := range a.metas {
		if m.Fingerprint == fp {
			alias = m.Alias
			break
		}
	}
	if alias == "" {
		return nil, errors.New("key not found")
	}
	mk, err := a.masterKey()
	if err != nil {
		return nil, err
	}
	rec, err := store.LoadDecryptedRecord(alias, mk)
	if err != nil {
		return nil, err
	}
	priv, err := x509.ParsePKCS8PrivateKey(rec.PKCS8DER)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	if debugOn() {
		debugf("agent sign default fp=%s type=%s", fp, signer.PublicKey().Type())
	}
	return signer.Sign(nil, data)
}

// Support RSA-SHA2 algorithms when requested by the client.
func (a *secureAgent) SignWithFlags(pubkey ssh.PublicKey, data []byte, flags xagent.SignatureFlags) (*ssh.Signature, error) {
	fp := ssh.FingerprintSHA256(pubkey)
	var alias string
	for _, m := range a.metas {
		if m.Fingerprint == fp {
			alias = m.Alias
			break
		}
	}
	if alias == "" {
		return nil, errors.New("key not found")
	}
	mk, err := a.masterKey()
	if err != nil {
		return nil, err
	}
	rec, err := store.LoadDecryptedRecord(alias, mk)
	if err != nil {
		return nil, err
	}
	priv, err := x509.ParsePKCS8PrivateKey(rec.PKCS8DER)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}

	if algSigner, ok := signer.(ssh.AlgorithmSigner); ok {
		algo := ""
		if (flags & xagent.SignatureFlagRsaSha512) != 0 {
			algo = "rsa-sha2-512"
		} else if (flags & xagent.SignatureFlagRsaSha256) != 0 {
			algo = "rsa-sha2-256"
		}
		if algo != "" {
			if debugOn() {
				debugf("agent sign flags=%d algo=%s fp=%s", flags, algo, fp)
			}
			return algSigner.SignWithAlgorithm(rand.Reader, data, algo)
		}
	}
	if debugOn() {
		debugf("agent sign flags=%d fallback fp=%s", flags, fp)
	}
	return signer.Sign(nil, data)
}

func (a *secureAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType == "ext-info-c" {
		// Advertise support for RSA SHA-256 and SHA-512 signature flags as a uint32 bitmask (big-endian)
		flags := uint32(xagent.SignatureFlagRsaSha256 | xagent.SignatureFlagRsaSha512)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, flags)
		if debugOn() {
			debugf("agent extension ext-info-c flags=%d", flags)
		}
		return b, nil
	}
	if debugOn() {
		debugf("agent extension unsupported type=%s", extensionType)
	}
	return nil, errors.New("unsupported extension")
}

func (a *secureAgent) Add(key xagent.AddedKey) error     { return errors.New("unsupported") }
func (a *secureAgent) Remove(pubkey ssh.PublicKey) error { return errors.New("unsupported") }
func (a *secureAgent) RemoveAll() error                  { return nil }
func (a *secureAgent) Lock(passphrase []byte) error      { return nil }
func (a *secureAgent) Unlock(passphrase []byte) error    { return nil }
func (a *secureAgent) Signers() ([]ssh.Signer, error)    { return nil, errors.New("unsupported") }

func jsonUnmarshal(b []byte, v interface{}) error { return json.Unmarshal(b, v) }

func debugOn() bool {
	v := os.Getenv("FSSH_DEBUG")
	return v == "1" || v == "true" || v == "TRUE"
}

func debugf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func (a *secureAgent) masterKey() ([]byte, error) {
	if a.ttl <= 0 {
		return keychain.LoadMasterKey()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if a.cached != nil && now.Before(a.expiry) {
		log.Debug("master key cache hit", map[string]interface{}{"expires_at": a.expiry.UTC().Format(time.RFC3339)})
		return a.cached, nil
	}
	mk, err := keychain.LoadMasterKey()
	if err != nil { return nil, err }
	a.cached = mk
	a.expiry = now.Add(time.Duration(a.ttl) * time.Second)
	log.Info("master key unlocked", map[string]interface{}{"ttl_sec": a.ttl})
	return mk, nil
}
