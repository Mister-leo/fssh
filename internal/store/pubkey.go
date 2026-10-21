package store

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// PubKeysDir holds "<alias>.pub" files. ssh_config can point IdentityFile at
// them to select one key from the agent (IdentitiesOnly), and they give users
// the public key to install on servers.
func PubKeysDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".fssh", "pubkeys")
}

// PubKeyPath returns the public key file for alias.
func PubKeyPath(alias string) (string, error) {
	if err := checkAliasPath(alias); err != nil {
		return "", err
	}
	return filepath.Join(PubKeysDir(), alias+".pub"), nil
}

// PublicKey parses the record's public key.
func (ef *EncryptedFile) PublicKey() (ssh.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(ef.PubKey)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePublicKey(b)
}

// AuthorizedKey returns the authorized_keys line, commented with the alias.
func (ef *EncryptedFile) AuthorizedKey() (string, error) {
	pk, err := ef.PublicKey()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " " + ef.Alias, nil
}

// KeyDescription returns a short type label such as "ED25519", "RSA-3072"
// or "ECDSA-P256".
func KeyDescription(pk ssh.PublicKey) string {
	if cpk, ok := pk.(ssh.CryptoPublicKey); ok {
		switch k := cpk.CryptoPublicKey().(type) {
		case *rsa.PublicKey:
			return fmt.Sprintf("RSA-%d", k.N.BitLen())
		case *ecdsa.PublicKey:
			return "ECDSA-" + strings.ReplaceAll(k.Curve.Params().Name, "-", "") // P-256 -> P256
		}
	}
	switch pk.Type() {
	case ssh.KeyAlgoED25519:
		return "ED25519"
	}
	return strings.ToUpper(strings.TrimPrefix(pk.Type(), "ssh-"))
}

func writePubKey(ef *EncryptedFile) error {
	line, err := ef.AuthorizedKey()
	if err != nil {
		return err
	}
	path, err := PubKeyPath(ef.Alias)
	if err != nil {
		return err
	}
	if b, err := os.ReadFile(path); err == nil && string(b) == line+"\n" {
		return nil
	}
	if err := os.MkdirAll(PubKeysDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(line+"\n"), 0644)
}

// SyncPubKeys writes missing public key files and removes ones whose record
// no longer exists. Keys imported by older versions get their files here.
func SyncPubKeys() error {
	metas, err := ListMeta()
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for i := range metas {
		want[metas[i].Alias+".pub"] = true
		if err := writePubKey(&metas[i]); err != nil {
			return fmt.Errorf("write public key for %s: %w", metas[i].Alias, err)
		}
	}
	entries, err := os.ReadDir(PubKeysDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".pub") && !want[e.Name()] {
			os.Remove(filepath.Join(PubKeysDir(), e.Name()))
		}
	}
	return nil
}

// RemoveRecord deletes a key's encrypted record and its public key file.
func RemoveRecord(alias string) error {
	path, err := RecordPath(alias)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	if pub, err := PubKeyPath(alias); err == nil {
		os.Remove(pub)
	}
	return nil
}
