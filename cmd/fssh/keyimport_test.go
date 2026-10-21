package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"fssh/internal/i18n"
	"fssh/internal/store"

	"golang.org/x/crypto/ssh"
)

func encryptedKeyPEM(t *testing.T, passphrase string) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func TestParseKeyNonInteractiveErrors(t *testing.T) {
	i18n.Set(i18n.EN)
	t.Cleanup(func() { i18n.Set("") })

	key := encryptedKeyPEM(t, "secret123")

	cases := []struct {
		name string
		data []byte
		pass string
		want string
	}{
		{"missing passphrase", key, "", i18n.T("import.err_passphrase_required")},
		{"wrong passphrase", key, "wrong", i18n.T("import.err_passphrase_wrong")},
		{"public key file", []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLACEHOLDER test"), "", i18n.T("import.err_not_private_key")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseKeyWithRetry("k", c.data, c.pass, "", false, "")
			if err == nil || err.Error() != c.want {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}

	rec, err := parseKeyWithRetry("k", key, "secret123", "", false, "")
	if err != nil || rec.Fingerprint == "" {
		t.Fatalf("correct passphrase: rec=%v err=%v", rec, err)
	}
}

func TestSanitizeAlias(t *testing.T) {
	cases := map[string]string{
		"ed25519":   "ed25519",
		"my key":    "my-key",
		".hidden":   "hidden",
		"中文":        "key",
		"work@corp": "work-corp",
		"___":       "key",
	}
	for in, want := range cases {
		got := sanitizeAlias(in)
		if got != want {
			t.Errorf("sanitizeAlias(%q) = %q, want %q", in, got, want)
		}
		if err := store.ValidateAlias(got); err != nil {
			t.Errorf("sanitizeAlias(%q) = %q is not a valid alias", in, got)
		}
	}
}

func TestUniqueAlias(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if got := uniqueAlias("rsa"); got != "rsa" {
		t.Fatalf("empty store: got %q", got)
	}
	for _, alias := range []string{"rsa", "rsa-2"} {
		rec, err := store.NewRecordFromPrivateKeyBytes(alias, encryptedKeyPEM(t, ""), "", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SaveEncryptedRecord(rec, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	}
	if got := uniqueAlias("rsa"); got != "rsa-3" {
		t.Fatalf("got %q, want rsa-3", got)
	}
}
