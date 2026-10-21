package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func setupHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// newKeyPEM returns an OpenSSH-format ed25519 private key.
func newKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func masterKey() []byte { return bytes.Repeat([]byte{7}, 32) }

func TestValidateAlias(t *testing.T) {
	valid := []string{"github", "work-rsa", "id_ed25519", "a.b", "K1", "x123456789012345678901234567890123456789012345678901234567890123"}
	invalid := []string{"", "-lead", ".hidden", "_x", "has space", "a/b", "../etc", "中文", "x1234567890123456789012345678901234567890123456789012345678901234"}
	for _, a := range valid {
		if err := ValidateAlias(a); err != nil {
			t.Errorf("ValidateAlias(%q) = %v, want nil", a, err)
		}
	}
	for _, a := range invalid {
		if err := ValidateAlias(a); !errors.Is(err, ErrInvalidAlias) {
			t.Errorf("ValidateAlias(%q) = %v, want ErrInvalidAlias", a, err)
		}
	}
}

func TestRecordPathRejectsTraversal(t *testing.T) {
	setupHome(t)
	for _, a := range []string{"", ".", "..", "../x", "a/b", `a\b`, "a\x00b"} {
		if _, err := RecordPath(a); !errors.Is(err, ErrInvalidAlias) {
			t.Errorf("RecordPath(%q) = %v, want ErrInvalidAlias", a, err)
		}
	}
	// Legacy aliases that predate ValidateAlias must stay usable.
	if _, err := RecordPath("my key"); err != nil {
		t.Errorf("RecordPath(legacy alias) = %v", err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	setupHome(t)
	rec, err := NewRecordFromPrivateKeyBytes("work", newKeyPEM(t), "", "c")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveEncryptedRecord(rec, masterKey()); err != nil {
		t.Fatal(err)
	}

	path, _ := RecordPath("work")
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("record file mode = %v, err = %v; want 0600", fi.Mode().Perm(), err)
	}

	got, err := LoadDecryptedRecord("work", masterKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.PKCS8DER, rec.PKCS8DER) || got.Fingerprint != rec.Fingerprint {
		t.Fatal("decrypted record does not match")
	}

	if _, err := LoadDecryptedRecord("work", bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Fatal("decrypting with the wrong master key must fail")
	}
}

func TestMetaLookup(t *testing.T) {
	setupHome(t)
	if _, err := LoadMeta("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadMeta(missing) = %v, want ErrNotFound", err)
	}
	if metas, err := ListMeta(); err != nil || len(metas) != 0 {
		t.Fatalf("ListMeta on empty store = %v, %v", metas, err)
	}

	rec, err := NewRecordFromPrivateKeyBytes("a", newKeyPEM(t), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveEncryptedRecord(rec, masterKey()); err != nil {
		t.Fatal(err)
	}
	// A stray non-record file must be ignored.
	if err := os.WriteFile(filepath.Join(KeysDir(), "notes.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	m, err := LoadMeta("a")
	if err != nil || m.Fingerprint != rec.Fingerprint {
		t.Fatalf("LoadMeta(a) = %+v, %v", m, err)
	}
	metas, err := ListMeta()
	if err != nil || len(metas) != 1 {
		t.Fatalf("ListMeta = %d records, %v; want 1", len(metas), err)
	}
	alias, ok, err := FindByFingerprint(rec.Fingerprint)
	if err != nil || !ok || alias != "a" {
		t.Fatalf("FindByFingerprint = %q, %v, %v", alias, ok, err)
	}
	if _, ok, _ := FindByFingerprint("SHA256:nope"); ok {
		t.Fatal("FindByFingerprint matched an unknown fingerprint")
	}
}
