package store

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

func saveTestKey(t *testing.T, alias string, mk []byte) *Record {
	t.Helper()
	rec, err := NewRecordFromPrivateKeyBytes(alias, newKeyPEM(t), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveEncryptedRecord(rec, mk); err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestReencryptAll(t *testing.T) {
	setupHome(t)
	oldKey, newKey := masterKey(), bytes.Repeat([]byte{9}, 32)
	a := saveTestKey(t, "a", oldKey)
	saveTestKey(t, "b", oldKey)
	if err := os.WriteFile(filepath.Join(KeysDir(), "notes.txt"), []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	metaBefore, _ := LoadMeta("a")

	committed := false
	n, err := ReencryptAll([][]byte{oldKey}, newKey, func() error { committed = true; return nil })
	if err != nil || n != 2 || !committed {
		t.Fatalf("ReencryptAll = %d, %v, committed=%v", n, err, committed)
	}
	got, err := LoadDecryptedRecord("a", newKey)
	if err != nil || !bytes.Equal(got.PKCS8DER, a.PKCS8DER) {
		t.Fatalf("record not readable with new key: %v", err)
	}
	if _, err := LoadDecryptedRecord("a", oldKey); err == nil {
		t.Fatal("record still readable with old key")
	}
	if metaAfter, _ := LoadMeta("a"); metaAfter.CreatedAt != metaBefore.CreatedAt {
		t.Fatalf("CreatedAt changed: %q -> %q", metaBefore.CreatedAt, metaAfter.CreatedAt)
	}
	if b, err := os.ReadFile(filepath.Join(KeysDir(), "notes.txt")); err != nil || string(b) != "keep me" {
		t.Fatal("non-record files must survive the directory swap")
	}
	for _, leftover := range []string{KeysDir() + ".new", KeysDir() + ".old"} {
		if _, err := os.Stat(leftover); !os.IsNotExist(err) {
			t.Fatalf("%s left behind", leftover)
		}
	}
}

// A record that cannot be decrypted must abort before commit and leave the
// store exactly as it was.
func TestReencryptAllAbortsOnUndecryptableRecord(t *testing.T) {
	setupHome(t)
	oldKey, newKey := masterKey(), bytes.Repeat([]byte{9}, 32)
	saveTestKey(t, "a", oldKey)
	saveTestKey(t, "z", bytes.Repeat([]byte{3}, 32)) // under a different key

	committed := false
	if _, err := ReencryptAll([][]byte{oldKey}, newKey, func() error { committed = true; return nil }); err == nil {
		t.Fatal("expected error")
	}
	if committed {
		t.Fatal("commit must not run when a record fails")
	}
	if _, err := LoadDecryptedRecord("a", oldKey); err != nil {
		t.Fatalf("original record damaged: %v", err)
	}
	if _, err := os.Stat(KeysDir() + ".new"); !os.IsNotExist(err) {
		t.Fatal("staging directory left behind")
	}
}

func TestReencryptAllCommitFailureKeepsStore(t *testing.T) {
	setupHome(t)
	oldKey, newKey := masterKey(), bytes.Repeat([]byte{9}, 32)
	saveTestKey(t, "a", oldKey)

	if _, err := ReencryptAll([][]byte{oldKey}, newKey, func() error { return errors.New("keychain write failed") }); err == nil {
		t.Fatal("expected commit error")
	}
	if _, err := LoadDecryptedRecord("a", oldKey); err != nil {
		t.Fatalf("store must still use the old key: %v", err)
	}
}

// Migration case: records written under two different keys.
func TestReencryptAllWithCandidateKeys(t *testing.T) {
	setupHome(t)
	k1, k2 := masterKey(), bytes.Repeat([]byte{3}, 32)
	saveTestKey(t, "a", k1)
	saveTestKey(t, "b", k2)

	if n, err := ReencryptAll([][]byte{k1, k2}, k1, nil); err != nil || n != 2 {
		t.Fatalf("ReencryptAll = %d, %v", n, err)
	}
	for _, alias := range []string{"a", "b"} {
		if _, err := LoadDecryptedRecord(alias, k1); err != nil {
			t.Fatalf("%s not readable with target key: %v", alias, err)
		}
	}
}

func TestPubKeyFiles(t *testing.T) {
	setupHome(t)
	rec := saveTestKey(t, "work", masterKey())

	path, _ := PubKeyPath("work")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("public key file not written: %v", err)
	}
	pk, comment, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil || comment != "work" || ssh.FingerprintSHA256(pk) != rec.Fingerprint {
		t.Fatalf("bad public key file %q: %v", b, err)
	}

	// SyncPubKeys restores missing files and removes orphans
	os.Remove(path)
	orphan := filepath.Join(PubKeysDir(), "gone.pub")
	os.WriteFile(orphan, []byte("x"), 0644)
	if err := SyncPubKeys(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("missing public key not restored")
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("orphan public key not removed")
	}

	if err := RemoveRecord("work"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("public key left after RemoveRecord")
	}
	if err := RemoveRecord("work"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove: %v", err)
	}
}

func TestKeyDescription(t *testing.T) {
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := []struct {
		priv interface{}
		want string
	}{{edPriv, "ED25519"}, {rsaPriv, "RSA-2048"}, {ecPriv, "ECDSA-P256"}}
	for _, c := range cases {
		s, err := ssh.NewSignerFromKey(c.priv)
		if err != nil {
			t.Fatal(err)
		}
		if got := KeyDescription(s.PublicKey()); got != c.want {
			t.Errorf("KeyDescription = %q, want %q", got, c.want)
		}
	}
}

func TestBackupRoundTrip(t *testing.T) {
	setupHome(t)
	a := saveTestKey(t, "a", masterKey())
	saveTestKey(t, "b", masterKey())
	path := filepath.Join(t.TempDir(), "x.fsshbak")

	n, err := WriteBackup(path, masterKey(), "backup passphrase")
	if err != nil || n != 2 {
		t.Fatalf("WriteBackup = %d, %v", n, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Fatalf("backup mode = %v", fi.Mode().Perm())
	}
	if _, err := WriteBackup(path, masterKey(), "backup passphrase"); err == nil {
		t.Fatal("existing backup file overwritten")
	}
	if _, err := ReadBackup(path, "wrong passphrase!"); !errors.Is(err, ErrBackupPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	recs, err := ReadBackup(path, "backup passphrase")
	if err != nil || len(recs) != 2 {
		t.Fatalf("ReadBackup = %d, %v", len(recs), err)
	}
	var got *Record
	for _, r := range recs {
		if r.Alias == "a" {
			got = r
		}
	}
	metaA, _ := LoadMeta("a")
	if got == nil || !bytes.Equal(got.PKCS8DER, a.PKCS8DER) || got.CreatedAt != metaA.CreatedAt {
		t.Fatal("restored record differs")
	}

	// restore under a different master key (another Mac / auth mode)
	setupHome(t)
	other := bytes.Repeat([]byte{4}, 32)
	if err := SaveEncryptedRecord(got, other); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDecryptedRecord("a", other); err != nil {
		t.Fatal(err)
	}
}

func TestExportOpenSSH(t *testing.T) {
	setupHome(t)
	rec := saveTestKey(t, "a", masterKey())
	plain, err := ExportOpenSSH(rec, "")
	if err != nil || !bytes.Contains(plain, []byte("BEGIN OPENSSH PRIVATE KEY")) {
		t.Fatalf("plain export: %v\n%s", err, plain)
	}
	if _, err := ssh.ParseRawPrivateKey(plain); err != nil {
		t.Fatalf("ssh cannot parse export: %v", err)
	}
	enc, err := ExportOpenSSH(rec, "export pass")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ssh.ParseRawPrivateKey(enc); err == nil {
		t.Fatal("encrypted export parsed without passphrase")
	}
	k, err := ssh.ParseRawPrivateKeyWithPassphrase(enc, []byte("export pass"))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(k)
	if ssh.FingerprintSHA256(s.PublicKey()) != rec.Fingerprint {
		t.Fatal("exported key differs")
	}
}
