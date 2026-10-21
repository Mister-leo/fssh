package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"fssh/internal/keychain"
	"fssh/internal/store"

	"golang.org/x/crypto/ssh"
)

// These tests write to the login Keychain under an isolated service name and
// are opt-in: FSSH_KEYCHAIN_TESTS=1 go test ./cmd/fssh -run Keychain
func keychainTest(t *testing.T) {
	t.Helper()
	if os.Getenv("FSSH_KEYCHAIN_TESTS") != "1" {
		t.Skip("set FSSH_KEYCHAIN_TESTS=1 to run Keychain tests")
	}
	t.Setenv("FSSH_KEYCHAIN_SERVICE", fmt.Sprintf("fssh-test-%d", os.Getpid()))

	// The Security framework finds the login keychain under $HOME/Library;
	// pointing HOME at an empty temp dir makes macOS show a "Keychain Not
	// Found" dialog. Keep the real Library reachable from the temp HOME.
	realHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Symlink(filepath.Join(realHome, "Library"), filepath.Join(tmp, "Library")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", tmp)
	t.Cleanup(func() { keychain.DeleteMasterKey() })
}

func saveKey(t *testing.T, alias string, mk []byte) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	rec, err := store.NewRecordFromPrivateKeyBytes(alias, pem.EncodeToMemory(block), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEncryptedRecord(rec, mk); err != nil {
		t.Fatal(err)
	}
}

func keychainHasKey(t *testing.T) bool {
	t.Helper()
	ok, err := keychain.MasterKeyExists()
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// Legacy OTP init stored the OTP-derived key itself: a redundant copy that is
// deleted without asking.
func TestKeychainMigrationDeletesRedundantCopy(t *testing.T) {
	keychainTest(t)
	otpKey := bytes.Repeat([]byte{1}, 32)
	saveKey(t, "a", otpKey)
	if err := keychain.StoreMasterKey(otpKey, true); err != nil {
		t.Fatal(err)
	}

	migrateOTPKeychain(otpKey)

	if keychainHasKey(t) {
		t.Fatal("redundant Keychain copy was not removed")
	}
	if _, err := store.LoadDecryptedRecord("a", otpKey); err != nil {
		t.Fatalf("record damaged: %v", err)
	}
}

// After switching from Touch ID, records may be under the old Keychain key.
// They are re-encrypted; without a terminal to confirm, the old key is kept.
func TestKeychainMigrationReencryptsAndKeepsDifferentKey(t *testing.T) {
	keychainTest(t)
	otpKey, oldKey := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	saveKey(t, "old", oldKey)
	saveKey(t, "new", otpKey)
	if err := keychain.StoreMasterKey(oldKey, true); err != nil {
		t.Fatal(err)
	}

	migrateOTPKeychain(otpKey) // test stdin is not a terminal

	for _, alias := range []string{"old", "new"} {
		if _, err := store.LoadDecryptedRecord(alias, otpKey); err != nil {
			t.Fatalf("%s not readable with the OTP key: %v", alias, err)
		}
	}
	if !keychainHasKey(t) {
		t.Fatal("a differing Keychain key must not be deleted without confirmation")
	}
}
