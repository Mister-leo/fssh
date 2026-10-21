package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"flag"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"fssh/internal/i18n"
	"fssh/internal/store"

	gossh "golang.org/x/crypto/ssh"
)

// fakeHome creates a temp HOME in OTP mode so nothing touches the Keychain
// (the Keychain lives under the real HOME; queries against a fake one can
// make macOS show a "Keychain Not Found" dialog).
func fakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(home, ".fssh"), 0700)
	os.WriteFile(filepath.Join(home, ".fssh", "auth_mode.json"), []byte(`{"version":"fssh-auth/v1","mode":"otp"}`), 0600)
	os.MkdirAll(filepath.Join(home, ".ssh"), 0700)
	i18n.Set(i18n.EN)
	t.Cleanup(func() { i18n.Set("") })
	return home
}

func writeKeyFile(t *testing.T, path, passphrase string) gossh.PublicKey {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var block *pem.Block
	var err error
	if passphrase == "" {
		block, err = gossh.MarshalPrivateKey(priv, "")
	} else {
		block, err = gossh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, pem.EncodeToMemory(block), 0600)
	s, _ := gossh.NewSignerFromKey(priv)
	return s.PublicKey()
}

func TestSplitArgs(t *testing.T) {
	cases := map[string][]string{
		`me@1.2.3.4 -p 2222`:           {"me@1.2.3.4", "-p", "2222"},
		`host "echo hi there"`:         {"host", "echo hi there"},
		`host 'a "b"' c\ d`:            {"host", `a "b"`, "c d"},
		`  spaced   out  `:             {"spaced", "out"},
		`host -L 8080:localhost:80 ''`: {"host", "-L", "8080:localhost:80", ""},
	}
	for in, want := range cases {
		got, err := splitArgs(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("splitArgs(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := splitArgs(`unterminated "quote`); err == nil {
		t.Error("unterminated quote accepted")
	}
}

func TestFakeIPRange(t *testing.T) {
	for ip, fake := range map[string]bool{"198.18.5.109": true, "198.19.255.1": true, "198.20.0.1": false, "10.0.0.1": false} {
		if got := fakeIPNet.Contains(net.ParseIP(ip)); got != fake {
			t.Errorf("fake-ip(%s) = %v, want %v", ip, got, fake)
		}
	}
	if ip, fake := lookupIP("10.1.2.3", 0); ip != "10.1.2.3" || fake {
		t.Error("literal IPs must not be resolved")
	}
}

func TestParseInterleaved(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	copyOut := fs.Bool("copy", false, "")
	args := parseInterleaved(fs, []string{"work", "--copy"})
	if !*copyOut || !reflect.DeepEqual(args, []string{"work"}) {
		t.Fatalf("args=%v copy=%v", args, *copyOut)
	}
}

func TestPlistProgram(t *testing.T) {
	plist := generatePlistContent("/opt/homebrew/bin/fssh", "/tmp/x.log")
	if got := plistProgram(plist); got != "/opt/homebrew/bin/fssh" {
		t.Fatalf("plistProgram = %q", got)
	}
}

func TestScanPlaintextKeys(t *testing.T) {
	home := fakeHome(t)
	ssh := filepath.Join(home, ".ssh")
	plain := writeKeyFile(t, filepath.Join(ssh, "id_ed25519"), "")
	writeKeyFile(t, filepath.Join(ssh, "id_work"), "secret")
	os.WriteFile(filepath.Join(ssh, "config"), []byte("Host x\n"), 0600)
	os.WriteFile(filepath.Join(ssh, "id_ed25519.pub"), []byte("ssh-ed25519 AAAA"), 0644)
	os.MkdirAll(filepath.Join(ssh, "fssh-archive"), 0700)
	writeKeyFile(t, filepath.Join(ssh, "fssh-archive", "id_old"), "")

	keys := scanPlaintextKeys()
	got := map[string]plaintextKey{}
	for _, k := range keys {
		got[filepath.Base(k.path)] = k
	}
	if len(keys) != 2 {
		t.Fatalf("found %d keys: %+v", len(keys), keys)
	}
	if k := got["id_ed25519"]; k.encrypted || k.fingerprint != gossh.FingerprintSHA256(plain) {
		t.Errorf("id_ed25519 = %+v", k)
	}
	if k := got["id_work"]; !k.encrypted {
		t.Errorf("id_work = %+v", k)
	}
}

func TestHandleOriginalArchive(t *testing.T) {
	home := fakeHome(t)
	src := filepath.Join(home, ".ssh", "id_ed25519")
	writeKeyFile(t, src, "")
	os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Host gh\n    IdentityFile ~/.ssh/id_ed25519\n"), 0600)

	out := captureStdout(t, func() { handleOriginalKeyFile(src, "work", originalArchive) })
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("original still in ~/.ssh")
	}
	if _, err := os.Stat(filepath.Join(archiveDir(), "id_ed25519")); err != nil {
		t.Fatalf("not archived: %v", err)
	}
	if !strings.Contains(out, "fssh bind gh work") {
		t.Errorf("no hint about the host using the file:\n%s", out)
	}

	// a second key with the same file name must not overwrite the first
	writeKeyFile(t, src, "")
	handleOriginalKeyFile(src, "work2", originalArchive)
	entries, _ := os.ReadDir(archiveDir())
	if len(entries) != 2 {
		t.Fatalf("archive has %d files, want 2", len(entries))
	}
}

func TestDoctorFindsProblems(t *testing.T) {
	home := fakeHome(t)
	writeKeyFile(t, filepath.Join(home, ".ssh", "id_rsa"), "")

	var msgs []string
	for _, c := range runChecks() {
		if c.level != checkOK {
			msgs = append(msgs, c.msg)
		}
	}
	joined := strings.Join(msgs, "\n")
	for _, want := range []string{
		i18n.T("doctor.not_initialized"),
		i18n.T("doctor.ssh_missing"),
		"id_rsa",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("doctor did not report %q:\n%s", want, joined)
		}
	}
}

func TestStatusLabelsTranslated(t *testing.T) {
	for _, k := range []string{"mode", "initialized", "keys", "agent", "launchagent", "sshconfig", "authsock", "ttl", "forwarded", "recovery"} {
		if !i18n.Has("status." + k) {
			t.Errorf("missing i18n key status.%s", k)
		}
	}
}

func TestBoundHostsListing(t *testing.T) {
	home := fakeHome(t)
	pub := filepath.Join(store.PubKeysDir(), "work.pub")
	os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Host gh\n    IdentityFile "+pub+"\n    IdentitiesOnly yes\n"), 0600)
	if got := boundHosts(); !reflect.DeepEqual(got["work"], []string{"gh"}) {
		t.Fatalf("boundHosts = %v", got)
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	b := make([]byte, 64*1024)
	n, _ := r.Read(b)
	return string(b[:n])
}

func TestShellEnvBlock(t *testing.T) {
	dir := t.TempDir()
	zshrc := filepath.Join(dir, ".zshrc")
	os.WriteFile(zshrc, []byte("alias ll='ls -l'\n"), 0600)

	if changed, err := ensureShellEnv(zshrc, "/Users/x/.fssh/agent.sock"); err != nil || !changed {
		t.Fatalf("ensureShellEnv = %v, %v", changed, err)
	}
	b, _ := os.ReadFile(zshrc)
	if !strings.Contains(string(b), `export SSH_AUTH_SOCK="/Users/x/.fssh/agent.sock"`) || !strings.HasPrefix(string(b), "alias ll") {
		t.Fatalf("unexpected rc:\n%s", b)
	}
	if fi, _ := os.Stat(zshrc); fi.Mode().Perm() != 0600 {
		t.Error("file mode not preserved")
	}
	if changed, _ := ensureShellEnv(zshrc, "/Users/x/.fssh/agent.sock"); changed {
		t.Error("ensureShellEnv must be idempotent")
	}
	if removed, err := removeShellEnv(zshrc); err != nil || !removed {
		t.Fatalf("removeShellEnv = %v, %v", removed, err)
	}
	if b, _ := os.ReadFile(zshrc); string(b) != "alias ll='ls -l'\n" {
		t.Fatalf("rc not restored exactly: %q", b)
	}

	fish := filepath.Join(dir, "config.fish")
	ensureShellEnv(fish, "/s")
	if b, _ := os.ReadFile(fish); !strings.Contains(string(b), `set -gx SSH_AUTH_SOCK "/s"`) {
		t.Fatalf("fish syntax: %s", b)
	}
}

func TestBrewBinary(t *testing.T) {
	for in, want := range map[string]string{
		"/opt/homebrew/Cellar/fssh/1.2.0/bin/fssh": "/opt/homebrew/bin/fssh",
		"/usr/local/Cellar/fssh/HEAD-abc/bin/fssh": "/usr/local/bin/fssh",
		"/usr/local/bin/fssh":                      "",
	} {
		if got := brewBinary(in); got != want {
			t.Errorf("brewBinary(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResetStoreMovesDataAside(t *testing.T) {
	home := fakeHome(t)
	deleted := false
	orig := deleteMasterKey
	deleteMasterKey = func() error { deleted = true; return nil }
	t.Cleanup(func() { deleteMasterKey = orig })

	key := filepath.Join(home, "k")
	writeKeyFile(t, key, "")
	b, _ := os.ReadFile(key)
	rec, err := store.NewRecordFromPrivateKeyBytes("a", b, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEncryptedRecord(rec, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}

	captureStdout(t, moveAsideOrphans)

	if !deleted {
		t.Error("master key not deleted")
	}
	if metas, _ := store.ListMeta(); len(metas) != 0 {
		t.Error("records still in the active store")
	}
	moved, _ := filepath.Glob(store.KeysDir() + ".reset-*")
	if len(moved) != 1 {
		t.Fatalf("old records not kept aside: %v", moved)
	}
	if _, err := os.Stat(filepath.Join(home, ".fssh", "auth_mode.json")); !os.IsNotExist(err) {
		t.Error("auth mode not cleared")
	}
}
