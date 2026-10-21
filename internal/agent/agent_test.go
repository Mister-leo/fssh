package agentserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"fssh/internal/audit"
	"fssh/internal/auth"
	"fssh/internal/config"
	"fssh/internal/i18n"
	"fssh/internal/store"

	"golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

// ---- fakes ----

type fakeProvider struct {
	mu     sync.Mutex
	mk     []byte
	err    error
	reqs   []auth.Request
	clears int
}

func (f *fakeProvider) UnlockMasterKey(req auth.Request) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	if f.err != nil {
		return nil, f.err
	}
	return append([]byte(nil), f.mk...), nil
}
func (f *fakeProvider) PrepareRekey(auth.Request) (*auth.Rekey, error) { return nil, errors.New("n/a") }
func (f *fakeProvider) IsAvailable() bool                              { return true }
func (f *fakeProvider) Mode() auth.AuthMode                            { return auth.ModeTouchID }
func (f *fakeProvider) ClearCache() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clears++
}

func (f *fakeProvider) lastReq(t *testing.T) auth.Request {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) == 0 {
		t.Fatal("provider was not asked to unlock")
	}
	return f.reqs[len(f.reqs)-1]
}

type notifyPrompter struct {
	mu       sync.Mutex
	notified []string
}

func (n *notifyPrompter) Password(string) (string, error) { return "", errors.New("unexpected") }
func (n *notifyPrompter) Text(string) (string, error)     { return "", errors.New("unexpected") }
func (n *notifyPrompter) Notify(_, msg string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.notified = append(n.notified, msg)
}

// ---- helpers ----

var testMK = bytes.Repeat([]byte{5}, 32)

// setupStore creates a temp HOME with one imported ed25519 key "work".
func setupStore(t *testing.T) ssh.PublicKey {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	i18n.Set(i18n.EN)
	t.Cleanup(func() { i18n.Set("") })

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := store.NewRecordFromPrivateKeyBytes("work", pem.EncodeToMemory(block), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEncryptedRecord(rec, testMK); err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	return signer.PublicKey()
}

type harness struct {
	agent    *secureAgent
	provider *fakeProvider
	prompter *notifyPrompter
	mu       sync.Mutex
	entries  []audit.Entry
}

func newHarness(policy string) *harness {
	h := &harness{provider: &fakeProvider{mk: testMK}, prompter: &notifyPrompter{}}
	h.agent = newSecureAgent(h.provider, h.prompter, policy)
	h.agent.record = func(e audit.Entry) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.entries = append(h.entries, e)
	}
	return h
}

func (h *harness) lastEntry(t *testing.T) audit.Entry {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.entries) == 0 {
		t.Fatal("no audit entry")
	}
	return h.entries[len(h.entries)-1]
}

// dial serves the agent on a real unix socket and returns a client.
func (h *harness) dial(t *testing.T) xagent.ExtendedAgent {
	t.Helper()
	dir, err := os.MkdirTemp("", "fssh") // short path: unix socket names are limited to 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "a.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = xagent.ServeAgent(h.agent.forConn(c), c); c.Close() }()
		}
	}()
	conn, err := net.Dial("unix", filepath.Join(dir, "a.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return xagent.NewClient(conn)
}

// sessionBind builds a signed session-bind payload for a fresh host key.
func sessionBindPayload(t *testing.T, forwarding bool) ([]byte, ssh.PublicKey) {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	host, _ := ssh.NewSignerFromKey(hostPriv)
	sid := make([]byte, 32)
	rand.Read(sid)
	sig, err := host.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{host.PublicKey().Marshal(), sid, ssh.Marshal(sig), forwarding}), host.PublicKey()
}

func writeKnownHost(t *testing.T, name string, key ssh.PublicKey) {
	t.Helper()
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".ssh")
	os.MkdirAll(dir, 0700)
	line := "|1|hashedhost= " + string(ssh.MarshalAuthorizedKey(key)) + name + ",10.0.0.1 " + string(ssh.MarshalAuthorizedKey(key))
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
}

// ---- tests ----

func TestAgentSignsWithContext(t *testing.T) {
	pub := setupStore(t)
	h := newHarness(config.ForwardedSignPrompt)
	client := h.dial(t)

	payload, hostKey := sessionBindPayload(t, false)
	writeKnownHost(t, "github.com", hostKey)
	if _, err := client.Extension(sessionBindExtension, payload); err != nil {
		t.Fatalf("session-bind: %v", err)
	}

	keys, err := client.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "work" {
		t.Fatalf("List = %v, %v", keys, err)
	}
	data := []byte("challenge")
	sig, err := client.Sign(keys[0], data)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	req := h.provider.lastReq(t)
	if req.NoCache {
		t.Error("direct request must be allowed to use the TTL cache")
	}
	if !strings.Contains(req.Reason, "github.com") || !strings.Contains(req.Reason, `"work"`) {
		t.Errorf("reason lacks host or key: %q", req.Reason)
	}
	if self := filepath.Base(os.Args[0]); !strings.Contains(req.Reason, self) {
		t.Errorf("reason lacks requesting process %q: %q", self, req.Reason)
	}

	e := h.lastEntry(t)
	if e.Result != audit.ResultOK || e.Alias != "work" || e.Host != "github.com" || e.Forwarded || e.PID != os.Getpid() {
		t.Errorf("audit entry = %+v", e)
	}
}

func TestAgentForwardedRequestAlwaysConfirms(t *testing.T) {
	setupStore(t)
	h := newHarness(config.ForwardedSignPrompt)
	client := h.dial(t)

	payload, _ := sessionBindPayload(t, true)
	if _, err := client.Extension(sessionBindExtension, payload); err != nil {
		t.Fatal(err)
	}
	keys, _ := client.List()
	if _, err := client.Sign(keys[0], []byte("x")); err != nil {
		t.Fatal(err)
	}
	req := h.provider.lastReq(t)
	if !req.NoCache {
		t.Error("forwarded request must bypass the TTL cache")
	}
	if !strings.Contains(req.Reason, i18n.T("agent.reason_forwarded")) {
		t.Errorf("reason does not flag forwarding: %q", req.Reason)
	}
	if e := h.lastEntry(t); !e.Forwarded || e.Result != audit.ResultOK {
		t.Errorf("audit entry = %+v", e)
	}
}

func TestAgentForwardedDenyPolicy(t *testing.T) {
	setupStore(t)
	h := newHarness(config.ForwardedSignDeny)
	client := h.dial(t)

	payload, _ := sessionBindPayload(t, true)
	client.Extension(sessionBindExtension, payload)
	keys, _ := client.List()
	if _, err := client.Sign(keys[0], []byte("x")); err == nil {
		t.Fatal("forwarded request should be refused")
	}
	if len(h.provider.reqs) != 0 {
		t.Fatal("refused request must not trigger authentication")
	}
	if len(h.prompter.notified) != 1 {
		t.Fatalf("notifications = %v", h.prompter.notified)
	}
	if e := h.lastEntry(t); e.Result != audit.ResultDenied {
		t.Errorf("audit entry = %+v", e)
	}
}

func TestAgentRejectsForgedSessionBind(t *testing.T) {
	setupStore(t)
	h := newHarness(config.ForwardedSignPrompt)
	client := h.dial(t)

	payload, _ := sessionBindPayload(t, false)
	payload[len(payload)-2] ^= 0xff // corrupt the signature
	if _, err := client.Extension(sessionBindExtension, payload); err == nil {
		t.Fatal("forged session-bind accepted")
	}
	if _, err := client.Extension("unknown@example.com", nil); !errors.Is(err, xagent.ErrExtensionUnsupported) {
		t.Fatalf("unknown extension: err = %v", err)
	}
}

func TestAgentLockUnlock(t *testing.T) {
	setupStore(t)
	h := newHarness(config.ForwardedSignPrompt)
	client := h.dial(t)
	keys, _ := client.List()
	key := keys[0]

	if err := client.Lock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	if h.provider.clears != 1 {
		t.Error("lock must clear the unlock cache")
	}
	if ks, _ := client.List(); len(ks) != 0 {
		t.Error("locked agent must not list keys")
	}
	if _, err := client.Sign(key, []byte("x")); err == nil {
		t.Error("locked agent must not sign")
	}
	if err := client.Unlock([]byte("wrong")); err == nil {
		t.Error("unlock with wrong passphrase succeeded")
	}
	if err := client.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Sign(key, []byte("x")); err != nil {
		t.Fatalf("sign after unlock: %v", err)
	}
}

func TestAgentRemoveAllClearsCacheAndAddIsRefused(t *testing.T) {
	setupStore(t)
	h := newHarness(config.ForwardedSignPrompt)
	client := h.dial(t)

	if err := client.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if h.provider.clears != 1 {
		t.Error("ssh-add -D must clear the unlock cache")
	}
	if ks, _ := client.List(); len(ks) != 1 {
		t.Error("keys stay in the encrypted store")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := client.Add(xagent.AddedKey{PrivateKey: priv}); err == nil {
		t.Error("Add must be refused")
	}
}

func TestAgentDecryptFailureClearsCache(t *testing.T) {
	setupStore(t)
	h := newHarness(config.ForwardedSignPrompt)
	h.provider.mk = bytes.Repeat([]byte{6}, 32) // stale key, e.g. after rekey
	client := h.dial(t)
	keys, _ := client.List()

	if _, err := client.Sign(keys[0], []byte("x")); err == nil {
		t.Fatal("sign with wrong master key succeeded")
	}
	if h.provider.clears != 1 || len(h.prompter.notified) != 1 {
		t.Fatalf("clears=%d notified=%v", h.provider.clears, h.prompter.notified)
	}
	if e := h.lastEntry(t); e.Result != audit.ResultFailed {
		t.Errorf("audit entry = %+v", e)
	}
}

func TestParseProcArgs(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, int32(3))
	buf.WriteString("/usr/bin/ssh\x00\x00\x00\x00ssh\x00-T\x00git@github.com\x00HOME=/x\x00")
	exe, args := parseProcArgs(buf.Bytes())
	if exe != "/usr/bin/ssh" || strings.Join(args, " ") != "ssh -T git@github.com" {
		t.Fatalf("exe=%q args=%q", exe, args)
	}
	if exe, args := parseProcArgs([]byte{1}); exe != "" || args != nil {
		t.Fatal("short buffer must not panic")
	}
}

func TestProcessInfoSelf(t *testing.T) {
	info := processInfo(os.Getpid())
	if info.Name == "" || info.PID != os.Getpid() {
		t.Fatalf("processInfo(self) = %+v", info)
	}
}

func TestPeerDisplay(t *testing.T) {
	cases := []struct {
		p    PeerInfo
		want string
	}{
		{PeerInfo{Name: "ssh", ParentName: "git"}, "git → ssh"},
		{PeerInfo{Name: "ssh", ParentName: "-zsh"}, "ssh"},
		{PeerInfo{Name: "ssh"}, "ssh"},
	}
	for _, c := range cases {
		if got := c.p.Display(); got != c.want {
			t.Errorf("%+v.Display() = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestCleanKnownHost(t *testing.T) {
	for in, want := range map[string]string{
		"github.com":         "github.com",
		"[example.com]:22":   "example.com",
		"[example.com]:2222": "example.com:2222",
		"[10.0.0.1]:2200":    "10.0.0.1:2200",
	} {
		if got := cleanKnownHost(in); got != want {
			t.Errorf("cleanKnownHost(%q) = %q, want %q", in, got, want)
		}
	}
}
