package agentserver

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"fssh/internal/audit"
	"fssh/internal/auth"
	"fssh/internal/config"
	"fssh/internal/i18n"
	"fssh/internal/log"
	"fssh/internal/prompt"
	"fssh/internal/store"

	"golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

var (
	errLocked        = errors.New("agent is locked")
	errKeyNotFound   = errors.New("key not found")
	errForwardDenied = errors.New("signature via agent forwarding denied by policy")
)

// secureAgent decrypts keys on demand and authenticates every signature
// (subject to the provider's TTL cache). State shared by all connections.
type secureAgent struct {
	provider        auth.AuthProvider
	prompter        prompt.Prompter
	forwardedPolicy string

	mu       sync.Mutex
	locked   bool
	lockSalt []byte
	lockHash []byte

	// replaceable in tests
	record func(audit.Entry)
	now    func() time.Time
}

func newSecureAgent(provider auth.AuthProvider, pr prompt.Prompter, forwardedPolicy string) *secureAgent {
	a := &secureAgent{
		provider:        provider,
		prompter:        pr,
		forwardedPolicy: forwardedPolicy,
		now:             time.Now,
	}
	a.record = func(e audit.Entry) {
		if err := audit.Append(e); err != nil {
			log.Warn("写入审计日志失败", map[string]interface{}{"error": err.Error()})
		}
	}
	metas, _ := store.ListMeta()
	log.Info("创建安全 agent", map[string]interface{}{
		"auth_mode":      provider.Mode(),
		"key_count":      len(metas),
		"forwarded_sign": forwardedPolicy,
	})
	return a
}

// forConn wraps the shared agent with per-connection context.
func (a *secureAgent) forConn(c net.Conn) *connAgent {
	return &connAgent{shared: a, peer: peerInfo(c)}
}

// signContext describes who is asking and for which server.
type signContext struct {
	peer      PeerInfo
	host      string // destination from session-bind, "" if unknown
	forwarded bool
}

func (a *secureAgent) isLocked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.locked
}

func (a *secureAgent) list() ([]*xagent.Key, error) {
	if a.isLocked() {
		return nil, nil
	}
	metas, err := store.ListMeta()
	if err != nil {
		return nil, err
	}
	var ks []*xagent.Key
	for _, m := range metas {
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

// reason builds the text shown in the Touch ID / OTP prompt.
func (a *secureAgent) reason(ctx signContext, alias string) string {
	proc := ctx.peer.Display()
	var s string
	if ctx.host != "" {
		s = i18n.T("agent.reason_host", proc, alias, ctx.host)
	} else {
		s = i18n.T("agent.reason", proc, alias)
	}
	if ctx.forwarded {
		s = i18n.T("agent.reason_forwarded") + "\n" + s
	}
	return s
}

func (a *secureAgent) sign(ctx signContext, pubkey ssh.PublicKey, data []byte, flags xagent.SignatureFlags) (*ssh.Signature, error) {
	fp := ssh.FingerprintSHA256(pubkey)
	entry := audit.Entry{
		Time:        a.now().Format(time.RFC3339),
		Fingerprint: fp,
		Process:     ctx.peer.Display(),
		PID:         ctx.peer.PID,
		Host:        ctx.host,
		Forwarded:   ctx.forwarded,
	}
	fail := func(result string, err error) (*ssh.Signature, error) {
		entry.Result, entry.Error = result, err.Error()
		a.record(entry)
		log.Warn("签名请求未完成", map[string]interface{}{
			"alias": entry.Alias, "process": entry.Process, "host": entry.Host, "error": err.Error(),
		})
		return nil, err
	}

	if a.isLocked() {
		return fail(audit.ResultDenied, errLocked)
	}
	alias, ok, err := store.FindByFingerprint(fp)
	if err != nil {
		return fail(audit.ResultFailed, err)
	}
	if !ok {
		return fail(audit.ResultFailed, errKeyNotFound)
	}
	entry.Alias = alias

	if ctx.forwarded && a.forwardedPolicy == config.ForwardedSignDeny {
		a.prompter.Notify("fssh", i18n.T("agent.notify_forward_denied", entry.Process, alias))
		return fail(audit.ResultDenied, errForwardDenied)
	}

	// Forwarded requests bypass the TTL cache: every one needs confirmation.
	mk, err := a.provider.UnlockMasterKey(auth.Request{
		Reason:   a.reason(ctx, alias),
		NoCache:  ctx.forwarded,
		Prompter: a.prompter,
	})
	if err != nil {
		return fail(audit.ResultFailed, fmt.Errorf("认证失败: %w", err))
	}

	rec, err := store.LoadDecryptedRecord(alias, mk)
	if err != nil {
		// A stale cached key (e.g. after rekey) must not keep failing until TTL expiry.
		a.provider.ClearCache()
		a.prompter.Notify("fssh", i18n.T("agent.notify_decrypt_failed", alias))
		return fail(audit.ResultFailed, err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(rec.PKCS8DER)
	if err != nil {
		return fail(audit.ResultFailed, err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return fail(audit.ResultFailed, err)
	}

	var sig *ssh.Signature
	algo := ""
	if flags&xagent.SignatureFlagRsaSha512 != 0 {
		algo = ssh.KeyAlgoRSASHA512
	} else if flags&xagent.SignatureFlagRsaSha256 != 0 {
		algo = ssh.KeyAlgoRSASHA256
	}
	if algSigner, ok := signer.(ssh.AlgorithmSigner); ok && algo != "" {
		sig, err = algSigner.SignWithAlgorithm(rand.Reader, data, algo)
	} else {
		sig, err = signer.Sign(rand.Reader, data)
	}
	if err != nil {
		return fail(audit.ResultFailed, err)
	}

	entry.Result = audit.ResultOK
	a.record(entry)
	log.Debug("SSH 签名", map[string]interface{}{
		"alias": alias, "process": entry.Process, "host": entry.Host, "algorithm": sig.Format,
	})
	return sig, nil
}

// lock implements `ssh-add -x`: forget unlocked state and refuse to list or
// sign until unlocked with the same passphrase.
func (a *secureAgent) lock(passphrase []byte) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	a.mu.Lock()
	if a.locked {
		a.mu.Unlock()
		return errors.New("agent already locked")
	}
	a.locked, a.lockSalt, a.lockHash = true, salt, lockDigest(salt, passphrase)
	a.mu.Unlock()

	a.provider.ClearCache()
	log.Info("agent 已锁定", nil)
	return nil
}

// unlock implements `ssh-add -X`.
func (a *secureAgent) unlock(passphrase []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.locked {
		return errors.New("agent not locked")
	}
	if subtle.ConstantTimeCompare(lockDigest(a.lockSalt, passphrase), a.lockHash) != 1 {
		return errors.New("incorrect passphrase")
	}
	a.locked, a.lockSalt, a.lockHash = false, nil, nil
	log.Info("agent 已解锁", nil)
	return nil
}

func lockDigest(salt, passphrase []byte) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write(passphrase)
	return h.Sum(nil)
}

// removeAll implements `ssh-add -D`. Keys live in fssh's encrypted store and
// are not removed; the agent forgets its unlocked state instead, so the next
// signature needs authentication again.
func (a *secureAgent) removeAll() error {
	a.provider.ClearCache()
	log.Info("已清除解锁缓存 (ssh-add -D)", nil)
	return nil
}

// connAgent is the xagent.ExtendedAgent served on one connection.
type connAgent struct {
	shared *secureAgent
	peer   PeerInfo

	mu    sync.Mutex
	binds []*sessionBind
}

func (c *connAgent) context() signContext {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx := signContext{peer: c.peer}
	for _, b := range c.binds {
		if b.forwarding {
			ctx.forwarded = true
		}
	}
	// The last bind is the hop this request is for.
	if n := len(c.binds); n > 0 {
		hk := c.binds[n-1].hostKey
		if name := knownHostName(hk); name != "" {
			ctx.host = name
		} else {
			ctx.host = ssh.FingerprintSHA256(hk)
		}
	}
	return ctx
}

func (c *connAgent) List() ([]*xagent.Key, error) { return c.shared.list() }

func (c *connAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.shared.sign(c.context(), key, data, 0)
}

func (c *connAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags xagent.SignatureFlags) (*ssh.Signature, error) {
	return c.shared.sign(c.context(), key, data, flags)
}

func (c *connAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != sessionBindExtension {
		return nil, xagent.ErrExtensionUnsupported
	}
	b, err := parseSessionBind(contents)
	if err != nil {
		log.Warn("无效的 session-bind 请求", map[string]interface{}{"error": err.Error()})
		return nil, err
	}
	c.mu.Lock()
	c.binds = append(c.binds, b)
	c.mu.Unlock()
	return nil, nil
}

func (c *connAgent) Lock(passphrase []byte) error   { return c.shared.lock(passphrase) }
func (c *connAgent) Unlock(passphrase []byte) error { return c.shared.unlock(passphrase) }
func (c *connAgent) RemoveAll() error               { return c.shared.removeAll() }

func (c *connAgent) Add(key xagent.AddedKey) error {
	return errors.New("unsupported: import keys with `fssh import`")
}

func (c *connAgent) Remove(pubkey ssh.PublicKey) error {
	return errors.New("unsupported: remove keys with `fssh remove`")
}

func (c *connAgent) Signers() ([]ssh.Signer, error) { return nil, errors.New("unsupported") }
