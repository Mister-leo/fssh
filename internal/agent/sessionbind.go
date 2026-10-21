package agentserver

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// sessionBindExtension is sent by OpenSSH >= 8.9 to tell the agent which
// server a connection is for and whether it arrives via agent forwarding.
// See PROTOCOL.agent in OpenSSH.
const sessionBindExtension = "session-bind@openssh.com"

type sessionBind struct {
	hostKey    ssh.PublicKey
	forwarding bool
}

// parseSessionBind decodes and verifies a session-bind request: the server's
// host key must have signed the session identifier.
func parseSessionBind(contents []byte) (*sessionBind, error) {
	var msg struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}
	if err := ssh.Unmarshal(contents, &msg); err != nil {
		return nil, err
	}
	hk, err := ssh.ParsePublicKey(msg.HostKey)
	if err != nil {
		return nil, err
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(msg.Signature, &sig); err != nil {
		return nil, err
	}
	if err := hk.Verify(msg.SessionID, &sig); err != nil {
		return nil, err
	}
	return &sessionBind{hostKey: hk, forwarding: msg.Forwarding}, nil
}

// knownHostName maps a host key to the first host name recorded for it in
// ~/.ssh/known_hosts. Hashed entries cannot be reversed and are skipped.
func knownHostName(key ssh.PublicKey) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	f, err := os.Open(filepath.Join(home, ".ssh", "known_hosts"))
	if err != nil {
		return ""
	}
	defer f.Close()

	want := key.Marshal()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
			fields = fields[1:] // @cert-authority / @revoked marker
		}
		if len(fields) < 3 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], "|") {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil || !bytes.Equal(b, want) {
			continue
		}
		return cleanKnownHost(strings.Split(fields[0], ",")[0])
	}
	return ""
}

// cleanKnownHost turns "[host]:22" into "host" and "[host]:2222" into "host:2222".
func cleanKnownHost(h string) string {
	if !strings.HasPrefix(h, "[") {
		return h
	}
	end := strings.Index(h, "]")
	if end < 0 {
		return h
	}
	host, port := h[1:end], strings.TrimPrefix(h[end+1:], ":")
	if port == "" || port == "22" {
		return host
	}
	return host + ":" + port
}
