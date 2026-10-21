// Package audit records every signature request handled by the agent in
// ~/.fssh/audit.log (JSON lines, 0600).
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

const (
	ResultOK     = "ok"
	ResultDenied = "denied" // refused by policy or lock, no authentication attempted
	ResultFailed = "failed" // authentication or decryption failed

	maxSize = 5 << 20 // rotate to audit.log.1 beyond 5 MB
)

// Entry is one signature request.
type Entry struct {
	Time        string `json:"time"`
	Alias       string `json:"alias,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Process     string `json:"process,omitempty"`
	PID         int    `json:"pid,omitempty"`
	Host        string `json:"host,omitempty"`
	Forwarded   bool   `json:"forwarded,omitempty"`
	Result      string `json:"result"`
	Error       string `json:"error,omitempty"`
}

var mu sync.Mutex

// Path returns the audit log location.
func Path() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".fssh", "audit.log")
}

// Append writes e as one JSON line.
func Append(e Entry) error {
	mu.Lock()
	defer mu.Unlock()

	p := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	if fi, err := os.Stat(p); err == nil && fi.Size() > maxSize {
		_ = os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// Tail returns the last n entries, oldest first. Malformed lines are skipped.
func Tail(n int) ([]Entry, error) {
	f, err := os.Open(Path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var all []Entry
	s := bufio.NewScanner(f)
	for s.Scan() {
		var e Entry
		if json.Unmarshal(s.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	return all, nil
}
