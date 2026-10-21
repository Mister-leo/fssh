package otp

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CounterStore remembers the last accepted TOTP time step. A code is only
// accepted for a later step, so an observed code cannot be replayed within
// its validity window, across processes as well.
type CounterStore interface {
	Last() int64
	Record(counter int64) error
}

// FileCounters keeps the last step in ~/.fssh/otp/last_counter.
type FileCounters struct{}

func counterPath() string {
	return filepath.Join(filepath.Dir(ConfigPath()), "last_counter")
}

func (FileCounters) Last() int64 {
	b, err := os.ReadFile(counterPath())
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

func (FileCounters) Record(counter int64) error {
	return os.WriteFile(counterPath(), []byte(strconv.FormatInt(counter, 10)+"\n"), 0600)
}
