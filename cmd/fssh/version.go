package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set at release build time:
//
//	go build -ldflags "-X main.version=v1.2.3 -X main.commit=abc1234" ./cmd/fssh
var (
	version = "dev"
	commit  = ""
)

// versionString returns e.g. "fssh v1.2.3 (abc1234, go1.21.13 darwin/arm64)".
// Local `go build` in a git checkout falls back to the embedded VCS revision.
func versionString() string {
	c := commit
	if c == "" {
		c = vcsRevision()
	}
	if c == "" {
		c = "unknown"
	}
	return fmt.Sprintf("fssh %s (%s, %s %s/%s)", version, c, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func vcsRevision() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var rev string
	dirty := false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	if rev != "" && dirty {
		rev += "-dirty"
	}
	return rev
}
