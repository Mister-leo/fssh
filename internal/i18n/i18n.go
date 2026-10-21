// Package i18n provides zh/en user-facing messages.
//
// Language detection order:
//  1. FSSH_LANG environment variable
//  2. "language" field in ~/.fssh/config.json
//  3. LC_ALL / LC_MESSAGES / LANG
//  4. macOS preferred language (AppleLanguages), for processes started by
//     launchd that have no shell locale variables
//
// Anything not recognised as Chinese falls back to English.
package i18n

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"fssh/internal/config"
)

type Lang string

const (
	EN Lang = "en"
	ZH Lang = "zh"
)

var (
	mu      sync.Mutex
	current Lang

	// Replaceable in tests.
	configLanguage = func() string {
		c, err := config.Load()
		if err != nil {
			return ""
		}
		return c.Language
	}
	appleLanguages = func() string {
		out, err := exec.Command("defaults", "read", "-g", "AppleLanguages").Output()
		if err != nil {
			return ""
		}
		return firstAppleLanguage(string(out))
	}
)

// Current returns the active language, detecting it on first use.
func Current() Lang {
	mu.Lock()
	defer mu.Unlock()
	if current == "" {
		current = detect()
	}
	return current
}

// Set overrides the active language.
func Set(l Lang) {
	mu.Lock()
	defer mu.Unlock()
	current = l
}

// T returns the message for key in the active language, formatted with args.
// Missing translations fall back to English, unknown keys to the key itself.
func T(key string, args ...interface{}) string {
	s := key
	if m, ok := messages[key]; ok {
		s = m[Current()]
		if s == "" {
			s = m[EN]
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

func detect() Lang {
	if l, ok := Parse(os.Getenv("FSSH_LANG")); ok {
		return l
	}
	if l, ok := Parse(configLanguage()); ok {
		return l
	}
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if l, ok := Parse(os.Getenv(k)); ok {
			return l
		}
	}
	if l, ok := Parse(appleLanguages()); ok {
		return l
	}
	return EN
}

// Parse maps a locale string ("zh_CN.UTF-8", "zh-Hans", "en", ...) to a Lang.
// Empty and POSIX locales ("", "C", "POSIX", "C.UTF-8") are treated as unset.
func Parse(s string) (Lang, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "c" || s == "posix" || strings.HasPrefix(s, "c.") {
		return "", false
	}
	if strings.HasPrefix(s, "zh") {
		return ZH, true
	}
	return EN, true
}

// firstAppleLanguage extracts the first entry from `defaults read -g AppleLanguages`
// output, e.g. "(\n    \"zh-Hans-CN\",\n    \"en-CN\"\n)" -> "zh-Hans-CN".
func firstAppleLanguage(out string) string {
	fields := strings.FieldsFunc(out, func(r rune) bool {
		return r == '(' || r == ')' || r == ',' || r == '"' || r == ' ' || r == '\n' || r == '\t'
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
