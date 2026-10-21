package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fssh/internal/i18n"
	"fssh/internal/otp"
	"fssh/internal/sshconfig"
)

// SSH_AUTH_SOCK matters for programs that do not read ~/.ssh/config
// (ssh-add, some IDEs and git clients). fssh writes it into the shell
// startup file inside a marked block so uninstall can remove it exactly.

const (
	shellBlockBegin = "# >>> fssh managed >>>"
	shellBlockEnd   = "# <<< fssh managed <<<"
)

// shellRCFile returns the startup file of the user's login shell, or "".
func shellRCFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch filepath.Base(os.Getenv("SHELL")) {
	case "zsh":
		return filepath.Join(home, ".zshrc")
	case "bash":
		// macOS terminals start login shells, which read .bash_profile
		return filepath.Join(home, ".bash_profile")
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish")
	}
	return ""
}

// allShellRCFiles lists every file fssh may have written to.
func allShellRCFiles() []string {
	home, _ := os.UserHomeDir()
	return []string{
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".config", "fish", "config.fish"),
	}
}

func shellEnvBlock(rc, sock string) string {
	line := fmt.Sprintf("export SSH_AUTH_SOCK=%q", sock)
	if strings.HasSuffix(rc, ".fish") {
		line = fmt.Sprintf("set -gx SSH_AUTH_SOCK %q", sock)
	}
	return shellBlockBegin + "\n" + line + "\n" + shellBlockEnd + "\n"
}

// ensureShellEnv writes or replaces the marked block. Returns whether the
// file changed.
func ensureShellEnv(rc, sock string) (bool, error) {
	content, err := os.ReadFile(rc)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	rest, _ := withoutShellBlock(string(content))
	if rest != "" && !strings.HasSuffix(rest, "\n") {
		rest += "\n"
	}
	if rest != "" {
		rest += "\n"
	}
	updated := rest + shellEnvBlock(rc, sock)
	if updated == string(content) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(rc), 0755); err != nil {
		return false, err
	}
	mode := os.FileMode(0644)
	if fi, err := os.Stat(rc); err == nil {
		mode = fi.Mode().Perm()
	}
	return true, os.WriteFile(rc, []byte(updated), mode)
}

// removeShellEnv deletes the marked block. Returns whether one was found.
func removeShellEnv(rc string) (bool, error) {
	content, err := os.ReadFile(rc)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	rest, found := withoutShellBlock(string(content))
	if !found {
		return false, nil
	}
	fi, _ := os.Stat(rc)
	return true, os.WriteFile(rc, []byte(rest), fi.Mode().Perm())
}

func withoutShellBlock(s string) (string, bool) {
	begin := strings.Index(s, shellBlockBegin)
	if begin < 0 {
		return s, false
	}
	end := strings.Index(s[begin:], shellBlockEnd)
	if end < 0 {
		return s, false
	}
	end = begin + end + len(shellBlockEnd)
	if end < len(s) && s[end] == '\n' {
		end++
	}
	// drop the blank line ensureShellEnv put before the block
	before := strings.TrimRight(s[:begin], "\n")
	if before != "" {
		before += "\n"
	}
	after := s[end:]
	return before + after, true
}

// setupShellEnv is the optional wizard step that exports SSH_AUTH_SOCK.
func setupShellEnv() error {
	sock := agentSocket()
	if global, _, _ := sshconfig.AgentCoverage(sock); global {
		fmt.Println(i18n.T("shellenv.optional"))
	} else {
		fmt.Println(i18n.T("shellenv.needed"))
	}
	rc := shellRCFile()
	if rc == "" {
		fmt.Println(i18n.T("shellenv.manual", sock))
		return nil
	}
	if b, err := os.ReadFile(rc); err == nil && strings.Contains(string(b), shellBlockBegin) {
		fmt.Println("✓ " + i18n.T("shellenv.already", tildify(rc)))
		return nil
	}
	if !otp.PromptConfirm(i18n.T("shellenv.confirm", tildify(rc))) {
		fmt.Println(i18n.T("shellenv.manual", sock))
		return nil
	}
	if _, err := ensureShellEnv(rc, sock); err != nil {
		return err
	}
	fmt.Println("✓ " + i18n.T("shellenv.done", tildify(rc)))
	return nil
}
