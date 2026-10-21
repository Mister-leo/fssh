package main

import (
	"errors"
	"fmt"
	"fssh/internal/i18n"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fssh/internal/otp"
)

const defaultBinaryPath = "/usr/local/bin/fssh"

// brewBinary maps a Homebrew Cellar path to Homebrew's stable symlink, which
// survives upgrades: ".../Cellar/fssh/1.2/bin/fssh" -> ".../bin/fssh".
// Returns "" for non-Homebrew paths.
func brewBinary(resolved string) string {
	i := strings.Index(resolved, "/Cellar/")
	if i < 0 {
		return ""
	}
	return filepath.Join(resolved[:i], "bin", "fssh")
}

// agentBinaryPath is the program the LaunchAgent starts.
func agentBinaryPath() string {
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			if b := brewBinary(resolved); b != "" {
				return b
			}
		}
	}
	return defaultBinaryPath
}

// ensureBinaryInstalled installs fssh to /usr/local/bin if not already installed
func ensureBinaryInstalled() error {
	targetPath := defaultBinaryPath

	// Get current executable path
	currentPath, err := os.Executable()
	if err != nil {
		return errors.New(i18n.T("binary.err_path", err))
	}

	// Resolve symlinks
	currentPath, err = filepath.EvalSymlinks(currentPath)
	if err != nil {
		return errors.New(i18n.T("binary.err_path", err))
	}

	// Homebrew manages its own install; copying it elsewhere would go stale
	if b := brewBinary(currentPath); b != "" {
		fmt.Println("✓ " + i18n.T("binary.brew", b))
		return nil
	}

	// Check if already installed at target location
	if _, err := os.Stat(targetPath); err == nil {
		// Target exists, check if it's the same file
		existingPath, err := filepath.EvalSymlinks(targetPath)
		if err == nil && existingPath == currentPath {
			fmt.Println("✓ " + i18n.T("binary.installed", targetPath))
			return nil
		}

		// Different file, ask if user wants to replace
		fmt.Println("⚠️  " + i18n.T("binary.exists", targetPath))
		if !otp.PromptConfirm(i18n.T("binary.replace")) {
			fmt.Println(i18n.T("binary.skipped"))
			return nil
		}
	}

	// If we're already running from /usr/local/bin, no need to install
	if currentPath == targetPath {
		fmt.Println("✓ " + i18n.T("binary.installed", targetPath))
		return nil
	}

	// Inform user about sudo requirement
	fmt.Println(i18n.T("binary.installing", targetPath))

	// Ensure /usr/local/bin exists
	if err := runSudoCommand("mkdir", "-p", "/usr/local/bin"); err != nil {
		return errors.New(i18n.T("binary.err_install", err))
	}

	// Copy binary
	if err := runSudoCommand("cp", currentPath, targetPath); err != nil {
		return errors.New(i18n.T("binary.err_install", err))
	}

	// Set permissions
	if err := runSudoCommand("chmod", "755", targetPath); err != nil {
		return errors.New(i18n.T("binary.err_install", err))
	}

	fmt.Println("✓ " + i18n.T("binary.done", targetPath))
	return nil
}

// runSudoCommand runs a command with sudo
func runSudoCommand(name string, args ...string) error {
	cmdArgs := append([]string{name}, args...)
	cmd := exec.Command("sudo", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
