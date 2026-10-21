package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"fssh/internal/auth"
	"fssh/internal/i18n"
	"fssh/internal/keychain"
	"fssh/internal/otp"
	"fssh/internal/store"

	"golang.org/x/term"
)

// unlockMasterKeyErr authenticates through the configured auth mode. Commands
// must never read the Keychain directly: in OTP mode that would bypass the
// password + TOTP check.
func unlockMasterKeyErr(reason string) ([]byte, error) {
	p, err := auth.GetAuthProvider(0)
	if err != nil {
		return nil, err
	}
	mk, err := p.UnlockMasterKey(auth.Request{Reason: reason})
	if err != nil {
		return nil, err
	}
	if p.Mode() == auth.ModeOTP {
		migrateOTPKeychain(mk)
	}
	return mk, nil
}

func unlockMasterKey(reason string) []byte {
	mk, err := unlockMasterKeyErr(reason)
	if err != nil {
		fatal(err)
	}
	return mk
}

// migrateOTPKeychain removes the copy of the master key that older versions
// also stored in the Keychain in OTP mode, which let anyone with the macOS
// login password bypass OTP. Runs only after a successful OTP authentication.
//
// If the Keychain key equals the OTP key it is a redundant copy and is
// deleted. If it differs (the user switched from Touch ID), records written
// under it are first re-encrypted under the OTP key; deleting it is then
// confirmed interactively, since it may still protect backups elsewhere.
func migrateOTPKeychain(otpKey []byte) {
	exists, err := keychain.MasterKeyExists()
	if err != nil || !exists {
		return
	}
	kcKey, err := keychain.LoadMasterKeyWithoutPrompt()
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("migrate.otp_keychain_failed", err))
		return
	}
	if !bytes.Equal(kcKey, otpKey) {
		if _, err := store.ReencryptAll([][]byte{otpKey, kcKey}, otpKey, nil); err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("migrate.otp_keychain_failed", err))
			return
		}
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintln(os.Stderr, i18n.T("migrate.otp_keychain_kept"))
			return
		}
		fmt.Fprintln(os.Stderr, i18n.T("migrate.otp_keychain_differs"))
		if !otp.PromptConfirm(i18n.T("migrate.otp_keychain_confirm")) {
			fmt.Fprintln(os.Stderr, i18n.T("migrate.otp_keychain_kept"))
			return
		}
	}
	if err := keychain.DeleteMasterKey(); err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("migrate.otp_keychain_failed", err))
		return
	}
	fmt.Fprintln(os.Stderr, i18n.T("migrate.otp_keychain_done"))
}

// restartManagedAgent restarts the LaunchAgent-managed agent so it drops
// cached keys; a no-op when the agent is not managed by launchd.
func restartManagedAgent() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	if _, err := os.Stat(filepath.Join(home, "Library", "LaunchAgents", plistLabel+".plist")); err != nil {
		return
	}
	target := fmt.Sprintf("gui/%d/%s", os.Getuid(), plistLabel)
	if err := exec.Command("launchctl", "kickstart", "-k", target).Run(); err != nil {
		fmt.Println(i18n.T("agent.restart_manual", target))
		return
	}
	fmt.Println(i18n.T("agent.restarted"))
}
