package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fssh/internal/auth"
	"fssh/internal/i18n"
	"fssh/internal/keychain"
	"fssh/internal/macos"
	"fssh/internal/otp"
	"fssh/internal/prompt"
	"fssh/internal/store"
)

// otpOptions are the TOTP settings chosen at init / mode switch.
type otpOptions struct {
	seedTTL   int
	algorithm string
	digits    int
}

// initTouchIDMode sets up Touch ID mode on a store without a master key.
func initTouchIDMode() {
	if !macos.BiometryAvailable() {
		fmt.Println(i18n.T("mode.touchid_password_fallback"))
	}
	fmt.Println(i18n.T("init.keychain_dialog_hint"))

	mk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, mk); err != nil {
		fatal(err)
	}
	if err := keychain.StoreMasterKey(mk, true); err != nil {
		fmt.Println(i18n.T("init.keychain_failed"))
		fatal(err)
	}
	if err := auth.SaveMode(auth.ModeTouchID); err != nil {
		fatal(err)
	}
	fmt.Println("✓ " + i18n.T("init.touchid_done"))
}

// initOTPMode sets up OTP mode on a store without a master key.
func initOTPMode(o otpOptions) {
	cfg, seed, codes := newOTPConfig(o)
	if err := otp.SaveConfig(cfg); err != nil {
		fatal(err)
	}
	if err := auth.SaveMode(auth.ModeOTP); err != nil {
		fatal(err)
	}
	showOTPResult(seed, codes, cfg)
}

// newOTPConfig asks for a password, shows the secret, and makes the user
// enter a valid code before returning, so nothing is committed until the
// authenticator app is known to work.
func newOTPConfig(o otpOptions) (*otp.Config, []byte, []string) {
	tty := prompt.TTY{}
	fmt.Println(i18n.T("init.otp_title"))
	password := promptNewPassword(tty)

	cfg, seed, codes, err := otp.NewConfig(&otp.InitOptions{
		Password:         password,
		SeedUnlockTTL:    o.seedTTL,
		Algorithm:        o.algorithm,
		Digits:           o.digits,
		Period:           30,
		GenerateRecovery: true,
	})
	if err != nil {
		fatal(err)
	}

	fmt.Println()
	otp.DisplaySecret(seed, cfg.Algorithm, cfg.Digits, cfg.Period)
	fmt.Println(i18n.T("otp.init_add_to_app"))
	fmt.Println()
	for attempt := 1; ; attempt++ {
		code, err := tty.Text(i18n.T("init.otp_verify_code", cfg.Digits))
		if err != nil {
			fatal(err)
		}
		if otp.Verify(seed, strings.TrimSpace(code), cfg.Algorithm, cfg.Digits, cfg.Period) {
			break
		}
		if attempt >= 3 {
			fatal(errors.New(i18n.T("init.otp_verify_failed")))
		}
		fmt.Println(i18n.T("otp.retry_code"))
	}
	return cfg, seed, codes
}

func showOTPResult(seed []byte, codes []string, cfg *otp.Config) {
	fmt.Println()
	fmt.Println("✓ " + i18n.T("otp.init_done"))
	fmt.Println()
	otp.DisplayRecoveryCodes(codes)
	fmt.Println(i18n.T("otp.init_saved", otp.ConfigPath()))
	fmt.Println()
	fmt.Println(i18n.T("otp.init_security"))
	fmt.Println()
}

// initMode initializes the given mode on an empty store.
func initMode(mode auth.AuthMode, o otpOptions) {
	if mode == auth.ModeOTP {
		initOTPMode(o)
	} else {
		initTouchIDMode()
	}
}

// ---- mode switch ----

func cmdMode() {
	if len(os.Args) < 3 || os.Args[2] == "-h" || os.Args[2] == "--help" {
		_, mode, _ := auth.IsInitialized()
		fmt.Println(i18n.T("mode.current", mode))
		fmt.Println(i18n.T("mode.usage"))
		return
	}
	if os.Args[2] != "switch" || len(os.Args) < 4 {
		fatal(errors.New(i18n.T("mode.usage")))
	}
	target := auth.AuthMode(os.Args[3])
	if target != auth.ModeTouchID && target != auth.ModeOTP {
		fatal(errors.New(i18n.T("mode.usage")))
	}
	fs := flag.NewFlagSet("mode switch", flag.ExitOnError)
	seedTTL := fs.Int("seed-unlock-ttl", 3600, "OTP password cache time (seconds)")
	algorithm := fs.String("algorithm", "SHA1", "TOTP algorithm: SHA1, SHA256, SHA512")
	digits := fs.Int("digits", 6, "TOTP digits: 6 or 8")
	fs.Parse(os.Args[4:])
	if !isTTY() {
		fatal(errors.New(i18n.T("cli.err_need_tty")))
	}
	switchMode(target, otpOptions{*seedTTL, *algorithm, *digits})
}

// switchMode moves every key to a new master key for the target mode. The
// records are re-encrypted and verified before the new mode is committed;
// a failure at any point leaves the current mode and keys untouched.
func switchMode(target auth.AuthMode, o otpOptions) {
	p, err := auth.GetAuthProvider(0)
	if err != nil {
		fatal(err)
	}
	if p.Mode() == target {
		fatal(errors.New(i18n.T("mode.already", target)))
	}
	oldKey, err := p.UnlockMasterKey(auth.Request{NoCache: true, Reason: i18n.T("auth.reason_mode_switch", target)})
	if err != nil {
		fatal(err)
	}
	candidates := [][]byte{oldKey}
	if p.Mode() == auth.ModeOTP {
		// older versions also wrote a Keychain key in OTP mode; records may use it
		if kc, err := keychain.LoadMasterKeyWithoutPrompt(); err == nil {
			candidates = append(candidates, kc)
		}
	}

	var newKey []byte
	var commit func() error
	var after func()
	switch target {
	case auth.ModeTouchID:
		if !macos.BiometryAvailable() {
			fmt.Println(i18n.T("mode.touchid_password_fallback"))
		}
		newKey = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
			fatal(err)
		}
		commit = func() error {
			if err := keychain.StoreMasterKey(newKey, true); err != nil {
				return err
			}
			// prove the new key can be unlocked before switching over
			got, err := keychain.LoadMasterKey(i18n.T("auth.reason_mode_verify"))
			if err != nil || string(got) != string(newKey) {
				keychain.DeleteMasterKey()
				if err == nil {
					err = errors.New("keychain verification failed")
				}
				return err
			}
			if err := auth.SaveMode(auth.ModeTouchID); err != nil {
				keychain.DeleteMasterKey()
				return err
			}
			return nil
		}
		after = func() { os.RemoveAll(filepath.Dir(otp.ConfigPath())) }
	case auth.ModeOTP:
		cfg, seed, codes := newOTPConfig(o)
		if newKey, err = otp.MasterKey(cfg, seed); err != nil {
			fatal(err)
		}
		commit = func() error {
			if err := otp.SaveConfig(cfg); err != nil {
				return err
			}
			if err := auth.SaveMode(auth.ModeOTP); err != nil {
				os.Remove(otp.ConfigPath())
				return err
			}
			return nil
		}
		// the Touch ID key would let the login password bypass OTP
		after = func() {
			keychain.DeleteMasterKey()
			showOTPResult(seed, codes, cfg)
		}
	}

	n, err := store.ReencryptAll(candidates, newKey, commit)
	if err != nil {
		fatal(err)
	}
	after()
	fmt.Println("✓ " + i18n.T("mode.switched", target, n))
	restartManagedAgent()
}

// ---- start over ----

// deleteMasterKey is replaced in tests: Keychain calls under a temporary
// HOME make macOS show a "Keychain Not Found" dialog.
var deleteMasterKey = keychain.DeleteMasterKey

// resetStore clears the current setup so init can start fresh. Records and
// the OTP config are moved aside rather than deleted; the Touch ID master
// key is removed from the Keychain, which makes old records unreadable.
func resetStore() {
	home, _ := os.UserHomeDir()
	ts := time.Now().Format("20060102-150405")
	moved := []string{}
	for _, dir := range []string{store.KeysDir(), filepath.Dir(otp.ConfigPath()), store.PubKeysDir()} {
		if _, err := os.Stat(dir); err == nil {
			dest := dir + ".reset-" + ts
			if err := os.Rename(dir, dest); err != nil {
				fatal(err)
			}
			moved = append(moved, tildify(dest))
		}
	}
	deleteMasterKey()
	os.Remove(filepath.Join(home, ".fssh", "auth_mode.json"))
	if len(moved) > 0 {
		fmt.Println(i18n.T("reset.moved", strings.Join(moved, ", ")))
	}
}

// confirmReset explains what starting over loses, offers a backup, and asks
// the user to type DELETE.
func confirmReset() bool {
	metas, _ := store.ListMeta()
	if len(metas) > 0 {
		var aliases []string
		for _, m := range metas {
			aliases = append(aliases, m.Alias)
		}
		fmt.Println(i18n.T("reset.warning", len(metas), strings.Join(aliases, ", ")))
		if otp.PromptConfirm(i18n.T("reset.offer_backup")) {
			runBackup(defaultBackupPath())
		}
	}
	answer, err := prompt.TTY{}.Text(i18n.T("reset.confirm"))
	return err == nil && strings.TrimSpace(answer) == "DELETE"
}
