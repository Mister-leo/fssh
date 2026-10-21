package main

import (
	"errors"
	"fmt"
	"os"

	"fssh/internal/auth"
	"fssh/internal/i18n"
	"fssh/internal/otp"
	"fssh/internal/prompt"

	"golang.org/x/term"
)

var otpSubcommands = []string{"recover", "change-password", "regen-recovery", "show-secret"}

func printOTPHelp() {
	fmt.Println(i18n.T("help.usage_otp"))
	fmt.Println()
	for _, name := range otpSubcommands {
		fmt.Printf("  %-16s %s\n", name, i18n.T("cmd.otp."+name))
	}
}

func cmdOTP() {
	if len(os.Args) < 3 {
		printOTPHelp()
		os.Exit(2)
	}
	sub := os.Args[2]
	if sub == "-h" || sub == "--help" || sub == "help" {
		printOTPHelp()
		return
	}
	if !otp.ConfigExists() {
		fatal(errors.New(i18n.T("otp.err_not_configured")))
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fatal(errors.New(i18n.T("cli.err_need_tty")))
	}
	switch sub {
	case "recover":
		otpRecover()
	case "change-password":
		otpChangePassword()
	case "regen-recovery":
		otpRegenRecovery()
	case "show-secret":
		otpShowSecret()
	default:
		fmt.Fprintln(os.Stderr, i18n.T("cli.unknown_command", "otp "+sub))
		printOTPHelp()
		os.Exit(2)
	}
}

func loadOTPConfig() *otp.Config {
	cfg, err := otp.LoadConfig(otp.ConfigPath())
	if err != nil {
		fatal(err)
	}
	return cfg
}

// promptNewPassword asks for a new OTP password twice and checks its strength.
func promptNewPassword(tty prompt.TTY) string {
	for attempt := 0; attempt < 3; attempt++ {
		p1, err := tty.Password(i18n.T("otp.prompt_new_password"))
		if err != nil {
			fatal(err)
		}
		if err := otp.ValidatePasswordStrength(p1); err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("otp.err_password_weak"))
			continue
		}
		p2, err := tty.Password(i18n.T("otp.prompt_confirm_password"))
		if err != nil {
			fatal(err)
		}
		if p1 != p2 {
			fmt.Fprintln(os.Stderr, i18n.T("otp.err_password_mismatch"))
			continue
		}
		return p1
	}
	fatal(errors.New(i18n.T("otp.err_password_aborted")))
	return ""
}

// otpVerifiedSeed runs the full password + TOTP check and returns the seed.
func otpVerifiedSeed(reason string) []byte {
	p, err := auth.NewOTPProvider(0)
	if err != nil {
		fatal(err)
	}
	seed, err := p.VerifySeed(auth.Request{Reason: reason, Prompter: prompt.TTY{}})
	if err != nil {
		fatal(err)
	}
	return seed
}

// otpRecover resets a forgotten password with a single-use recovery code.
func otpRecover() {
	tty := prompt.TTY{}
	cfg := loadOTPConfig()
	if cfg.LegacyRecovery() {
		fatal(errors.New(i18n.T("otp.err_legacy_recovery")))
	}

	code, err := tty.Text(i18n.T("otp.prompt_recovery_code"))
	if err != nil {
		fatal(err)
	}
	seed, idx, err := otp.RecoverSeed(cfg, code)
	if err != nil {
		fatal(errors.New(i18n.T("otp.err_recovery_code")))
	}

	password := promptNewPassword(tty)
	if err := otp.SetPassword(cfg, password, seed); err != nil {
		fatal(err)
	}
	otp.RemoveRecoveryCode(cfg, idx)
	if err := otp.SaveConfig(cfg); err != nil {
		fatal(err)
	}
	fmt.Println(i18n.T("otp.recover_done", len(cfg.RecoveryWrapped)))
}

func otpChangePassword() {
	seed := otpVerifiedSeed(i18n.T("otp.reason_change_password"))
	password := promptNewPassword(prompt.TTY{})
	cfg := loadOTPConfig()
	if err := otp.SetPassword(cfg, password, seed); err != nil {
		fatal(err)
	}
	if err := otp.SaveConfig(cfg); err != nil {
		fatal(err)
	}
	fmt.Println(i18n.T("otp.change_password_done"))
}

func otpRegenRecovery() {
	seed := otpVerifiedSeed(i18n.T("otp.reason_regen_recovery"))
	cfg := loadOTPConfig()
	codes, err := otp.SetRecoveryCodes(cfg, seed, otp.DefaultRecoveryCodes)
	if err != nil {
		fatal(err)
	}
	if err := otp.SaveConfig(cfg); err != nil {
		fatal(err)
	}
	fmt.Println()
	otp.DisplayRecoveryCodes(codes)
	fmt.Println(i18n.T("otp.regen_done"))
}

// otpShowSecret re-displays the TOTP secret, e.g. to add it to a new phone or
// to fix setups made by older versions that displayed it in Base64. It only
// needs the password: the seed is encrypted by the password alone, so the
// TOTP code would add no protection here.
func otpShowSecret() {
	tty := prompt.TTY{}
	cfg := loadOTPConfig()
	password, err := tty.Password(i18n.T("otp.prompt_password"))
	if err != nil {
		fatal(err)
	}
	seed, err := otp.DecryptSeed(cfg, password)
	if err != nil {
		fatal(errors.New(i18n.T("otp.err_password")))
	}
	fmt.Println()
	otp.DisplaySecret(seed, cfg.Algorithm, cfg.Digits, cfg.Period)
	fmt.Println(i18n.T("otp.show_secret_warning"))
}
