package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fssh/internal/i18n"
	"fssh/internal/otp"
	"fssh/internal/prompt"
	"fssh/internal/store"
)

func defaultBackupPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "fssh-backup-"+time.Now().Format("20060102-150405")+".fsshbak")
}

// promptNewSecret asks for a new secret twice and enforces 12+ characters.
func promptNewSecret(tty prompt.TTY, promptKey, confirmKey string) string {
	for attempt := 0; attempt < 3; attempt++ {
		p1, err := tty.Password(i18n.T(promptKey))
		if err != nil {
			fatal(err)
		}
		if err := otp.ValidatePasswordStrength(p1); err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("otp.err_password_weak"))
			continue
		}
		p2, err := tty.Password(i18n.T(confirmKey))
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

func cmdBackup() {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	out := fs.String("out", "", "backup file (default ~/fssh-backup-<time>.fsshbak)")
	fs.Parse(os.Args[2:])
	if !isTTY() {
		fatal(errors.New(i18n.T("cli.err_need_tty")))
	}
	path := *out
	if path == "" {
		path = defaultBackupPath()
	}
	if _, err := os.Stat(path); err == nil {
		fatal(errors.New(i18n.T("export.err_exists", path)))
	}
	runBackup(path)
}

// runBackup writes every key to path, encrypted with a new backup passphrase.
func runBackup(path string) {
	fmt.Println(i18n.T("backup.explain"))
	pass := promptNewSecret(prompt.TTY{}, "backup.prompt_passphrase", "otp.prompt_confirm_password")
	mk := unlockMasterKey(i18n.T("auth.reason_backup"))
	n, err := store.WriteBackup(path, mk, pass)
	if err != nil {
		fatal(err)
	}
	fmt.Println("✓ " + i18n.T("backup.done", n, path))
}

func cmdRestore() {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	in := fs.String("in", "", "backup file to restore")
	force := fs.Bool("force", false, "overwrite keys whose alias already exists")
	if args := parseInterleaved(fs, os.Args[2:]); *in == "" && len(args) > 0 {
		*in = args[0]
	}
	if *in == "" {
		fatal(errors.New(i18n.T("restore.usage")))
	}
	if !isTTY() {
		fatal(errors.New(i18n.T("cli.err_need_tty")))
	}

	pass, err := prompt.TTY{}.Password(i18n.T("restore.prompt_passphrase"))
	if err != nil {
		fatal(err)
	}
	recs, err := store.ReadBackup(*in, pass)
	if errors.Is(err, store.ErrBackupPassphrase) {
		fatal(errors.New(i18n.T("restore.err_passphrase")))
	}
	if err != nil {
		fatal(err)
	}

	var todo []*store.Record
	for _, rec := range recs {
		if existing, ok, _ := store.FindByFingerprint(rec.Fingerprint); ok {
			fmt.Println(i18n.T("restore.skip_same", rec.Alias, existing))
			continue
		}
		if taken, _ := aliasTaken(rec.Alias); taken && !*force {
			fmt.Println(i18n.T("restore.skip_alias", rec.Alias))
			continue
		}
		todo = append(todo, rec)
	}
	if len(todo) == 0 {
		fmt.Println(i18n.T("restore.nothing"))
		return
	}

	mk := unlockMasterKey(i18n.T("auth.reason_restore", len(todo)))
	for _, rec := range todo {
		if err := store.SaveEncryptedRecord(rec, mk); err != nil {
			fatal(fmt.Errorf("%s: %w", rec.Alias, err))
		}
		fmt.Println("✓ " + i18n.T("import.done", rec.Alias, rec.Fingerprint))
	}
	fmt.Println(i18n.T("restore.done", len(todo), len(recs)))
}
