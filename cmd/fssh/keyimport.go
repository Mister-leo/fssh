package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"fssh/internal/i18n"
	"fssh/internal/otp"
	"fssh/internal/store"

	"golang.org/x/crypto/ssh"
)

const maxPassphraseAttempts = 3

// parseKeyWithRetry parses a private key. When interactive is true and the key
// needs a passphrase (missing or wrong), it prompts on the terminal up to
// maxPassphraseAttempts times. Errors are translated into user-facing messages.
func parseKeyWithRetry(alias string, keyData []byte, passphrase, comment string, interactive bool, promptPrefix string) (*store.Record, error) {
	attempts := 0
	for {
		rec, err := store.NewRecordFromPrivateKeyBytes(alias, keyData, passphrase, comment)
		if err == nil {
			return rec, nil
		}

		var missing *ssh.PassphraseMissingError
		isMissing := errors.As(err, &missing)
		isWrong := errors.Is(err, x509.IncorrectPasswordError)
		if !interactive || (!isMissing && !isWrong) {
			return nil, friendlyKeyError(err)
		}
		if attempts >= maxPassphraseAttempts {
			return nil, errors.New(i18n.T("import.err_too_many_attempts", maxPassphraseAttempts))
		}
		if isWrong {
			fmt.Fprintln(os.Stderr, promptPrefix+i18n.T("import.passphrase_retry", maxPassphraseAttempts-attempts))
		}
		attempts++
		passphrase, err = otp.PromptPassword(promptPrefix + i18n.T("import.prompt_passphrase"))
		if err != nil {
			return nil, err
		}
	}
}

// friendlyKeyError maps low-level key parsing errors to actionable messages.
func friendlyKeyError(err error) error {
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		return errors.New(i18n.T("import.err_passphrase_required"))
	case errors.Is(err, x509.IncorrectPasswordError):
		return errors.New(i18n.T("import.err_passphrase_wrong"))
	case strings.Contains(err.Error(), "no key found"):
		return errors.New(i18n.T("import.err_not_private_key"))
	default:
		return errors.New(i18n.T("import.err_parse", err))
	}
}

// aliasError translates store alias errors into user-facing messages.
func aliasError(alias string, err error) error {
	switch {
	case errors.Is(err, store.ErrInvalidAlias):
		return errors.New(i18n.T("key.err_alias_invalid", alias))
	case errors.Is(err, store.ErrNotFound):
		return errors.New(i18n.T("key.err_not_found", alias))
	default:
		return err
	}
}

// aliasTaken reports whether a record with alias already exists.
func aliasTaken(alias string) (bool, error) {
	_, err := store.LoadMeta(alias)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return false, err
}
