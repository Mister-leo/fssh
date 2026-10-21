package main

import (
	"testing"

	"fssh/internal/i18n"
)

// Help text is looked up by building keys from command names, so a new
// command without a translation would print its raw key.
func TestEveryCommandHasHelpText(t *testing.T) {
	for _, name := range commandNames {
		if !i18n.Has("cmd." + name) {
			t.Errorf("missing i18n key cmd.%s", name)
		}
	}
	for _, name := range otpSubcommands {
		if !i18n.Has("cmd.otp." + name) {
			t.Errorf("missing i18n key cmd.otp.%s", name)
		}
	}
	for _, r := range []string{"ok", "denied", "failed"} {
		if !i18n.Has("log.result_" + r) {
			t.Errorf("missing i18n key log.result_%s", r)
		}
	}
}
