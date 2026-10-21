package main

import (
	"fmt"
	"os"
	"strings"

	"fssh/internal/auth"
	"fssh/internal/i18n"
	"fssh/internal/macos"
	"fssh/internal/prompt"
	"fssh/internal/sshconfig"
	"fssh/internal/store"
)

// runInteractiveSetup orchestrates the complete interactive setup wizard.
// The welcome text and step headers come from the same list, so they can
// never disagree about the number of steps.
func runInteractiveSetup(force bool, o otpOptions) {
	type step struct {
		title string
		run   func()
	}
	steps := []step{
		{i18n.T("setup.step_auth"), func() { setupAuth(force, o) }},
		{i18n.T("setup.step_binary"), func() { warnOnError(ensureBinaryInstalled(), "setup.binary_failed") }},
		{i18n.T("setup.step_import"), func() { warnOnError(importSSHKeys(), "setup.import_failed") }},
		{i18n.T("setup.step_launchd"), func() { warnOnError(setupLaunchAgent(), "setup.launchd_failed") }},
		{i18n.T("setup.step_agent"), func() { warnOnError(startAgent(), "setup.agent_failed") }},
		{i18n.T("setup.step_sshconfig"), func() { warnOnError(addToSSHConfig(), "setup.sshconfig_failed") }},
		{i18n.T("setup.step_shellenv"), func() { warnOnError(setupShellEnv(), "setup.shellenv_failed") }},
	}

	fmt.Println()
	fmt.Println(i18n.T("setup.welcome"))
	fmt.Println()
	for i, s := range steps {
		fmt.Printf("  %d. %s\n", i+1, s.title)
	}
	fmt.Println()

	for i, s := range steps {
		fmt.Println()
		fmt.Printf("%s %d/%d: %s\n", i18n.T("setup.step"), i+1, len(steps), s.title)
		fmt.Println("──────────────────────────────────────")
		fmt.Println()
		s.run()
	}
	printSetupComplete()
}

// warnOnError reports a failed optional step; the wizard continues.
func warnOnError(err error, key string) {
	if err != nil {
		fmt.Println("⚠️  " + i18n.T(key, err))
		fmt.Println()
	}
}

// setupAuth initializes authentication, or handles an existing setup: keep
// it, switch mode (keys are kept), or start over.
func setupAuth(force bool, o otpOptions) {
	initialized, mode, err := auth.IsInitialized()
	if err != nil {
		fatal(err)
	}
	if !initialized {
		moveAsideOrphans()
		initMode(promptAuthMode(), o)
		return
	}

	choice := "3"
	if !force {
		metas, _ := store.ListMeta()
		fmt.Println(i18n.T("setup.already", mode, len(metas)))
		fmt.Println(i18n.T("setup.already_choices"))
		c, err := prompt.TTY{}.Text(i18n.T("import.original_choice"))
		if err != nil {
			fatal(err)
		}
		if choice = strings.TrimSpace(c); choice == "" {
			choice = "1"
		}
	}

	switch choice {
	case "1":
		fmt.Println(i18n.T("setup.keep", mode))
	case "2":
		target := auth.ModeOTP
		if mode == auth.ModeOTP {
			target = auth.ModeTouchID
		}
		switchMode(target, o)
	case "3":
		if !confirmReset() {
			fmt.Println(i18n.T("setup.cancelled"))
			os.Exit(0)
		}
		resetStore()
		initMode(promptAuthMode(), o)
	default:
		fmt.Println(i18n.T("setup.cancelled"))
		os.Exit(0)
	}
}

// promptAuthMode asks for the auth mode, recommending Touch ID. Without a
// usable sensor Touch ID mode still works: macOS asks for the login password.
func promptAuthMode() auth.AuthMode {
	if macos.BiometryAvailable() {
		fmt.Println("✓ " + i18n.T("setup.touchid_available"))
	} else {
		fmt.Println(i18n.T("setup.touchid_unavailable"))
	}
	fmt.Println()
	fmt.Println(i18n.T("setup.mode_choices"))
	fmt.Println()

	for {
		choice, err := prompt.TTY{}.Text(i18n.T("import.original_choice"))
		if err != nil {
			fatal(err)
		}
		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "", "1", "touchid":
			return auth.ModeTouchID
		case "2", "otp":
			return auth.ModeOTP
		default:
			fmt.Println(i18n.T("setup.invalid_choice"))
		}
	}
}

// printSetupComplete prints the completion message
func printSetupComplete() {
	sock := agentSocket()
	global, _, _ := sshconfig.AgentCoverage(sock)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("  " + i18n.T("setup.complete"))
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
	if !global && os.Getenv("SSH_AUTH_SOCK") != sock {
		fmt.Println("⚠️  " + i18n.T("setup.complete_not_connected", tildify(sock)))
		fmt.Println()
	}
	fmt.Println(i18n.T("setup.next_steps"))
	fmt.Println()
}
