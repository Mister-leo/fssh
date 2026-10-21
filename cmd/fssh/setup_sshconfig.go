package main

import (
	"errors"
	"fmt"
	"fssh/internal/i18n"
	"os"
	"path/filepath"
	"strings"

	"fssh/internal/otp"
	"fssh/internal/sshconfig"
)

// addToSSHConfig adds fssh agent configuration to SSH config
func addToSSHConfig() error {
	socketPath := agentSocket()

	if ok, err := sshconfig.AgentConfigured(socketPath); err != nil {
		return errors.New(i18n.T("sshsetup.err", err))
	} else if ok {
		fmt.Println("✓ " + i18n.T("doctor.ssh_ok"))
		return nil
	}

	// Another agent (e.g. 1Password) may already be configured; the fssh block
	// goes first and would take precedence for every host.
	if other, _ := otherIdentityAgent(socketPath); other != "" {
		fmt.Println("⚠️  " + i18n.T("sshsetup.other_agent", other))
		if !otp.PromptConfirm(i18n.T("sshsetup.other_agent_confirm")) {
			fmt.Println(i18n.T("sshsetup.skipped"))
			displayManualInstructions(socketPath)
			return nil
		}
	}

	fmt.Println(i18n.T("sshsetup.explain"))
	if !otp.PromptConfirm(i18n.T("sshsetup.confirm")) {
		fmt.Println(i18n.T("sshsetup.skipped"))
		displayManualInstructions(socketPath)
		return nil
	}

	if _, err := sshconfig.EnsureAgentBlock(tildify(socketPath)); err != nil {
		return errors.New(i18n.T("sshsetup.err", err))
	}
	fmt.Println("✓ " + i18n.T("sshsetup.done"))
	return nil
}

// otherIdentityAgent returns an IdentityAgent value in ~/.ssh/config that is
// not the fssh socket, if any.
func otherIdentityAgent(socketPath string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "IdentityAgent") {
			v := strings.Trim(fields[1], `"`)
			if strings.HasPrefix(v, "~/") {
				v = filepath.Join(home, v[2:])
			}
			if v != socketPath && v != "none" {
				return fields[1], nil
			}
		}
	}
	return "", nil
}

// displayManualInstructions shows manual configuration instructions
func displayManualInstructions(socketPath string) {
	fmt.Println()
	fmt.Println(i18n.T("doctor.fix_ssh", tildify(socketPath)))
	fmt.Println()
}
