package main

import (
	"fmt"
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
		return fmt.Errorf("failed to read SSH config: %w", err)
	} else if ok {
		fmt.Println("✓ SSH config already contains fssh agent configuration")
		return nil
	}

	// Another agent (e.g. 1Password) may already be configured; the fssh block
	// goes first and would take precedence for every host.
	if other, _ := otherIdentityAgent(socketPath); other != "" {
		fmt.Printf("⚠️  SSH config already uses another agent: %s\n", other)
		if !otp.PromptConfirm("Do you want fssh agent to take precedence for all hosts?") {
			fmt.Println("Skipped SSH config update")
			displayManualInstructions(socketPath)
			return nil
		}
	}

	fmt.Println("To use fssh agent automatically, we can add configuration to ~/.ssh/config")
	if !otp.PromptConfirm("Do you want to update SSH config?") {
		fmt.Println("Skipped SSH config update")
		displayManualInstructions(socketPath)
		return nil
	}

	if _, err := sshconfig.EnsureAgentBlock(tildify(socketPath)); err != nil {
		return fmt.Errorf("failed to update SSH config: %w", err)
	}
	fmt.Println("✓ Updated SSH config: ~/.ssh/config (a backup was saved next to it)")
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
	fmt.Println("To use fssh agent manually, add this to your ~/.ssh/config:")
	fmt.Println()
	fmt.Println("  Host *")
	fmt.Printf("      IdentityAgent %s\n", socketPath)
	fmt.Println()
	fmt.Println("Or set the environment variable:")
	fmt.Printf("  export SSH_AUTH_SOCK=%s\n", socketPath)
	fmt.Println()
}
