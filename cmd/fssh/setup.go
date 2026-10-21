package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"fssh/internal/config"
	"fssh/internal/auth"
	"fssh/internal/otp"
)

// runInteractiveSetup orchestrates the complete interactive setup wizard
func runInteractiveSetup(force bool, seedTTL int, algorithm string, digits int) {
	printWelcome()

	// Step 1: Check if already initialized
	if err := checkInitialization(force); err != nil {
		fatal(err)
	}

	// Step 2: Choose authentication mode
	authMode, err := promptAuthMode()
	if err != nil {
		fatal(err)
	}

	// Step 3: Execute authentication initialization
	fmt.Println()
	printStepHeader(3, 8, "Initialize Authentication")
	if authMode == "touchid" {
		initTouchIDMode(force)
	} else {
		initOTPMode(force, seedTTL, algorithm, digits)
	}

	// Step 4: Binary installation
	fmt.Println()
	printStepHeader(4, 8, "Binary Installation")
	if err := ensureBinaryInstalled(); err != nil {
		fmt.Printf("⚠️  Warning: Binary installation failed: %v\n", err)
		fmt.Println("You can install manually with:")
		fmt.Println("  sudo cp fssh /usr/local/bin/")
		fmt.Println()
	}

	// Step 5: Import SSH keys
	fmt.Println()
	printStepHeader(5, 8, "Import SSH Keys")
	if err := importSSHKeys(); err != nil {
		fmt.Printf("⚠️  Warning: SSH key import failed: %v\n", err)
		fmt.Println("You can import keys later with: fssh import")
		fmt.Println()
	}

	// Step 6: Configure LaunchAgent
	fmt.Println()
	printStepHeader(6, 8, "Configure LaunchAgent (Auto-start)")
	if err := setupLaunchAgent(); err != nil {
		fmt.Printf("⚠️  Warning: LaunchAgent setup failed: %v\n", err)
		fmt.Println("You can configure manually later")
		fmt.Println()
	}

	// Step 7: Start Agent
	fmt.Println()
	printStepHeader(7, 8, "Start SSH Agent")
	if err := startAgent(); err != nil {
		fmt.Printf("⚠️  Warning: Agent startup failed: %v\n", err)
		fmt.Println("You can start manually with: fssh agent")
		fmt.Println()
	}

	// Step 8: Configure SSH config
	fmt.Println()
	printStepHeader(8, 8, "Configure SSH Client")
	if err := addToSSHConfig(); err != nil {
		fmt.Printf("⚠️  Warning: SSH config update failed: %v\n", err)
		fmt.Println()
	}

	// Print completion message
	printSetupComplete()
}

// printWelcome displays the welcome banner
func printWelcome() {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║         Welcome to fssh Interactive Setup Wizard         ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("This wizard will help you:")
	fmt.Println("  1. Initialize authentication (Touch ID or OTP)")
	fmt.Println("  2. Install fssh binary to /usr/local/bin/")
	fmt.Println("  3. Import your SSH keys from ~/.ssh/")
	fmt.Println("  4. Configure LaunchAgent for auto-start")
	fmt.Println("  5. Start the SSH agent")
	fmt.Println("  6. Configure SSH client")
	fmt.Println()
}

// checkInitialization checks if fssh is already initialized
func checkInitialization(force bool) error {
	exists, _, err := auth.IsInitialized()
	if err != nil {
		return fmt.Errorf("failed to check initialization status: %w", err)
	}

	if exists && !force {
		fmt.Println("⚠️  fssh is already initialized!")
		fmt.Println()
		if !otp.PromptConfirm("Do you want to reinitialize? This will require re-importing all keys") {
			fmt.Println("Setup cancelled.")
			os.Exit(0)
		}
	}

	return nil
}

// promptAuthMode prompts the user to select authentication mode
func promptAuthMode() (string, error) {
	printStepHeader(2, 8, "Choose Authentication Mode")

	// Check Touch ID availability (macOS only)
	touchIDAvailable := runtime.GOOS == "darwin"

	if touchIDAvailable {
		fmt.Println("✓ Your Mac supports Touch ID!")
		fmt.Println()
	}

	fmt.Println("Available modes:")
	fmt.Println("  1) Touch ID (recommended) - Use your fingerprint")
	fmt.Println("  2) OTP - Use password + authenticator app")
	fmt.Println()

	for {
		choice, err := otp.PromptInput("Choose authentication mode [1]: ")
		if err != nil {
			return "", err
		}

		// Default to Touch ID
		if choice == "" {
			choice = "1"
		}

		switch choice {
		case "1", "touchid", "TouchID":
			if !touchIDAvailable {
				fmt.Println("❌ Touch ID is only available on macOS")
				continue
			}
			return "touchid", nil
		case "2", "otp", "OTP":
			return "otp", nil
		default:
			fmt.Println("Invalid choice. Please enter 1 or 2.")
		}
	}
}

// printStepHeader prints a step header
func printStepHeader(step, total int, title string) {
	fmt.Printf("Step %d/%d: %s\n", step, total, title)
	fmt.Println("──────────────────────────────────────")
	fmt.Println()
}

// printSetupComplete prints the completion message
func printSetupComplete() {
	// Get socket path
	home, _ := os.UserHomeDir()
	socketPath := filepath.Join(home, ".fssh", "agent.sock")

	// Try to load config to get actual socket path
	if cfg, err := config.Load(); err == nil && cfg.Socket != "" {
		socketPath = cfg.Socket
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║              Setup Complete! 🎉                           ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("⚠️  IMPORTANT: Set environment variable in your shell")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("Add this line to your shell configuration file:")
	fmt.Println()
	fmt.Printf("  export SSH_AUTH_SOCK=%s\n", socketPath)
	fmt.Println()
	fmt.Println("Shell configuration files:")
	fmt.Println("  • bash:   ~/.bashrc or ~/.bash_profile")
	fmt.Println("  • zsh:    ~/.zshrc")
	fmt.Println("  • fish:   ~/.config/fish/config.fish")
	fmt.Println()
	fmt.Println("Then reload your shell:")
	fmt.Println("  source ~/.zshrc   # or your shell config file")
	fmt.Println()
	fmt.Println("Or for current session only:")
	fmt.Printf("  export SSH_AUTH_SOCK=%s\n", socketPath)
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("Next Steps:")
	fmt.Println()
	fmt.Println("1. Set the environment variable (see above)")
	fmt.Println()
	fmt.Println("2. Test your setup:")
	fmt.Println("   ssh your-server  # Should prompt for Touch ID/OTP")
	fmt.Println()
	fmt.Println("3. Manage your keys:")
	fmt.Println("   fssh list        # List imported keys")
	fmt.Println("   fssh import      # Import more keys")
	fmt.Println("   fssh shell       # Interactive SSH management")
	fmt.Println()
	fmt.Println("4. Agent will auto-start on login via LaunchAgent")
	fmt.Println()
}
