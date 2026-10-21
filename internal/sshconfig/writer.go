package sshconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WriteHostConfig writes or updates a host configuration to ~/.ssh/config
// If overwrite is true, replaces existing host block
// If overwrite is false and host exists, returns error
func WriteHostConfig(cfg *HostConfig, overwrite bool) error {
	// 1. Validate configuration
	if err := ValidateHostConfig(cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// 2. Create backup
	backupPath, err := backupSSHConfig()
	if err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	// 3. Read current config
	lines, err := readSSHConfigLines()
	if err != nil {
		return err
	}

	// 4. Find existing host block
	start, end, found := findHostBlock(lines, cfg.Name)

	// 5. Check overwrite policy
	if found && !overwrite {
		return fmt.Errorf("host %s already exists (use overwrite=true to replace)", cfg.Name)
	}

	// 6. Render new host block
	newBlock := renderHostBlock(cfg)
	newBlockLines := strings.Split(strings.TrimRight(newBlock, "\n"), "\n")

	// 7. Construct updated config
	var result []string
	if found {
		// Replace existing block, keeping what HostConfig does not model
		newBlockLines = mergePreserved(lines[start:end], newBlockLines, cfg.Name)
		result = append(result, lines[:start]...)
		result = append(result, newBlockLines...)
		result = append(result, lines[end:]...)
	} else {
		// Append new block
		result = append(result, lines...)
		if len(result) > 0 && result[len(result)-1] != "" {
			result = append(result, "") // Blank line before new host
		}
		result = append(result, newBlockLines...)
	}

	// 8. Write updated config
	if err := writeSSHConfigLines(result); err != nil {
		// Attempt to restore backup on failure
		if backupPath != "" {
			configPath := sshConfigPath()
			_ = copyFile(backupPath, configPath)
		}
		return err
	}

	return nil
}

// DeleteHostConfig removes a host from SSH config
func DeleteHostConfig(hostName string) error {
	// 1. Create backup
	backupPath, err := backupSSHConfig()
	if err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	// 2. Read current config
	lines, err := readSSHConfigLines()
	if err != nil {
		return err
	}

	// 3. Find host block
	start, end, found := findHostBlock(lines, hostName)
	if !found {
		return fmt.Errorf("host %s not found", hostName)
	}

	// 4. Remove block (including surrounding blank lines)
	result := append(lines[:start], lines[end:]...)

	// 5. Clean up extra blank lines
	result = cleanupBlankLines(result)

	// 6. Write updated config
	if err := writeSSHConfigLines(result); err != nil {
		// Attempt to restore backup on failure
		if backupPath != "" {
			configPath := sshConfigPath()
			_ = copyFile(backupPath, configPath)
		}
		return err
	}

	return nil
}

// LoadHostConfig loads a specific host configuration
func LoadHostConfig(hostName string) (*HostConfig, error) {
	lines, err := readSSHConfigLines()
	if err != nil {
		return nil, err
	}

	start, end, found := findHostBlock(lines, hostName)
	if !found {
		return nil, fmt.Errorf("host %s not found", hostName)
	}

	return parseHostBlock(lines, start, end)
}

// LoadAllHostConfigs loads all host configurations
func LoadAllHostConfigs() (map[string]*HostConfig, error) {
	lines, err := readSSHConfigLines()
	if err != nil {
		return nil, err
	}

	configs := make(map[string]*HostConfig)
	i := 0
	for i < len(lines) {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(strings.ToLower(line), "host ") {
			// Find end of this host block
			start := i
			end := i + 1
			for end < len(lines) {
				nextLine := strings.ToLower(strings.TrimSpace(lines[end]))
				if strings.HasPrefix(nextLine, "host ") || strings.HasPrefix(nextLine, "match ") {
					break
				}
				end++
			}

			// Parse this host block
			cfg, err := parseHostBlock(lines, start, end)
			if err == nil {
				configs[cfg.Name] = cfg
			}
			i = end
		} else {
			i++
		}
	}

	return configs, nil
}

// --- Helper functions ---

// managedKeys are the directives HostConfig models; renderHostBlock writes
// them, so mergePreserved drops their old lines.
var managedKeys = map[string]bool{
	"hostname": true, "user": true, "port": true, "identityagent": true,
	"identityfile": true, "identitiesonly": true, "proxyjump": true,
	"proxycommand": true, "forwardagent": true, "serveraliveinterval": true,
	"serveralivecountmax": true, "addkeystoagent": true, "usekeychain": true,
	"pubkeyacceptedalgorithms": true, "stricthostkeychecking": true,
	"userknownhostsfile": true, "compression": true, "tcpkeepalive": true,
}

// mergePreserved keeps what a rewrite would otherwise lose: the original Host
// line (with any extra aliases) and every comment, blank line and directive
// HostConfig does not model (LocalForward, SetEnv, ...), in original order.
func mergePreserved(oldBlock, newBlock []string, name string) []string {
	if len(oldBlock) == 0 {
		return newBlock
	}
	out := append([]string(nil), newBlock...)
	if _, v := parseKV(oldBlock[0]); containsField(v, name) {
		out[0] = oldBlock[0]
	}
	// trailing blank lines stay at the end of the block
	body := oldBlock[1:]
	tail := len(body)
	for tail > 0 && strings.TrimSpace(body[tail-1]) == "" {
		tail--
	}
	for _, line := range body[:tail] {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if k, _ := parseKV(trimmed); managedKeys[k] {
				continue
			}
		}
		out = append(out, line)
	}
	return append(out, body[tail:]...)
}

func containsField(s, name string) bool {
	for _, f := range strings.Fields(s) {
		if f == name {
			return true
		}
	}
	return false
}

func sshConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "config")
}

func backupSSHConfig() (string, error) {
	configPath := sshConfigPath()

	// Check if config exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// No config file, no backup needed
		return "", nil
	}

	// Create timestamped backup
	timestamp := time.Now().Unix()
	backupPath := fmt.Sprintf("%s.bak.%d", configPath, timestamp)

	// Copy file
	if err := copyFile(configPath, backupPath); err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}

	return backupPath, nil
}

func readSSHConfigLines() ([]string, error) {
	configPath := sshConfigPath()

	// Read file
	content, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Config doesn't exist, return empty
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// Split into lines
	lines := strings.Split(string(content), "\n")

	// Remove trailing newline if present (to avoid extra blank line)
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	return lines, nil
}

func writeSSHConfigLines(lines []string) error {
	configPath := sshConfigPath()

	// Create .ssh directory if it doesn't exist
	sshDir := filepath.Dir(configPath)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Write to temporary file first (atomic write pattern)
	tmpPath := configPath + ".tmp"
	content := strings.Join(lines, "\n")
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	if err := os.WriteFile(tmpPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, configPath); err != nil {
		os.Remove(tmpPath) // Clean up temp file
		return fmt.Errorf("failed to update config: %w", err)
	}

	return nil
}

// findHostBlock finds the line range of a host block
// Returns (start, end, found) where end is exclusive
func findHostBlock(lines []string, hostName string) (int, int, bool) {
	inBlock := false
	start := -1

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "match ") && inBlock {
			// a Match block also ends the current Host block
			return start, i, true
		}
		if strings.HasPrefix(lower, "host ") {
			hostParts := strings.Fields(line[5:])

			// Check if this is our target host
			isTarget := false
			for _, h := range hostParts {
				if h == hostName {
					isTarget = true
					break
				}
			}

			if isTarget && !inBlock {
				// Found start of target block
				inBlock = true
				start = i
			} else if inBlock {
				// Found next host block, end of target
				return start, i, true
			}
		}
	}

	// If we found the start but no next host, block extends to EOF
	if inBlock {
		return start, len(lines), true
	}

	return -1, -1, false
}

// renderHostBlock converts HostConfig to SSH config format
func renderHostBlock(cfg *HostConfig) string {
	var b strings.Builder

	b.WriteString("Host ")
	b.WriteString(cfg.Name)
	b.WriteString("\n")

	if cfg.Hostname != "" {
		b.WriteString("  Hostname ")
		b.WriteString(cfg.Hostname)
		b.WriteString("\n")
	}

	if cfg.User != "" {
		b.WriteString("  User ")
		b.WriteString(cfg.User)
		b.WriteString("\n")
	}

	if cfg.Port != "" {
		b.WriteString("  Port ")
		b.WriteString(cfg.Port)
		b.WriteString("\n")
	}

	// Identity configuration
	if cfg.IdentityAgent != "" {
		b.WriteString("  IdentityAgent ")
		b.WriteString(cfg.IdentityAgent)
		b.WriteString("\n")
	}

	for _, idFile := range cfg.IdentityFile {
		b.WriteString("  IdentityFile ")
		b.WriteString(idFile)
		b.WriteString("\n")
	}

	if cfg.IdentitiesOnly != "" {
		b.WriteString("  IdentitiesOnly ")
		b.WriteString(cfg.IdentitiesOnly)
		b.WriteString("\n")
	}

	// Proxy configuration (mutually exclusive)
	if cfg.ProxyJump != "" {
		b.WriteString("  ProxyJump ")
		b.WriteString(cfg.ProxyJump)
		b.WriteString("\n")
	} else if cfg.ProxyCommand != "" {
		b.WriteString("  ProxyCommand ")
		b.WriteString(cfg.ProxyCommand)
		b.WriteString("\n")
	}

	// Additional options
	if cfg.ForwardAgent != "" {
		b.WriteString("  ForwardAgent ")
		b.WriteString(cfg.ForwardAgent)
		b.WriteString("\n")
	}

	if cfg.ServerAliveInterval != "" {
		b.WriteString("  ServerAliveInterval ")
		b.WriteString(cfg.ServerAliveInterval)
		b.WriteString("\n")
	}

	// Global configuration options
	if cfg.ServerAliveCountMax != "" {
		b.WriteString("  ServerAliveCountMax ")
		b.WriteString(cfg.ServerAliveCountMax)
		b.WriteString("\n")
	}

	if cfg.AddKeysToAgent != "" {
		b.WriteString("  AddKeysToAgent ")
		b.WriteString(cfg.AddKeysToAgent)
		b.WriteString("\n")
	}

	if cfg.UseKeychain != "" {
		b.WriteString("  UseKeychain ")
		b.WriteString(cfg.UseKeychain)
		b.WriteString("\n")
	}

	if cfg.PubkeyAcceptedAlgorithms != "" {
		b.WriteString("  PubkeyAcceptedAlgorithms ")
		b.WriteString(cfg.PubkeyAcceptedAlgorithms)
		b.WriteString("\n")
	}

	if cfg.StrictHostKeyChecking != "" {
		b.WriteString("  StrictHostKeyChecking ")
		b.WriteString(cfg.StrictHostKeyChecking)
		b.WriteString("\n")
	}

	if cfg.UserKnownHostsFile != "" {
		b.WriteString("  UserKnownHostsFile ")
		b.WriteString(cfg.UserKnownHostsFile)
		b.WriteString("\n")
	}

	if cfg.Compression != "" {
		b.WriteString("  Compression ")
		b.WriteString(cfg.Compression)
		b.WriteString("\n")
	}

	if cfg.TCPKeepAlive != "" {
		b.WriteString("  TCPKeepAlive ")
		b.WriteString(cfg.TCPKeepAlive)
		b.WriteString("\n")
	}

	return b.String()
}

// parseHostBlock parses a host block into HostConfig
func parseHostBlock(lines []string, start, end int) (*HostConfig, error) {
	if start >= len(lines) {
		return nil, fmt.Errorf("invalid start index")
	}

	cfg := &HostConfig{LineNumber: start}

	// Parse Host line
	hostLine := strings.TrimSpace(lines[start])
	if !strings.HasPrefix(strings.ToLower(hostLine), "host ") {
		return nil, fmt.Errorf("invalid host block: expected 'Host' directive")
	}
	hostParts := strings.Fields(hostLine[5:])
	if len(hostParts) == 0 {
		return nil, fmt.Errorf("empty host name")
	}
	cfg.Name = hostParts[0]

	// Mark global configs
	if cfg.Name == "*" {
		cfg.IsGlobal = true
	}

	// Parse configuration directives
	for i := start + 1; i < end; i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Skip blank lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Stop at next Host or Match directive
		if lower := strings.ToLower(trimmed); strings.HasPrefix(lower, "host ") || strings.HasPrefix(lower, "match ") {
			break
		}

		key, value := parseKV(trimmed)
		switch key {
		case "hostname":
			cfg.Hostname = value
		case "user":
			cfg.User = value
		case "port":
			cfg.Port = value
		case "identityfile":
			cfg.IdentityFile = append(cfg.IdentityFile, value)
		case "identityagent":
			cfg.IdentityAgent = value
		case "identitiesonly":
			cfg.IdentitiesOnly = value
		case "proxycommand":
			cfg.ProxyCommand = value
		case "proxyjump":
			cfg.ProxyJump = value
		case "forwardagent":
			cfg.ForwardAgent = value
		case "serveraliveinterval":
			cfg.ServerAliveInterval = value
		case "serveralivecountmax":
			cfg.ServerAliveCountMax = value
		case "addkeystoagent":
			cfg.AddKeysToAgent = value
		case "usekeychain":
			cfg.UseKeychain = value
		case "pubkeyacceptedalgorithms":
			cfg.PubkeyAcceptedAlgorithms = value
		case "stricthostkeychecking":
			cfg.StrictHostKeyChecking = value
		case "userknownhostsfile":
			cfg.UserKnownHostsFile = value
		case "compression":
			cfg.Compression = value
		case "tcpkeepalive":
			cfg.TCPKeepAlive = value
		}
	}

	return cfg, nil
}

// cleanupBlankLines removes excessive blank lines (more than 2 consecutive)
func cleanupBlankLines(lines []string) []string {
	var result []string
	blankCount := 0

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			blankCount++
			if blankCount <= 2 {
				result = append(result, line)
			}
		} else {
			blankCount = 0
			result = append(result, line)
		}
	}

	return result
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	content, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, content, 0600)
}
