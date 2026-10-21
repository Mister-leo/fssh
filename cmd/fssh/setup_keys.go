package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fssh/internal/i18n"
	"fssh/internal/otp"
	"fssh/internal/store"
	"golang.org/x/crypto/ssh"
)

// SSHKeyInfo holds metadata about a discovered SSH key
type SSHKeyInfo struct {
	Path        string
	Filename    string
	IsEncrypted bool
	Alias       string // Suggested alias
}

// importSSHKeys scans ~/.ssh/ and interactively imports discovered keys
func importSSHKeys() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	sshDir := filepath.Join(home, ".ssh")

	// Scan for SSH keys
	keys, err := scanSSHDirectory(sshDir)
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		fmt.Println("No SSH private keys found in ~/.ssh/")
		fmt.Println()
		fmt.Println("You can import keys later with: fssh import --alias <name> --file <path>")
		return nil
	}

	// Display found keys
	fmt.Printf("Found %d SSH private key(s):\n", len(keys))
	fmt.Println()

	for i, key := range keys {
		encrypted := ""
		if key.IsEncrypted {
			encrypted = " [encrypted]"
		}
		fmt.Printf("  %d) %s%s\n", i+1, key.Filename, encrypted)
		fmt.Printf("     Path: %s\n", key.Path)
		fmt.Println()
	}

	// Ask which keys to import
	fmt.Println("Enter the numbers of keys to import (e.g., '1,3' or '1-3' or 'all'):")
	selection, err := otp.PromptInput("Keys to import [all]: ")
	if err != nil {
		return fmt.Errorf("failed to read selection: %w", err)
	}

	// Trim and normalize input
	selection = strings.TrimSpace(selection)

	// Replace any Unicode spaces with regular spaces
	selection = strings.Map(func(r rune) rune {
		if r == '\u3000' || r == '\u00A0' || r == '\t' {
			return ' '
		}
		return r
	}, selection)

	// Remove all spaces for easier parsing
	selection = strings.ReplaceAll(selection, " ", "")

	if selection == "" {
		selection = "all"
	}

	if strings.ToLower(selection) == "none" || strings.ToLower(selection) == "skip" {
		fmt.Println("Skipped key import")
		return nil
	}

	// Parse selection
	selectedIndices, err := parseSelection(selection, len(keys))
	if err != nil {
		return fmt.Errorf("invalid selection: %w", err)
	}

	if len(selectedIndices) == 0 {
		fmt.Println("No keys selected")
		return nil
	}

	// Filter keys based on selection
	var keysToImport []*SSHKeyInfo
	for _, idx := range selectedIndices {
		keysToImport = append(keysToImport, keys[idx])
	}

	// Load master key
	mk, err := unlockMasterKeyErr(i18n.T("auth.reason_import_wizard"))
	if err != nil {
		return fmt.Errorf("failed to load master key: %w", err)
	}

	// Import selected keys
	fmt.Println()
	fmt.Printf("Importing %d key(s)...\n", len(keysToImport))
	fmt.Println()
	successCount := 0
	for i, key := range keysToImport {
		fmt.Printf("[%d/%d] Importing %s...\n", i+1, len(keysToImport), key.Filename)

		// Read key file
		keyData, err := os.ReadFile(key.Path)
		if err != nil {
			fmt.Printf("  ❌ Failed to read key file: %v\n", err)
			continue
		}

		// Parse first (prompting for the passphrase if needed) so that an
		// already imported key is skipped before asking for an alias
		rec, err := parseKeyWithRetry("", keyData, "", "", true, "  ")
		if err != nil {
			fmt.Printf("  ❌ %v\n", err)
			continue
		}
		if existing, ok, _ := store.FindByFingerprint(rec.Fingerprint); ok {
			fmt.Printf("  ✓ Already imported as '%s', skipped\n", existing)
			continue
		}

		// Prompt for alias with suggestion until it is valid and unused
		alias, err := promptNewAlias(uniqueAlias(generateAlias(key.Filename)))
		if err != nil {
			fmt.Printf("  ❌ Failed to read alias: %v\n", err)
			continue
		}
		rec.Alias = alias

		// Save encrypted record
		if err := store.SaveEncryptedRecord(rec, mk); err != nil {
			fmt.Printf("  ❌ Failed to save key: %v\n", err)
			continue
		}

		fmt.Printf("  ✓ Imported as '%s' (fingerprint: %s)\n", rec.Alias, rec.Fingerprint)
		successCount++
		handleOriginalKeyFile(key.Path, rec.Alias, "")
	}

	fmt.Println()
	if successCount > 0 {
		fmt.Printf("✓ Successfully imported %d/%d selected keys\n", successCount, len(keysToImport))
		if metas, _ := store.ListMeta(); len(metas) >= 2 {
			fmt.Println(i18n.T("setup.bind_hint"))
		}
	} else {
		fmt.Println("⚠️  No keys were imported")
	}

	return nil
}

// scanSSHDirectory scans the SSH directory for private key files
func scanSSHDirectory(sshDir string) ([]*SSHKeyInfo, error) {
	// Check if directory exists
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("SSH directory not found: %s", sshDir)
	}

	// Standard SSH private key patterns
	keyPatterns := []string{
		"id_rsa",
		"id_dsa",
		"id_ecdsa",
		"id_ed25519",
		"id_ecdsa_sk",
		"id_ed25519_sk",
	}

	var keys []*SSHKeyInfo

	// Read directory entries
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH directory: %w", err)
	}

	// Scan for keys
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()

		// Skip known non-key files
		if strings.HasSuffix(filename, ".pub") ||
			strings.HasSuffix(filename, ".ppk") ||
			filename == "config" ||
			filename == "known_hosts" ||
			filename == "authorized_keys" {
			continue
		}

		// Check if it matches standard patterns OR has no extension
		isStandardKey := false
		for _, pattern := range keyPatterns {
			if strings.HasPrefix(filename, pattern) {
				isStandardKey = true
				break
			}
		}

		// Also check files without extensions (potential custom keys)
		if !isStandardKey && !strings.Contains(filename, ".") {
			isStandardKey = true
		}

		if !isStandardKey {
			continue
		}

		keyPath := filepath.Join(sshDir, filename)

		// Analyze the key
		keyInfo := analyzeKeyFile(keyPath)
		if keyInfo != nil {
			keys = append(keys, keyInfo)
		}
	}

	return keys, nil
}

// analyzeKeyFile analyzes a potential SSH key file
func analyzeKeyFile(path string) *SSHKeyInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Try to parse as private key
	_, err = ssh.ParseRawPrivateKey(data)

	info := &SSHKeyInfo{
		Path:     path,
		Filename: filepath.Base(path),
	}

	if err != nil {
		// Check if it's an encrypted key
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			info.IsEncrypted = true
		} else {
			// Not a valid private key
			return nil
		}
	}

	return info
}

// generateAlias generates a suggested alias from the filename
func generateAlias(filename string) string {
	// Remove "id_" prefix if present
	alias := strings.TrimPrefix(filename, "id_")

	// Remove common suffixes
	alias = strings.TrimSuffix(alias, "_sk")

	// If empty after trimming, use original filename
	if alias == "" {
		alias = filename
	}

	return alias
}

// sanitizeAlias turns an arbitrary filename into a valid alias.
func sanitizeAlias(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	alias := strings.TrimLeft(b.String(), "._-")
	if len(alias) > 56 {
		alias = alias[:56] // leave room for a "-N" suffix
	}
	if alias == "" {
		alias = "key"
	}
	return alias
}

// uniqueAlias makes a suggested alias valid and unused, e.g. "rsa" -> "rsa-2".
func uniqueAlias(base string) string {
	base = sanitizeAlias(base)
	alias := base
	for i := 2; ; i++ {
		if taken, err := aliasTaken(alias); err != nil || !taken {
			return alias
		}
		alias = fmt.Sprintf("%s-%d", base, i)
	}
}

// promptNewAlias asks for an alias until it is valid and not already used.
// Empty input accepts the suggestion, which must itself be valid and unused.
func promptNewAlias(suggested string) (string, error) {
	for {
		alias, err := otp.PromptInput(fmt.Sprintf("  Alias [%s]: ", suggested))
		if err != nil {
			return "", err
		}
		if alias == "" {
			alias = suggested
		}
		if err := store.ValidateAlias(alias); err != nil {
			fmt.Printf("  ❌ %v\n", aliasError(alias, err))
			continue
		}
		taken, err := aliasTaken(alias)
		if err != nil {
			return "", err
		}
		if taken {
			fmt.Printf("  ❌ Alias '%s' is already used, choose another\n", alias)
			continue
		}
		return alias, nil
	}
}

// parseSelection parses user selection string into indices
// Supports formats: "all", "1", "1,3", "1-3", "1,3-5,7"
// Note: Input should already be cleaned (no spaces)
func parseSelection(selection string, total int) ([]int, error) {
	// Handle "all"
	if strings.ToLower(selection) == "all" {
		indices := make([]int, total)
		for i := 0; i < total; i++ {
			indices[i] = i
		}
		return indices, nil
	}

	var indices []int
	seen := make(map[int]bool)

	// Split by comma
	parts := strings.Split(selection, ",")
	for _, part := range parts {
		if part == "" {
			continue // Skip empty parts
		}

		// Check if it's a range (e.g., "1-3")
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range format: '%s'", part)
			}

			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid number in range: '%s' (error: %v)", rangeParts[0], err)
			}

			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid number in range: '%s' (error: %v)", rangeParts[1], err)
			}

			if start < 1 || end > total || start > end {
				return nil, fmt.Errorf("range %d-%d is out of bounds (valid range: 1-%d)", start, end, total)
			}

			for i := start; i <= end; i++ {
				idx := i - 1 // Convert to 0-based index
				if !seen[idx] {
					indices = append(indices, idx)
					seen[idx] = true
				}
			}
		} else {
			// Single number
			num, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid number: '%s' (error: %v)", part, err)
			}

			if num < 1 || num > total {
				return nil, fmt.Errorf("number %d is out of bounds (valid range: 1-%d)", num, total)
			}

			idx := num - 1 // Convert to 0-based index
			if !seen[idx] {
				indices = append(indices, idx)
				seen[idx] = true
			}
		}
	}

	if len(indices) == 0 {
		return nil, fmt.Errorf("no valid keys selected")
	}

	return indices, nil
}
