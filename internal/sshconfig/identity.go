package sshconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrDefinedElsewhere means a host exists only in a file pulled in by
// Include, which fssh does not edit.
type ErrDefinedElsewhere struct {
	Host, File string
}

func (e *ErrDefinedElsewhere) Error() string {
	return fmt.Sprintf("host %s is defined in %s", e.Host, e.File)
}

// SetIdentity binds host to one key held by the agent at agentSock:
//
//	IdentityAgent <agentSock>
//	IdentityFile  <pubPath>
//	IdentitiesOnly yes
//
// Existing IdentityAgent / IdentityFile / IdentitiesOnly lines in the block
// are replaced; everything else is untouched. A missing host gets a new
// block. Returns whether a block was created.
func SetIdentity(host, agentSock, pubPath string) (bool, error) {
	if host == "" || strings.ContainsAny(host, " \t*?!") {
		return false, fmt.Errorf("invalid host name %q", host)
	}
	lines, err := readSSHConfigLines()
	if err != nil {
		return false, err
	}
	directives := []string{
		"  IdentityAgent " + agentSock,
		"  IdentityFile " + pubPath,
		"  IdentitiesOnly yes",
	}

	start, end, found := findHostBlock(lines, host)
	var result []string
	if found {
		result = append(result, lines[:start+1]...)
		result = append(result, directives...)
		for _, line := range lines[start+1 : end] {
			if k, _ := parseKV(line); k == "identityagent" || k == "identityfile" || k == "identitiesonly" {
				continue
			}
			result = append(result, line)
		}
		result = append(result, lines[end:]...)
	} else {
		if hi, ok, err := FindHost(host); err == nil && ok && hi.Source != sshConfigPath() {
			return false, &ErrDefinedElsewhere{Host: host, File: hi.Source}
		}
		result = append(result, lines...)
		if len(result) > 0 && strings.TrimSpace(result[len(result)-1]) != "" {
			result = append(result, "")
		}
		result = append(result, "Host "+host)
		result = append(result, directives...)
	}
	return !found, writeWithBackup(result)
}

// ClearIdentity removes IdentityFile lines pointing into pubDir and, if no
// IdentityFile remains, IdentitiesOnly. Returns whether anything changed.
func ClearIdentity(host, pubDir string) (bool, error) {
	lines, err := readSSHConfigLines()
	if err != nil {
		return false, err
	}
	start, end, found := findHostBlock(lines, host)
	if !found {
		if hi, ok, err := FindHost(host); err == nil && ok && hi.Source != sshConfigPath() {
			return false, &ErrDefinedElsewhere{Host: host, File: hi.Source}
		}
		return false, fmt.Errorf("host %s not found", host)
	}

	var body []string
	removed, otherFiles := false, false
	for _, line := range lines[start+1 : end] {
		k, v := parseKV(line)
		if k == "identityfile" {
			if isUnder(expandHomePath(v), pubDir) {
				removed = true
				continue
			}
			otherFiles = true
		}
		body = append(body, line)
	}
	if !removed {
		return false, nil
	}
	if !otherFiles {
		kept := body[:0]
		for _, line := range body {
			if k, _ := parseKV(line); k != "identitiesonly" {
				kept = append(kept, line)
			}
		}
		body = kept
	}
	result := append(append(append([]string{}, lines[:start+1]...), body...), lines[end:]...)
	return true, writeWithBackup(result)
}

// BoundKey returns the fssh key alias a host config is bound to, i.e. the
// first IdentityFile inside pubDir ("<alias>.pub").
func BoundKey(cfg *HostConfig, pubDir string) string {
	for _, f := range cfg.IdentityFile {
		p := expandHomePath(f)
		if isUnder(p, pubDir) && strings.HasSuffix(p, ".pub") {
			return strings.TrimSuffix(filepath.Base(p), ".pub")
		}
	}
	return ""
}

// HostsBoundTo lists hosts in ~/.ssh/config bound to the key alias.
func HostsBoundTo(alias, pubDir string) ([]string, error) {
	cfgs, err := LoadAllHostConfigs()
	if err != nil {
		return nil, err
	}
	var hosts []string
	for name, cfg := range cfgs {
		if BoundKey(cfg, pubDir) == alias {
			hosts = append(hosts, name)
		}
	}
	return hosts, nil
}

// ---- managed block ----

const (
	managedBegin = "# >>> fssh managed >>>"
	managedEnd   = "# <<< fssh managed <<<"
	// written by versions before the managed markers
	legacyManagedComment = "# fssh agent configuration"
)

// EnsureAgentBlock puts a marked "Host * / IdentityAgent" block at the top of
// ~/.ssh/config (ssh uses the first value it finds, so it must come first).
// An existing managed or legacy block is replaced. Returns whether the file
// changed.
func EnsureAgentBlock(agentSock string) (bool, error) {
	lines, err := readSSHConfigLines()
	if err != nil {
		return false, err
	}
	block := []string{managedBegin, "Host *", "    IdentityAgent " + agentSock, managedEnd, ""}
	rest, _ := withoutAgentBlock(lines)
	result := append(block, rest...)
	if strings.Join(result, "\n") == strings.Join(lines, "\n") {
		return false, nil
	}
	return true, writeWithBackup(result)
}

// RemoveAgentBlock removes the managed (or legacy) block. Returns whether
// one was found.
func RemoveAgentBlock() (bool, error) {
	lines, err := readSSHConfigLines()
	if err != nil {
		return false, err
	}
	rest, found := withoutAgentBlock(lines)
	if !found {
		return false, nil
	}
	return true, writeWithBackup(rest)
}

// AgentCoverage reports how ~/.ssh/config routes ssh to agentSock: global
// when it applies to every host (top level or a "Host *" block), partial when
// only specific hosts use it.
func AgentCoverage(agentSock string) (global, partial bool, err error) {
	lines, err := readSSHConfigLines()
	if err != nil {
		return false, false, err
	}
	allHosts := true // directives before any Host/Match apply to every host
	for _, line := range lines {
		k, v := parseKV(line)
		switch k {
		case "host":
			allHosts = containsField(v, "*")
		case "match":
			allHosts = strings.EqualFold(strings.TrimSpace(v), "all")
		case "identityagent":
			if expandHomePath(v) != agentSock {
				continue
			}
			if allHosts {
				global = true
			} else {
				partial = true
			}
		}
	}
	return global, partial, nil
}

// AgentConfigured reports whether every host uses agentSock.
func AgentConfigured(agentSock string) (bool, error) {
	global, _, err := AgentCoverage(agentSock)
	return global, err
}

func withoutAgentBlock(lines []string) ([]string, bool) {
	for i, line := range lines {
		switch strings.TrimSpace(line) {
		case managedBegin:
			for j := i + 1; j < len(lines); j++ {
				if strings.TrimSpace(lines[j]) == managedEnd {
					return dropBlankAt(append(append([]string{}, lines[:i]...), lines[j+1:]...), i), true
				}
			}
		case legacyManagedComment:
			// "# fssh agent configuration" + "Host *" + "IdentityAgent ..."
			if i+2 < len(lines) && strings.EqualFold(strings.TrimSpace(lines[i+1]), "host *") {
				if k, _ := parseKV(lines[i+2]); k == "identityagent" {
					return dropBlankAt(append(append([]string{}, lines[:i]...), lines[i+3:]...), i), true
				}
			}
		}
	}
	return lines, false
}

// dropBlankAt removes a single blank line left at index i by block removal.
func dropBlankAt(lines []string, i int) []string {
	if i < len(lines) && strings.TrimSpace(lines[i]) == "" {
		return append(lines[:i], lines[i+1:]...)
	}
	return lines
}

func writeWithBackup(lines []string) error {
	backupPath, err := backupSSHConfig()
	if err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}
	if err := writeSSHConfigLines(lines); err != nil {
		if backupPath != "" {
			_ = copyFile(backupPath, sshConfigPath())
		}
		return err
	}
	return nil
}

func expandHomePath(p string) string {
	p = strings.Trim(p, `"`)
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func isUnder(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel)
}

// HostsUsingIdentityFile lists hosts in ~/.ssh/config whose IdentityFile is path.
func HostsUsingIdentityFile(path string) ([]string, error) {
	cfgs, err := LoadAllHostConfigs()
	if err != nil {
		return nil, err
	}
	var hosts []string
	for name, cfg := range cfgs {
		for _, f := range cfg.IdentityFile {
			if expandHomePath(f) == path {
				hosts = append(hosts, name)
				break
			}
		}
	}
	return hosts, nil
}
