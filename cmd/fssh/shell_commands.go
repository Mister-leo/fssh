package main

import (
	"fmt"
	"fssh/internal/i18n"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fssh/internal/sshconfig"
	"fssh/internal/store"
	"github.com/peterh/liner"
)

// cleanLinerInput 清理 liner 输入，移除 ANSI 转义序列和控制字符
func cleanLinerInput(input string) string {
	input = strings.TrimSpace(input)
	var cleaned strings.Builder
	inEscape := false
	for _, r := range input {
		if r == '\x1b' || r == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}
		if r < 32 || r == 127 {
			continue
		}
		if r == '\u3000' || r == '\u00A0' {
			continue
		}
		cleaned.WriteRune(r)
	}
	return strings.TrimSpace(cleaned.String())
}

// ShellContext holds state for shell commands
type ShellContext struct {
	infos        []sshconfig.HostInfo
	hosts        []string
	byName       map[string]sshconfig.HostInfo
	byHostname   map[string]sshconfig.HostInfo
	ipToName     map[string]string
	idToName     map[string]string
	hostnames    []string
	ips          []string
	ids          []string
	liner        *liner.State
	importedKeys []string
	idOf         map[string]string // host name -> list id
	boundKey     map[string]string // host name -> fssh key alias
}

// cmdAdd adds a new SSH host configuration
func cmdAdd(ctx *ShellContext) error {
	fmt.Println(i18n.T("shell.add_new_ssh_host"))

	cfg := &sshconfig.HostConfig{}

	// 1. Host Alias (required)
	for {
		line, err := ctx.liner.Prompt(i18n.T("shell.host_alias_e_g_myserver"))
		if err != nil {
			return err
		}
		alias := strings.TrimSpace(line)
		if alias == "" {
			fmt.Println(i18n.T("shell.error_host_alias_is_required"))
			continue
		}
		// Check if already exists
		if _, exists := ctx.byName[alias]; exists {
			fmt.Printf(i18n.T("shell.warning_host_s_already_exists_use"), alias, alias)
			return nil
		}
		cfg.Name = alias
		break
	}

	// 2. Hostname/IP (required)
	for {
		line, err := ctx.liner.Prompt(i18n.T("shell.hostname_or_ip"))
		if err != nil {
			return err
		}
		hostname := strings.TrimSpace(line)
		if hostname == "" {
			fmt.Println(i18n.T("shell.error_hostname_is_required"))
			continue
		}
		cfg.Hostname = hostname
		break
	}

	// 3. Username (optional)
	line, _ := ctx.liner.Prompt(i18n.T("shell.username_press_enter_to_skip"))
	cfg.User = strings.TrimSpace(line)

	// 4. Port (optional)
	line, _ = ctx.liner.Prompt(i18n.T("shell.port_22"))
	port := strings.TrimSpace(line)
	if port != "" && port != "22" {
		cfg.Port = port
	}

	// 5. Private Key Selection
	fmt.Println(i18n.T("shell.private_key_configuration"))
	fmt.Println(i18n.T("shell.1_use_fssh_agent_recommended"))
	fmt.Println(i18n.T("shell.2_direct_identityfile_path"))
	fmt.Println(i18n.T("shell.3_none_password_authentication"))
	line, _ = ctx.liner.Prompt(i18n.T("shell.choice_1"))
	choice := strings.TrimSpace(line)
	if choice == "" {
		choice = "1"
	}

	switch choice {
	case "1":
		applyAgentIdentity(cfg, chooseKey(ctx))

	case "2":
		line, _ := ctx.liner.Prompt(i18n.T("shell.identityfile_path"))
		idFile := strings.TrimSpace(line)
		if idFile != "" {
			cfg.IdentityFile = []string{idFile}
		}

	case "3":
		// No identity configuration
		fmt.Println(i18n.T("shell.using_password_authentication"))
	}

	// 6. Proxy Configuration
	fmt.Println(i18n.T("shell.proxy_configuration"))
	fmt.Println(i18n.T("shell.1_no_proxy"))
	fmt.Println(i18n.T("shell.2_socks5_proxy"))
	fmt.Println(i18n.T("shell.3_ssh_jump_host_proxyjump"))
	fmt.Println(i18n.T("shell.4_custom_proxycommand"))
	line, _ = ctx.liner.Prompt(i18n.T("shell.choice_1"))
	proxyChoice := strings.TrimSpace(line)
	if proxyChoice == "" {
		proxyChoice = "1"
	}

	switch proxyChoice {
	case "2":
		proxyHost, _ := ctx.liner.Prompt(i18n.T("shell.socks5_proxy_host"))
		proxyPort, _ := ctx.liner.Prompt(i18n.T("shell.socks5_proxy_port_1080"))
		if proxyPort == "" {
			proxyPort = "1080"
		}

		// Detect which tool to use
		fmt.Println("  a) nc (netcat)")
		fmt.Println("  b) ncat (nmap ncat)")
		tool, _ := ctx.liner.Prompt(i18n.T("shell.tool_a"))

		proxyType := sshconfig.ProxyTypeSocks5NC
		if tool == "b" {
			proxyType = sshconfig.ProxyTypeSocks5NCAT
		}
		cfg.ProxyCommand = sshconfig.BuildProxyCommand(proxyType,
			strings.TrimSpace(proxyHost), proxyPort)

	case "3":
		jumpHost, _ := ctx.liner.Prompt(i18n.T("shell.jump_host_user_host_or_just"))
		cfg.ProxyJump = strings.TrimSpace(jumpHost)

	case "4":
		proxyCmd, _ := ctx.liner.Prompt("ProxyCommand: ")
		cfg.ProxyCommand = strings.TrimSpace(proxyCmd)
	}

	// 7. Confirm and save
	fmt.Println(i18n.T("shell.summary"))
	fmt.Printf("Host: %s\n", cfg.Name)
	fmt.Printf("Hostname: %s\n", cfg.Hostname)
	if cfg.User != "" {
		fmt.Printf("User: %s\n", cfg.User)
	}
	if cfg.Port != "" {
		fmt.Printf("Port: %s\n", cfg.Port)
	}
	if cfg.IdentityAgent != "" {
		fmt.Printf("IdentityAgent: %s\n", cfg.IdentityAgent)
	}
	for _, idFile := range cfg.IdentityFile {
		fmt.Printf("IdentityFile: %s\n", idFile)
	}
	if cfg.ProxyJump != "" {
		fmt.Printf("ProxyJump: %s\n", cfg.ProxyJump)
	}
	if cfg.ProxyCommand != "" {
		fmt.Printf("ProxyCommand: %s\n", cfg.ProxyCommand)
	}

	confirm, _ := ctx.liner.Prompt(i18n.T("shell.save_this_configuration_y_n"))
	confirm = cleanLinerInput(confirm)
	if strings.ToLower(confirm) == "n" {
		fmt.Println(i18n.T("shell.cancelled"))
		return nil
	}

	// Write to SSH config
	if err := sshconfig.WriteHostConfig(cfg, false); err != nil {
		return fmt.Errorf(i18n.T("shell.failed_to_save_w"), err)
	}

	// Reload context
	if err := reloadHosts(ctx); err != nil {
		fmt.Printf(i18n.T("shell.warning_failed_to_reload_hosts_v"), err)
	}

	fmt.Printf(i18n.T("shell.host_s_added_to_ssh_config"), cfg.Name)
	fmt.Print(i18n.T("shell.backup_created"))
	fmt.Printf(i18n.T("shell.you_can_now_connect_with_ssh"), cfg.Name)

	return nil
}

// cmdEdit edits an existing SSH host configuration
func cmdEdit(ctx *ShellContext, args string) error {
	hostName := strings.TrimSpace(args)
	if hostName == "" {
		fmt.Println(i18n.T("shell.usage_edit_host"))
		return nil
	}

	// Load existing configuration
	cfg, err := loadEditableHost(ctx, hostName)
	if err != nil {
		return err
	}

	fmt.Printf(i18n.T("shell.edit_host_s"), cfg.Name)
	fmt.Println(i18n.T("shell.press_enter_to_keep_current_value"))

	// Edit Hostname
	currentHostname := cfg.Hostname
	if currentHostname == "" {
		currentHostname = "(none)"
	}
	line, _ := ctx.liner.Prompt(fmt.Sprintf("Hostname [%s]: ", currentHostname))
	if line = strings.TrimSpace(line); line != "" {
		cfg.Hostname = line
	}

	// Edit User
	currentUser := cfg.User
	if currentUser == "" {
		currentUser = "(none)"
	}
	line, _ = ctx.liner.Prompt(fmt.Sprintf("User [%s]: ", currentUser))
	if line = strings.TrimSpace(line); line != "" {
		if line == "-" {
			cfg.User = "" // Clear field
		} else {
			cfg.User = line
		}
	}

	// Edit Port
	currentPort := cfg.Port
	if currentPort == "" {
		currentPort = "22"
	}
	line, _ = ctx.liner.Prompt(fmt.Sprintf("Port [%s]: ", currentPort))
	if line = strings.TrimSpace(line); line != "" {
		if line == "22" {
			cfg.Port = "" // Default port, no need to specify
		} else {
			cfg.Port = line
		}
	}

	// Edit Identity Configuration
	line, _ = ctx.liner.Prompt(i18n.T("shell.change_identity_configuration_y_n"))
	if strings.ToLower(strings.TrimSpace(line)) == "y" {
		fmt.Println(i18n.T("shell.1_use_fssh_agent"))
		fmt.Println(i18n.T("shell.2_direct_identityfile"))
		fmt.Println(i18n.T("shell.3_none"))
		choice, _ := ctx.liner.Prompt(i18n.T("shell.choice"))

		switch strings.TrimSpace(choice) {
		case "1":
			applyAgentIdentity(cfg, chooseKey(ctx))
		case "2":
			idFile, _ := ctx.liner.Prompt(i18n.T("shell.identityfile_path"))
			cfg.IdentityFile = []string{strings.TrimSpace(idFile)}
			cfg.IdentityAgent = ""
			cfg.IdentitiesOnly = ""
		case "3":
			cfg.IdentityAgent = ""
			cfg.IdentityFile = nil
			cfg.IdentitiesOnly = ""
		}
	}

	// Edit Proxy Configuration
	line, _ = ctx.liner.Prompt(i18n.T("shell.change_proxy_configuration_y_n"))
	if strings.ToLower(strings.TrimSpace(line)) == "y" {
		fmt.Println(i18n.T("shell.1_no_proxy"))
		fmt.Println(i18n.T("shell.2_socks5_proxy"))
		fmt.Println(i18n.T("shell.3_ssh_jump_host"))
		fmt.Println(i18n.T("shell.4_custom_proxycommand"))
		proxyChoice, _ := ctx.liner.Prompt(i18n.T("shell.choice"))

		switch strings.TrimSpace(proxyChoice) {
		case "1":
			cfg.ProxyCommand = ""
			cfg.ProxyJump = ""

		case "2":
			proxyHost, _ := ctx.liner.Prompt(i18n.T("shell.socks5_proxy_host"))
			proxyPort, _ := ctx.liner.Prompt(i18n.T("shell.socks5_proxy_port_1080"))
			if proxyPort == "" {
				proxyPort = "1080"
			}
			fmt.Println("  a) nc (netcat)")
			fmt.Println("  b) ncat (nmap ncat)")
			tool, _ := ctx.liner.Prompt(i18n.T("shell.tool_a"))

			proxyType := sshconfig.ProxyTypeSocks5NC
			if tool == "b" {
				proxyType = sshconfig.ProxyTypeSocks5NCAT
			}
			cfg.ProxyCommand = sshconfig.BuildProxyCommand(proxyType,
				strings.TrimSpace(proxyHost), proxyPort)
			cfg.ProxyJump = ""

		case "3":
			jumpHost, _ := ctx.liner.Prompt(i18n.T("shell.jump_host_user_host_or_just"))
			cfg.ProxyJump = strings.TrimSpace(jumpHost)
			cfg.ProxyCommand = ""

		case "4":
			proxyCmd, _ := ctx.liner.Prompt("ProxyCommand: ")
			cfg.ProxyCommand = strings.TrimSpace(proxyCmd)
			cfg.ProxyJump = ""
		}
	}

	// Confirm and save
	confirm, _ := ctx.liner.Prompt(i18n.T("shell.save_changes_y_n"))
	confirm = cleanLinerInput(confirm)
	if strings.ToLower(confirm) == "n" {
		fmt.Println(i18n.T("shell.cancelled"))
		return nil
	}

	if err := sshconfig.WriteHostConfig(cfg, true); err != nil {
		return fmt.Errorf(i18n.T("shell.failed_to_save_w"), err)
	}

	if err := reloadHosts(ctx); err != nil {
		fmt.Printf(i18n.T("shell.warning_failed_to_reload_hosts_v"), err)
	}

	fmt.Printf(i18n.T("shell.host_s_updated"), cfg.Name)
	return nil
}

// cmdDelete deletes an SSH host configuration
func cmdDelete(ctx *ShellContext, args string) error {
	hostName := strings.TrimSpace(args)
	if hostName == "" {
		fmt.Println(i18n.T("shell.usage_delete_host"))
		return nil
	}

	// Check if host exists
	cfg, err := loadEditableHost(ctx, hostName)
	if err != nil {
		return err
	}

	// Show details and confirm
	fmt.Printf(i18n.T("shell.delete_host_s"), cfg.Name)
	fmt.Printf("Hostname: %s\n", cfg.Hostname)
	if cfg.User != "" {
		fmt.Printf("User: %s\n", cfg.User)
	}

	line, _ := ctx.liner.Prompt(i18n.T("shell.type_yes_to_confirm_deletion"))
	line = cleanLinerInput(line)
	if line != "yes" {
		fmt.Println(i18n.T("shell.cancelled"))
		return nil
	}

	if err := sshconfig.DeleteHostConfig(hostName); err != nil {
		return fmt.Errorf(i18n.T("shell.failed_to_delete_w"), err)
	}

	if err := reloadHosts(ctx); err != nil {
		fmt.Printf(i18n.T("shell.warning_failed_to_reload_hosts_v"), err)
	}

	fmt.Printf(i18n.T("shell.host_s_deleted_from_ssh_config"), hostName)
	return nil
}

// cmdShow displays detailed host configuration
func cmdShow(ctx *ShellContext, args string) error {
	hostName := strings.TrimSpace(args)
	if hostName == "" {
		fmt.Println(i18n.T("shell.usage_show_host"))
		return nil
	}
	return printHostDetails(ctx, hostName, false)
}

// cmdInfo displays detailed host configuration by ID, alias, hostname, or IP
func cmdInfo(ctx *ShellContext, args string) error {
	query := strings.TrimSpace(args)
	if query == "" {
		fmt.Println(i18n.T("shell.usage_info_id_alias_hostname_ip"))
		return nil
	}
	hostName := resolveHostQuery(ctx, query)
	if hostName == "" {
		return fmt.Errorf(i18n.T("shell.host_not_found_s"), query)
	}
	return printHostDetails(ctx, hostName, true)
}

func printHostDetails(ctx *ShellContext, hostName string, resolve bool) error {
	hi, known := ctx.byName[hostName]
	cfg, err := sshconfig.LoadHostConfig(hostName)
	if err != nil {
		if !known {
			return fmt.Errorf(i18n.T("shell.host_not_found_s"), hostName)
		}
		// defined in an Include'd file: only what LoadHostInfos knows
		cfg = &sshconfig.HostConfig{Name: hi.Name, Hostname: hi.Hostname}
	}

	fmt.Printf("\n=== Host: %s ===\n", cfg.Name)
	if known && len(hi.Aliases) > 0 {
		fmt.Printf("Aliases: %s\n", strings.Join(hi.Aliases, ", "))
	}
	if cfg.Hostname != "" {
		fmt.Printf("Hostname: %s\n", cfg.Hostname)
	} else {
		fmt.Printf(i18n.T("shell.hostname_s_no_hostname_ssh_connects"), cfg.Name)
	}
	if resolve {
		target := cfg.Hostname
		if target == "" {
			target = cfg.Name
		}
		if ip, fake := lookupIP(target, time.Second); ip != "" {
			fmt.Printf("IP: %s\n", ip)
		} else if fake {
			fmt.Println(i18n.T("shell.ip_hidden_proxy_fake_ip_address"))
		}
	}
	if known && hi.Source != "" {
		home, _ := os.UserHomeDir()
		if hi.Source != filepath.Join(home, ".ssh", "config") {
			fmt.Printf(i18n.T("shell.defined_in_s_read_only_in"), tildify(hi.Source))
		}
	}

	if cfg.User != "" {
		fmt.Printf("User: %s\n", cfg.User)
	}
	if cfg.Port != "" {
		fmt.Printf("Port: %s\n", cfg.Port)
	} else {
		fmt.Print(i18n.T("shell.port_22_default"))
	}

	if key := ctx.boundKey[cfg.Name]; key != "" {
		fmt.Printf(i18n.T("shell.fssh_key_s_identitiesonly_s"), key, cfg.IdentitiesOnly)
	}
	if cfg.IdentityAgent != "" {
		fmt.Printf("IdentityAgent: %s\n", cfg.IdentityAgent)
	}
	for _, idFile := range cfg.IdentityFile {
		fmt.Printf("IdentityFile: %s\n", idFile)
	}

	if cfg.ProxyJump != "" {
		fmt.Printf("ProxyJump: %s\n", cfg.ProxyJump)
	}
	if cfg.ProxyCommand != "" {
		fmt.Printf("ProxyCommand: %s\n", cfg.ProxyCommand)
	}

	if cfg.ForwardAgent != "" {
		fmt.Printf("ForwardAgent: %s\n", cfg.ForwardAgent)
	}
	if cfg.ServerAliveInterval != "" {
		fmt.Printf("ServerAliveInterval: %s\n", cfg.ServerAliveInterval)
	}

	fmt.Println()
	return nil
}

// resolveHostQuery resolves a query (id/alias/hostname/ip) to a host alias
func resolveHostQuery(ctx *ShellContext, query string) string {
	// Try ID first
	if name, ok := ctx.idToName[query]; ok {
		return name
	}

	// Try exact alias match
	if _, ok := ctx.byName[query]; ok {
		return query
	}

	// Try hostname match
	if hi, ok := ctx.byHostname[query]; ok {
		return hi.Name
	}

	// Try IP match
	if name, ok := ctx.ipToName[query]; ok {
		return name
	}

	return ""
}

// --- Helper functions ---

// listImportedKeys lists all imported private keys
func listImportedKeys() ([]string, error) {
	dir := store.KeysDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var keys []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".enc") {
			continue
		}
		// Remove .enc suffix to get alias
		alias := strings.TrimSuffix(e.Name(), ".enc")
		keys = append(keys, alias)
	}

	return keys, nil
}

// reloadHosts (re)builds every lookup table from ~/.ssh/config. It does no
// DNS lookups: those made startup slow and showed proxy fake-ip addresses.
func reloadHosts(ctx *ShellContext) error {
	infos, err := sshconfig.LoadHostInfos()
	if err != nil {
		return err
	}

	ctx.infos = infos
	ctx.hosts = nil
	ctx.hostnames = nil
	ctx.ips = nil
	ctx.ids = nil
	ctx.byName = make(map[string]sshconfig.HostInfo)
	ctx.byHostname = make(map[string]sshconfig.HostInfo)
	ctx.ipToName = make(map[string]string)
	ctx.idToName = make(map[string]string)
	ctx.idOf = make(map[string]string)

	for i, hi := range infos {
		id := fmt.Sprintf("%d", i+1)
		ctx.idToName[id] = hi.Name
		ctx.idOf[hi.Name] = id
		ctx.ids = append(ctx.ids, id)
		for _, n := range hi.Names() {
			ctx.hosts = append(ctx.hosts, n)
			ctx.byName[n] = hi
		}
		if hn := displayHostname(hi); hn != "" {
			if _, dup := ctx.byHostname[hn]; !dup {
				ctx.byHostname[hn] = hi
				ctx.hostnames = append(ctx.hostnames, hn)
			}
		}
		// only literal IPs: resolving names is slow and unreliable behind proxies
		if net.ParseIP(hi.Hostname) != nil {
			if _, dup := ctx.ipToName[hi.Hostname]; !dup {
				ctx.ipToName[hi.Hostname] = hi.Name
				ctx.ips = append(ctx.ips, hi.Hostname)
			}
		}
	}

	ctx.boundKey = make(map[string]string)
	if cfgs, err := sshconfig.LoadAllHostConfigs(); err == nil {
		for name, cfg := range cfgs {
			if alias := sshconfig.BoundKey(cfg, store.PubKeysDir()); alias != "" {
				ctx.boundKey[name] = alias
			}
		}
	}
	ctx.importedKeys, _ = listImportedKeys()
	return nil
}

// loadEditableHost loads a host block from ~/.ssh/config, explaining when the
// host lives in an Include'd file that fssh does not edit.
func loadEditableHost(ctx *ShellContext, hostName string) (*sshconfig.HostConfig, error) {
	cfg, err := sshconfig.LoadHostConfig(hostName)
	if err == nil {
		return cfg, nil
	}
	if hi, ok := ctx.byName[hostName]; ok && hi.Source != "" {
		home, _ := os.UserHomeDir()
		if hi.Source != filepath.Join(home, ".ssh", "config") {
			return nil, fmt.Errorf(i18n.T("shell.host_s_is_defined_in_s"), hostName, tildify(hi.Source))
		}
	}
	return nil, fmt.Errorf(i18n.T("shell.host_not_found_w"), err)
}

// chooseKey asks which imported key a host should use. Empty input means no
// binding: the host is offered every key in the agent.
func chooseKey(ctx *ShellContext) string {
	if len(ctx.importedKeys) == 0 {
		fmt.Println(i18n.T("shell.warning_no_keys_imported_yet_run"))
		return ""
	}
	fmt.Println(i18n.T("shell.imported_keys"))
	for i, key := range ctx.importedKeys {
		fmt.Printf("  %d) %s\n", i+1, key)
	}
	for {
		line, _ := ctx.liner.Prompt(i18n.T("shell.key_for_this_host_number_or"))
		choice := strings.TrimSpace(line)
		if choice == "" {
			return ""
		}
		for i, key := range ctx.importedKeys {
			if choice == key || choice == fmt.Sprintf("%d", i+1) {
				return key
			}
		}
		fmt.Println(i18n.T("shell.unknown_key_try_again"))
	}
}

// applyAgentIdentity points cfg at the fssh agent and, when alias is set,
// restricts it to that key (IdentityFile <alias>.pub + IdentitiesOnly).
func applyAgentIdentity(cfg *sshconfig.HostConfig, alias string) {
	cfg.IdentityAgent = tildify(agentSocket())
	cfg.IdentityFile = nil
	cfg.IdentitiesOnly = ""
	if alias == "" {
		return
	}
	_ = store.SyncPubKeys()
	if pub, err := store.PubKeyPath(alias); err == nil {
		cfg.IdentityFile = []string{tildify(pub)}
		cfg.IdentitiesOnly = "yes"
	}
}

// cmdGlobalShow displays the current Host * configuration
func cmdGlobalShow(ctx *ShellContext) error {
	cfg, found, err := sshconfig.LoadGlobalConfig()
	if err != nil {
		return fmt.Errorf(i18n.T("shell.failed_to_load_global_config_w"), err)
	}

	if !found {
		fmt.Println(i18n.T("shell.no_host_block_found_in_ssh"))
		fmt.Println(i18n.T("shell.you_can_create_one_with_global"))
		return nil
	}

	// Display all configured options
	fmt.Println(i18n.T("shell.global_ssh_configuration_host"))
	fmt.Println()

	displayed := false
	if cfg.ServerAliveInterval != "" {
		fmt.Printf("  ServerAliveInterval: %s\n", cfg.ServerAliveInterval)
		displayed = true
	}
	if cfg.ServerAliveCountMax != "" {
		fmt.Printf("  ServerAliveCountMax: %s\n", cfg.ServerAliveCountMax)
		displayed = true
	}
	if cfg.ForwardAgent != "" {
		fmt.Printf("  ForwardAgent: %s\n", cfg.ForwardAgent)
		displayed = true
	}
	if cfg.IdentityAgent != "" {
		fmt.Printf("  IdentityAgent: %s\n", cfg.IdentityAgent)
		displayed = true
	}
	if cfg.AddKeysToAgent != "" {
		fmt.Printf("  AddKeysToAgent: %s\n", cfg.AddKeysToAgent)
		displayed = true
	}
	if cfg.UseKeychain != "" {
		fmt.Printf("  UseKeychain: %s\n", cfg.UseKeychain)
		displayed = true
	}
	if cfg.PubkeyAcceptedAlgorithms != "" {
		fmt.Printf("  PubkeyAcceptedAlgorithms: %s\n", cfg.PubkeyAcceptedAlgorithms)
		displayed = true
	}
	if cfg.StrictHostKeyChecking != "" {
		fmt.Printf("  StrictHostKeyChecking: %s\n", cfg.StrictHostKeyChecking)
		displayed = true
	}
	if cfg.UserKnownHostsFile != "" {
		fmt.Printf("  UserKnownHostsFile: %s\n", cfg.UserKnownHostsFile)
		displayed = true
	}
	if cfg.Compression != "" {
		fmt.Printf("  Compression: %s\n", cfg.Compression)
		displayed = true
	}
	if cfg.TCPKeepAlive != "" {
		fmt.Printf("  TCPKeepAlive: %s\n", cfg.TCPKeepAlive)
		displayed = true
	}

	if !displayed {
		fmt.Println(i18n.T("shell.empty"))
	}

	fmt.Println()
	return nil
}

// cmdGlobalEdit interactively edits global configuration
func cmdGlobalEdit(ctx *ShellContext) error {
	cfg, found, err := sshconfig.LoadGlobalConfig()
	if err != nil {
		return fmt.Errorf(i18n.T("shell.failed_to_load_global_config_w"), err)
	}

	if !found {
		// Prompt user to create
		fmt.Println(i18n.T("shell.host_block_does_not_exist"))
		line, err := ctx.liner.Prompt(i18n.T("shell.create_it_now_y_n"))
		if err != nil {
			return err
		}
		if strings.ToLower(strings.TrimSpace(line)) == "n" {
			fmt.Println(i18n.T("shell.cancelled"))
			return nil
		}
		cfg = sshconfig.NewGlobalConfig()
	}

	fmt.Println(i18n.T("shell.edit_global_configuration_host"))
	fmt.Println(i18n.T("shell.press_enter_to_keep_current_value_2"))
	fmt.Println(i18n.T("shell.type_to_see_detailed_help_for"))
	fmt.Println()

	// Helper function to edit a single field
	editField := func(key, current string) string {
		desc, help, validValues := sshconfig.GetGlobalOptionHelp(key)
		if current == "" {
			current = "(not set)"
		}
		fmt.Printf("\n%s\n", desc)
		if len(validValues) > 0 {
			fmt.Printf(i18n.T("shell.valid_values_s"), strings.Join(validValues, ", "))
		}
		line, _ := ctx.liner.Prompt(fmt.Sprintf("%s [%s]: ", key, current))
		line = strings.TrimSpace(line)
		if line == "?" {
			fmt.Printf("\n%s\n\n", help)
			line, _ = ctx.liner.Prompt(fmt.Sprintf("%s [%s]: ", key, current))
			line = strings.TrimSpace(line)
		}
		if line == "-" {
			return ""
		}
		if line != "" {
			return line
		}
		if current == "(not set)" {
			return ""
		}
		// Return original value (unchanged)
		return current
	}

	// Edit ServerAliveInterval
	result := editField("ServerAliveInterval", cfg.ServerAliveInterval)
	if result != cfg.ServerAliveInterval {
		cfg.ServerAliveInterval = result
	}

	// Edit ServerAliveCountMax
	result = editField("ServerAliveCountMax", cfg.ServerAliveCountMax)
	if result != cfg.ServerAliveCountMax {
		cfg.ServerAliveCountMax = result
	}

	// Edit ForwardAgent
	result = editField("ForwardAgent", cfg.ForwardAgent)
	if result != cfg.ForwardAgent {
		cfg.ForwardAgent = result
	}

	// Edit IdentityAgent
	result = editField("IdentityAgent", cfg.IdentityAgent)
	if result != cfg.IdentityAgent {
		cfg.IdentityAgent = result
	}

	// Edit AddKeysToAgent
	result = editField("AddKeysToAgent", cfg.AddKeysToAgent)
	if result != cfg.AddKeysToAgent {
		cfg.AddKeysToAgent = result
	}

	// Edit UseKeychain
	result = editField("UseKeychain", cfg.UseKeychain)
	if result != cfg.UseKeychain {
		cfg.UseKeychain = result
	}

	// Edit PubkeyAcceptedAlgorithms
	result = editField("PubkeyAcceptedAlgorithms", cfg.PubkeyAcceptedAlgorithms)
	if result != cfg.PubkeyAcceptedAlgorithms {
		cfg.PubkeyAcceptedAlgorithms = result
	}

	// Edit StrictHostKeyChecking
	result = editField("StrictHostKeyChecking", cfg.StrictHostKeyChecking)
	if result != cfg.StrictHostKeyChecking {
		cfg.StrictHostKeyChecking = result
	}

	// Edit UserKnownHostsFile
	result = editField("UserKnownHostsFile", cfg.UserKnownHostsFile)
	if result != cfg.UserKnownHostsFile {
		cfg.UserKnownHostsFile = result
	}

	// Edit Compression
	result = editField("Compression", cfg.Compression)
	if result != cfg.Compression {
		cfg.Compression = result
	}

	// Edit TCPKeepAlive
	result = editField("TCPKeepAlive", cfg.TCPKeepAlive)
	if result != cfg.TCPKeepAlive {
		cfg.TCPKeepAlive = result
	}

	// Confirm and save
	fmt.Println()
	confirm, _ := ctx.liner.Prompt(i18n.T("shell.save_global_configuration_y_n"))
	confirm = cleanLinerInput(confirm)
	if strings.ToLower(confirm) == "n" {
		fmt.Println(i18n.T("shell.cancelled"))
		return nil
	}

	if err := sshconfig.WriteGlobalConfig(cfg); err != nil {
		return fmt.Errorf(i18n.T("shell.failed_to_save_w"), err)
	}

	fmt.Println(i18n.T("shell.global_configuration_updated"))
	fmt.Println(i18n.T("shell.backup_created_2"))
	return nil
}

// cmdGlobalSet quickly sets a single option
func cmdGlobalSet(ctx *ShellContext, args string) error {
	// Parse "key value"
	parts := strings.SplitN(strings.TrimSpace(args), " ", 2)
	if len(parts) < 2 {
		fmt.Println(i18n.T("shell.usage_global_set_key_value"))
		fmt.Println(i18n.T("shell.supported_options"))

		// Display all options with descriptions
		for _, key := range sshconfig.GetGlobalOptionNames() {
			desc, _, validValues := sshconfig.GetGlobalOptionHelp(key)
			fmt.Printf("  %-30s - %s", key, desc)
			if len(validValues) > 0 {
				fmt.Printf(" (%s)", strings.Join(validValues, "/"))
			}
			fmt.Println()
		}

		fmt.Println(i18n.T("shell.example"))
		fmt.Println("  global set ServerAliveInterval 60")
		fmt.Println(i18n.T("shell.tip_use_global_edit_for_interactive"))
		return nil
	}

	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	if err := sshconfig.SetGlobalOption(key, value); err != nil {
		return fmt.Errorf(i18n.T("shell.failed_to_set_option_w"), err)
	}

	fmt.Printf(i18n.T("shell.set_s_s"), key, value)
	fmt.Println(i18n.T("shell.backup_created_2"))
	return nil
}

// cmdGlobalUnset removes a single option
func cmdGlobalUnset(ctx *ShellContext, args string) error {
	key := strings.TrimSpace(args)
	if key == "" {
		fmt.Println(i18n.T("shell.usage_global_unset_key"))
		fmt.Println(i18n.T("shell.supported_options"))

		// Display all options with descriptions
		for _, key := range sshconfig.GetGlobalOptionNames() {
			desc, _, _ := sshconfig.GetGlobalOptionHelp(key)
			fmt.Printf("  %-30s - %s\n", key, desc)
		}

		fmt.Println(i18n.T("shell.example"))
		fmt.Println("  global unset UseKeychain")
		return nil
	}

	if err := sshconfig.UnsetGlobalOption(key); err != nil {
		return fmt.Errorf(i18n.T("shell.failed_to_unset_option_w"), err)
	}

	fmt.Printf(i18n.T("shell.unset_s"), key)
	fmt.Println(i18n.T("shell.backup_created_2"))
	return nil
}

// cmdGlobal routes global subcommands
func cmdGlobal(ctx *ShellContext, args string) error {
	args = strings.TrimSpace(args)

	if args == "" || args == "show" {
		return cmdGlobalShow(ctx)
	}
	if args == "edit" {
		return cmdGlobalEdit(ctx)
	}
	if args == "set" || strings.HasPrefix(args, "set ") {
		if args == "set" {
			return cmdGlobalSet(ctx, "")
		}
		return cmdGlobalSet(ctx, args[4:])
	}
	if args == "unset" || strings.HasPrefix(args, "unset ") {
		if args == "unset" {
			return cmdGlobalUnset(ctx, "")
		}
		return cmdGlobalUnset(ctx, args[6:])
	}

	// Unknown subcommand
	fmt.Println(i18n.T("shell.unknown_global_subcommand_usage"))
	fmt.Println(i18n.T("shell.global_show_display_current_global_config_2"))
	fmt.Println(i18n.T("shell.global_edit_edit_global_config_interactively_2"))
	fmt.Println(i18n.T("shell.global_set_key_value_set_a_2"))
	fmt.Println(i18n.T("shell.global_unset_key_remove_a_single_2"))
	return nil
}
