package sshconfig

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// HostConfig represents a complete SSH host configuration
type HostConfig struct {
	// Basic identity
	Name     string // Host alias
	Hostname string // Target hostname/IP

	// Authentication
	User          string   // SSH username
	Port          string   // SSH port (default 22)
	IdentityFile  []string // Direct identity files
	IdentityAgent string   // SSH agent socket path
	// IdentitiesOnly "yes" restricts ssh to the IdentityFile keys, so a host
	// bound to one fssh key is not offered every key in the agent.
	IdentitiesOnly string

	// Proxy configuration (mutually exclusive)
	ProxyCommand string // Full proxy command
	ProxyJump    string // SSH jump host

	// Additional fields
	ForwardAgent        string // yes/no
	ServerAliveInterval string // keep-alive interval

	// Global configuration fields
	ServerAliveCountMax      string // keep-alive max count
	AddKeysToAgent           string // yes/no/ask/confirm
	UseKeychain              string // yes/no (macOS only)
	PubkeyAcceptedAlgorithms string // algorithm list
	StrictHostKeyChecking    string // yes/no/ask/accept-new
	UserKnownHostsFile       string // known hosts file path
	Compression              string // yes/no
	TCPKeepAlive             string // yes/no

	// Internal metadata
	Comment    string // Inline comment from config
	LineNumber int    // Original line number (for debugging)
	IsGlobal   bool   // true for "Host *" blocks
}

// ProxyType represents the type of proxy configuration
type ProxyType int

const (
	ProxyTypeNone ProxyType = iota
	ProxyTypeSocks5NC
	ProxyTypeSocks5NCAT
	ProxyTypeHTTP
	ProxyTypeJump
	ProxyTypeCustom
)

// ProxyConfig represents proxy settings
type ProxyConfig struct {
	Type     ProxyType
	Host     string
	Port     string
	Username string // For jump hosts
}

// ValidateHostConfig validates a host configuration
func ValidateHostConfig(cfg *HostConfig) error {
	var errs []string

	// Validate required fields
	if cfg.Name == "" {
		errs = append(errs, "host name is required")
	}
	if strings.ContainsAny(cfg.Name, " \t\n") {
		errs = append(errs, "host name cannot contain whitespace")
	}

	// Special handling for Host *
	if cfg.Name == "*" || cfg.IsGlobal {
		cfg.IsGlobal = true
		// For global configs, Hostname is optional
	} else {
		// For regular hosts, Hostname is required
		if cfg.Hostname == "" {
			errs = append(errs, "hostname is required")
		}
	}

	// Validate port
	if cfg.Port != "" {
		port, err := strconv.Atoi(cfg.Port)
		if err != nil || port < 1 || port > 65535 {
			errs = append(errs, "port must be between 1 and 65535")
		}
	}

	// Validate proxy configuration (mutually exclusive)
	if cfg.ProxyCommand != "" && cfg.ProxyJump != "" {
		errs = append(errs, "cannot specify both ProxyCommand and ProxyJump")
	}

	// Validate ForwardAgent
	if cfg.ForwardAgent != "" {
		fa := strings.ToLower(cfg.ForwardAgent)
		if fa != "yes" && fa != "no" {
			errs = append(errs, "ForwardAgent must be 'yes' or 'no'")
		}
	}

	// Validate ServerAliveCountMax
	if cfg.ServerAliveCountMax != "" {
		count, err := strconv.Atoi(cfg.ServerAliveCountMax)
		if err != nil || count < 0 {
			errs = append(errs, "ServerAliveCountMax must be a non-negative integer")
		}
	}

	// Validate AddKeysToAgent
	if cfg.AddKeysToAgent != "" {
		val := strings.ToLower(cfg.AddKeysToAgent)
		if val != "yes" && val != "no" && val != "ask" && val != "confirm" {
			errs = append(errs, "AddKeysToAgent must be 'yes', 'no', 'ask', or 'confirm'")
		}
	}

	// Validate UseKeychain
	if cfg.UseKeychain != "" {
		val := strings.ToLower(cfg.UseKeychain)
		if val != "yes" && val != "no" {
			errs = append(errs, "UseKeychain must be 'yes' or 'no'")
		}
	}

	// Validate StrictHostKeyChecking
	if cfg.StrictHostKeyChecking != "" {
		val := strings.ToLower(cfg.StrictHostKeyChecking)
		if val != "yes" && val != "no" && val != "ask" && val != "accept-new" {
			errs = append(errs, "StrictHostKeyChecking must be 'yes', 'no', 'ask', or 'accept-new'")
		}
	}

	// Validate Compression
	if cfg.Compression != "" {
		val := strings.ToLower(cfg.Compression)
		if val != "yes" && val != "no" {
			errs = append(errs, "Compression must be 'yes' or 'no'")
		}
	}

	// Validate TCPKeepAlive
	if cfg.TCPKeepAlive != "" {
		val := strings.ToLower(cfg.TCPKeepAlive)
		if val != "yes" && val != "no" {
			errs = append(errs, "TCPKeepAlive must be 'yes' or 'no'")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// BuildProxyCommand constructs a ProxyCommand string for SOCKS5 proxies
func BuildProxyCommand(proxyType ProxyType, host, port string) string {
	switch proxyType {
	case ProxyTypeSocks5NC:
		return fmt.Sprintf("nc -X 5 -x %s:%s %%h %%p", host, port)
	case ProxyTypeSocks5NCAT:
		return fmt.Sprintf("ncat --proxy-type socks5 --proxy %s:%s %%h %%p", host, port)
	case ProxyTypeHTTP:
		return fmt.Sprintf("nc -X connect -x %s:%s %%h %%p", host, port)
	default:
		return ""
	}
}

// BuildProxyJump constructs a ProxyJump string
func BuildProxyJump(user, host string) string {
	if user != "" {
		return fmt.Sprintf("%s@%s", user, host)
	}
	return host
}

// ParseProxyCommand attempts to parse an existing ProxyCommand
func ParseProxyCommand(cmd string) (*ProxyConfig, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil, errors.New("empty proxy command")
	}

	cfg := &ProxyConfig{Type: ProxyTypeCustom}

	// Try to detect SOCKS5 with nc
	if strings.Contains(cmd, "nc -X 5 -x") {
		cfg.Type = ProxyTypeSocks5NC
		// Extract host:port pattern
		parts := strings.Fields(cmd)
		for i, part := range parts {
			if part == "-x" && i+1 < len(parts) {
				hostPort := parts[i+1]
				if idx := strings.Index(hostPort, ":"); idx > 0 {
					cfg.Host = hostPort[:idx]
					cfg.Port = hostPort[idx+1:]
				}
				break
			}
		}
	} else if strings.Contains(cmd, "ncat --proxy-type socks5") {
		cfg.Type = ProxyTypeSocks5NCAT
		// Extract from --proxy
		parts := strings.Fields(cmd)
		for i, part := range parts {
			if part == "--proxy" && i+1 < len(parts) {
				hostPort := parts[i+1]
				if idx := strings.Index(hostPort, ":"); idx > 0 {
					cfg.Host = hostPort[:idx]
					cfg.Port = hostPort[idx+1:]
				}
				break
			}
		}
	}

	return cfg, nil
}

// ParseProxyJump parses an existing ProxyJump configuration
func ParseProxyJump(jump string) (*ProxyConfig, error) {
	jump = strings.TrimSpace(jump)
	if jump == "" {
		return nil, errors.New("empty proxy jump")
	}

	cfg := &ProxyConfig{Type: ProxyTypeJump}

	// Format: [user@]host[:port]
	// Handle user@host
	if idx := strings.Index(jump, "@"); idx > 0 {
		cfg.Username = jump[:idx]
		jump = jump[idx+1:]
	}

	// Handle host:port
	if idx := strings.Index(jump, ":"); idx > 0 {
		cfg.Host = jump[:idx]
		cfg.Port = jump[idx+1:]
	} else {
		cfg.Host = jump
	}

	return cfg, nil
}

// ProxyTemplates provides common proxy command templates
var ProxyTemplates = map[string]string{
	"socks5-nc":   "nc -X 5 -x %s:%s %%h %%p",
	"socks5-ncat": "ncat --proxy-type socks5 --proxy %s:%s %%h %%p",
	"http-nc":     "nc -X connect -x %s:%s %%h %%p",
}

// GlobalConfigOption defines metadata for a single global configuration option
type GlobalConfigOption struct {
	Description  string   // Short description of the option
	DetailedHelp string   // Detailed help (use cases, notes, etc.)
	ValidValues  []string // Valid values list, nil means any value
}

// GlobalConfigOptions defines supported global configuration options
var GlobalConfigOptions = map[string]GlobalConfigOption{
	"ServerAliveInterval": {
		Description:  "服务器保活间隔（秒）",
		DetailedHelp: "SSH 客户端向服务器发送保活消息的间隔。防止因网络空闲导致连接断开。推荐值：30-60秒。设为 0 禁用。",
		ValidValues:  nil, // any non-negative integer
	},
	"ServerAliveCountMax": {
		Description:  "最大保活失败次数",
		DetailedHelp: "服务器无响应时，允许的最大保活消息数。达到此数量后断开连接。推荐值：3-6。",
		ValidValues:  nil, // any non-negative integer
	},
	"ForwardAgent": {
		Description:  "是否转发 SSH 代理",
		DetailedHelp: "启用后，本地 SSH 代理可在远程服务器上使用。方便多跳 SSH，但有安全风险。慎用。",
		ValidValues:  []string{"yes", "no"},
	},
	"IdentityAgent": {
		Description:  "SSH 代理套接字路径",
		DetailedHelp: "指定 SSH 代理的 UNIX 套接字路径。用于私钥认证。fssh 使用 ~/.fssh/agent.sock。",
		ValidValues:  nil, // file path
	},
	"AddKeysToAgent": {
		Description:  "自动添加密钥到代理",
		DetailedHelp: "首次使用私钥时，是否自动添加到 SSH 代理。yes=自动添加，ask=询问，confirm=确认后添加，no=不添加。",
		ValidValues:  []string{"yes", "no", "ask", "confirm"},
	},
	"UseKeychain": {
		Description:  "使用 macOS 钥匙串（仅 macOS）",
		DetailedHelp: "启用后，SSH 密钥密码将存储在 macOS 钥匙串中，无需重复输入。仅限 macOS 系统。",
		ValidValues:  []string{"yes", "no"},
	},
	"PubkeyAcceptedAlgorithms": {
		Description:  "允许的公钥签名算法",
		DetailedHelp: "指定客户端接受的公钥签名算法列表（逗号分隔）。用于兼容旧服务器。例如：+rsa-sha2-512,rsa-sha2-256",
		ValidValues:  nil, // comma-separated list
	},
	"StrictHostKeyChecking": {
		Description:  "严格主机密钥检查",
		DetailedHelp: "yes=严格检查（最安全），no=不检查（不安全），ask=询问，accept-new=自动接受新主机密钥。",
		ValidValues:  []string{"yes", "no", "ask", "accept-new"},
	},
	"UserKnownHostsFile": {
		Description:  "已知主机文件路径",
		DetailedHelp: "指定存储已知主机密钥的文件路径。默认为 ~/.ssh/known_hosts。可设置 /dev/null 跳过检查（不推荐）。",
		ValidValues:  nil, // file path
	},
	"Compression": {
		Description:  "是否启用压缩",
		DetailedHelp: "启用后，SSH 连接将压缩数据传输。在慢速网络上有帮助，但会增加 CPU 负担。",
		ValidValues:  []string{"yes", "no"},
	},
	"TCPKeepAlive": {
		Description:  "TCP 层保活",
		DetailedHelp: "启用 TCP 层的 keep-alive 机制。防止防火墙关闭空闲连接。与 ServerAliveInterval 不同，在 TCP 层工作。",
		ValidValues:  []string{"yes", "no"},
	},
}

// IsValidGlobalOption checks if a key is a supported global option
func IsValidGlobalOption(key string) bool {
	_, ok := GlobalConfigOptions[key]
	return ok
}

// GetGlobalOptionNames returns all supported global option names sorted alphabetically
func GetGlobalOptionNames() []string {
	names := make([]string, 0, len(GlobalConfigOptions))
	for name := range GlobalConfigOptions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// GetGlobalOptionHelp retrieves help information for a global option
func GetGlobalOptionHelp(key string) (description, detailedHelp string, validValues []string) {
	opt, ok := GlobalConfigOptions[key]
	if !ok {
		return "", "", nil
	}
	return opt.Description, opt.DetailedHelp, opt.ValidValues
}

// NewGlobalConfig creates a new HostConfig for global configuration (Host *)
func NewGlobalConfig() *HostConfig {
	return &HostConfig{
		Name:     "*",
		IsGlobal: true,
	}
}
