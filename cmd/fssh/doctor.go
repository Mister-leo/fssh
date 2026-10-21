package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fssh/internal/auth"
	"fssh/internal/config"
	"fssh/internal/i18n"
	"fssh/internal/otp"
	"fssh/internal/sshconfig"
	"fssh/internal/store"

	"golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

// probeAgent connects to the agent socket and counts listed keys.
func probeAgent(sock string) (int, error) {
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	keys, err := xagent.NewClient(conn).List()
	return len(keys), err
}

func launchAgentPlist() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", plistLabel+".plist")
}

func launchAgentLoaded() bool {
	return exec.Command("launchctl", "print", fmt.Sprintf("gui/%d/%s", os.Getuid(), plistLabel)).Run() == nil
}

func yesNo(b bool) string {
	if b {
		return i18n.T("status.yes")
	}
	return i18n.T("status.no")
}

func cmdStatus() {
	cfg, err := config.Load()
	if err != nil {
		fatal(err)
	}
	initialized, mode, err := auth.IsInitialized()
	if err != nil {
		fatal(err)
	}
	metas, err := store.ListMeta()
	if err != nil {
		fatal(err)
	}

	var rows [][]string
	row := func(k, v string) { rows = append(rows, []string{i18n.T(k), v}) }

	row("status.mode", string(mode))
	row("status.initialized", yesNo(initialized))
	row("status.keys", fmt.Sprintf("%d", len(metas)))
	if n, err := probeAgent(cfg.Socket); err == nil {
		row("status.agent", i18n.T("status.agent_running", n, tildify(cfg.Socket)))
	} else {
		row("status.agent", i18n.T("status.agent_down", tildify(cfg.Socket)))
	}
	_, plistErr := os.Stat(launchAgentPlist())
	row("status.launchagent", yesNo(plistErr == nil && launchAgentLoaded()))
	global, partial, _ := sshconfig.AgentCoverage(cfg.Socket)
	switch {
	case global:
		row("status.sshconfig", i18n.T("status.ssh_all"))
	case partial:
		row("status.sshconfig", i18n.T("status.ssh_partial"))
	default:
		row("status.sshconfig", i18n.T("status.no"))
	}
	switch env := os.Getenv("SSH_AUTH_SOCK"); {
	case env == "":
		row("status.authsock", i18n.T("status.authsock_unset"))
	case env == cfg.Socket:
		row("status.authsock", i18n.T("status.authsock_fssh"))
	default:
		row("status.authsock", env)
	}
	if cfg.RequireTouchPerSign {
		row("status.ttl", i18n.T("status.ttl_value", cfg.UnlockTTLSeconds))
	} else {
		row("status.ttl", i18n.T("status.convenience"))
	}
	row("status.forwarded", cfg.ForwardedSign)
	if mode == auth.ModeOTP && initialized {
		if oc, err := otp.LoadConfig(otp.ConfigPath()); err == nil {
			if oc.LegacyRecovery() {
				row("status.recovery", i18n.T("status.recovery_legacy"))
			} else {
				row("status.recovery", fmt.Sprintf("%d", len(oc.RecoveryWrapped)))
			}
		}
	}
	printTable(os.Stdout, rows)
}

// ---- doctor ----

type checkLevel int

const (
	checkOK checkLevel = iota
	checkWarn
	checkFail
)

type check struct {
	level checkLevel
	msg   string
	fix   string
}

func cmdDoctor() {
	checks := runChecks()
	fails, warns := 0, 0
	for _, c := range checks {
		mark := "✓"
		switch c.level {
		case checkWarn:
			mark, warns = "⚠", warns+1
		case checkFail:
			mark, fails = "✗", fails+1
		}
		fmt.Printf("%s %s\n", mark, c.msg)
		if c.fix != "" && c.level != checkOK {
			for _, line := range strings.Split(c.fix, "\n") {
				fmt.Printf("    → %s\n", line)
			}
		}
	}
	fmt.Println()
	if fails == 0 && warns == 0 {
		fmt.Println(i18n.T("doctor.all_ok"))
		return
	}
	fmt.Println(i18n.T("doctor.summary", fails, warns))
	if fails > 0 {
		os.Exit(1)
	}
}

func runChecks() []check {
	var out []check
	add := func(level checkLevel, msg, fix string) { out = append(out, check{level, msg, fix}) }

	cfg, err := config.Load()
	if err != nil {
		add(checkFail, i18n.T("doctor.config_invalid", err), i18n.T("doctor.fix_config"))
		cfg = config.Default()
	}

	// 1. initialization
	initialized, mode, err := auth.IsInitialized()
	switch {
	case err != nil:
		add(checkFail, i18n.T("doctor.init_error", err), "fssh init")
	case !initialized:
		add(checkFail, i18n.T("doctor.not_initialized"), "fssh init")
	default:
		add(checkOK, i18n.T("doctor.initialized", mode), "")
	}

	metas, _ := store.ListMeta()
	if initialized && len(metas) == 0 {
		add(checkWarn, i18n.T("doctor.no_keys"), "fssh import --alias <name> --file ~/.ssh/id_ed25519\nfssh keygen <name>")
	}
	_ = store.SyncPubKeys() // keys imported by older versions get their .pub files

	// 2. agent
	_, plistErr := os.Stat(launchAgentPlist())
	if n, err := probeAgent(cfg.Socket); err == nil {
		add(checkOK, i18n.T("doctor.agent_ok", n), "")
	} else {
		fix := "fssh agent"
		if plistErr == nil {
			fix = fmt.Sprintf("launchctl kickstart -k gui/%d/%s", os.Getuid(), plistLabel)
		}
		add(checkFail, i18n.T("doctor.agent_down", tildify(cfg.Socket)), fix)
	}

	// 3. auto-start
	if plistErr != nil {
		add(checkWarn, i18n.T("doctor.no_launchagent"), i18n.T("doctor.fix_launchagent"))
	} else if b, err := os.ReadFile(launchAgentPlist()); err == nil {
		bin := plistProgram(string(b))
		if bin != "" {
			if _, err := os.Stat(bin); err != nil {
				add(checkFail, i18n.T("doctor.launchagent_binary_missing", bin), "sudo cp $(which fssh) "+bin)
			}
		}
		if strings.Contains(string(b), "/tmp/fssh-agent.log") {
			add(checkWarn, i18n.T("doctor.log_in_tmp"), i18n.T("doctor.fix_launchagent"))
		}
	}

	// 4. ssh integration
	global, partial, _ := sshconfig.AgentCoverage(cfg.Socket)
	switch {
	case global:
		add(checkOK, i18n.T("doctor.ssh_ok"), "")
	case partial:
		add(checkWarn, i18n.T("doctor.ssh_partial"), i18n.T("doctor.fix_ssh", tildify(cfg.Socket)))
	case os.Getenv("SSH_AUTH_SOCK") == cfg.Socket:
		add(checkWarn, i18n.T("doctor.ssh_env_only"), i18n.T("doctor.fix_ssh", tildify(cfg.Socket)))
	default:
		add(checkFail, i18n.T("doctor.ssh_missing"), i18n.T("doctor.fix_ssh", tildify(cfg.Socket)))
	}

	// 5. plaintext private keys left in ~/.ssh
	imported := map[string]string{}
	for _, m := range metas {
		imported[m.Fingerprint] = m.Alias
	}
	for _, pk := range scanPlaintextKeys() {
		switch alias, ok := imported[pk.fingerprint]; {
		case ok:
			add(checkWarn, i18n.T("doctor.plaintext_imported", tildify(pk.path), alias),
				fmt.Sprintf("mkdir -p %s && mv %s %s/", tildify(archiveDir()), tildify(pk.path), tildify(archiveDir())))
		case pk.encrypted:
			add(checkWarn, i18n.T("doctor.plaintext_encrypted", tildify(pk.path)),
				fmt.Sprintf("fssh import --alias <name> --file %s", tildify(pk.path)))
		default:
			add(checkWarn, i18n.T("doctor.plaintext_unprotected", tildify(pk.path)),
				fmt.Sprintf("fssh import --alias <name> --file %s", tildify(pk.path)))
		}
	}

	// 6. several keys but no host binding: every key is offered everywhere
	if len(metas) >= 2 && len(boundHosts()) == 0 {
		add(checkWarn, i18n.T("doctor.unbound", len(metas)), "fssh bind <host> <alias>")
	}

	// 7. OTP recovery codes
	if mode == auth.ModeOTP && initialized {
		if oc, err := otp.LoadConfig(otp.ConfigPath()); err == nil {
			switch {
			case oc.LegacyRecovery():
				add(checkWarn, i18n.T("otp.legacy_recovery"), "fssh otp regen-recovery")
			case len(oc.RecoveryWrapped) <= 3:
				add(checkWarn, i18n.T("doctor.recovery_low", len(oc.RecoveryWrapped)), "fssh otp regen-recovery")
			}
		}
	}
	return out
}

// plistProgram extracts the first ProgramArguments entry from the plist.
func plistProgram(plist string) string {
	i := strings.Index(plist, "<key>ProgramArguments</key>")
	if i < 0 {
		return ""
	}
	rest := plist[i:]
	a := strings.Index(rest, "<string>")
	b := strings.Index(rest, "</string>")
	if a < 0 || b < a {
		return ""
	}
	return strings.TrimSpace(rest[a+len("<string>") : b])
}

type plaintextKey struct {
	path        string
	fingerprint string // from the key itself, or the adjacent .pub file
	encrypted   bool
}

// scanPlaintextKeys finds private key files directly in ~/.ssh (not in the
// fssh archive), the ones ssh would pick up by default or via IdentityFile.
func scanPlaintextKeys() []plaintextKey {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dir := filepath.Join(home, ".ssh")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []plaintextKey
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasSuffix(name, ".pub") || name == "config" || strings.HasPrefix(name, "known_hosts") || name == "authorized_keys" {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := e.Info()
		if err != nil || info.Size() > 64*1024 {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(b), "PRIVATE KEY") {
			continue
		}
		k := plaintextKey{path: path}
		raw, err := ssh.ParseRawPrivateKey(b)
		var missing *ssh.PassphraseMissingError
		switch {
		case err == nil:
			if signer, err := ssh.NewSignerFromKey(raw); err == nil {
				k.fingerprint = ssh.FingerprintSHA256(signer.PublicKey())
			}
		case errors.As(err, &missing):
			k.encrypted = true
			if missing.PublicKey != nil {
				k.fingerprint = ssh.FingerprintSHA256(missing.PublicKey)
			}
		default:
			continue
		}
		if k.fingerprint == "" {
			if pb, err := os.ReadFile(path + ".pub"); err == nil {
				if pk, _, _, _, err := ssh.ParseAuthorizedKey(pb); err == nil {
					k.fingerprint = ssh.FingerprintSHA256(pk)
				}
			}
		}
		out = append(out, k)
	}
	return out
}
