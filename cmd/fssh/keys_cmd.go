package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"fssh/internal/config"
	"fssh/internal/i18n"
	"fssh/internal/prompt"
	"fssh/internal/sshconfig"
	"fssh/internal/store"

	"golang.org/x/term"
)

// parseInterleaved parses flags that may appear before or after positional
// arguments ("fssh pubkey work --copy") and returns the positionals.
func parseInterleaved(fs *flag.FlagSet, args []string) []string {
	var positional []string
	for {
		fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			return positional
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

// tildify shortens paths under $HOME to "~/..." for readable ssh_config entries.
func tildify(p string) string {
	home, err := os.UserHomeDir()
	if err == nil && strings.HasPrefix(p, home+string(filepath.Separator)) {
		return "~" + p[len(home):]
	}
	return p
}

func isTTY() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// boundHosts maps key alias -> hosts bound to it in ~/.ssh/config.
func boundHosts() map[string][]string {
	out := map[string][]string{}
	cfgs, err := sshconfig.LoadAllHostConfigs()
	if err != nil {
		return out
	}
	for name, cfg := range cfgs {
		if alias := sshconfig.BoundKey(cfg, store.PubKeysDir()); alias != "" {
			out[alias] = append(out[alias], name)
		}
	}
	for _, hosts := range out {
		sort.Strings(hosts)
	}
	return out
}

func cmdList() {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	fs.Parse(os.Args[2:])

	metas, err := store.ListMeta()
	if err != nil {
		fatal(err)
	}
	bound := boundHosts()

	if *jsonOut {
		type item struct {
			Alias       string   `json:"alias"`
			Type        string   `json:"type"`
			Fingerprint string   `json:"fingerprint"`
			CreatedAt   string   `json:"created_at"`
			Comment     string   `json:"comment,omitempty"`
			PublicKey   string   `json:"public_key"`
			Hosts       []string `json:"hosts,omitempty"`
		}
		items := []item{}
		for i := range metas {
			m := &metas[i]
			it := item{Alias: m.Alias, Fingerprint: m.Fingerprint, CreatedAt: m.CreatedAt, Comment: m.Comment, Hosts: bound[m.Alias]}
			if pk, err := m.PublicKey(); err == nil {
				it.Type = store.KeyDescription(pk)
			}
			it.PublicKey, _ = m.AuthorizedKey()
			items = append(items, it)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(items)
		return
	}

	if len(metas) == 0 {
		fmt.Println(i18n.T("list.empty"))
		return
	}
	rows := [][]string{strings.Split(i18n.T("list.header"), "\t")}
	for i := range metas {
		m := &metas[i]
		typ := "?"
		if pk, err := m.PublicKey(); err == nil {
			typ = store.KeyDescription(pk)
		}
		created := m.CreatedAt
		if t, err := time.Parse(time.RFC3339, m.CreatedAt); err == nil {
			created = t.Local().Format("2006-01-02")
		}
		hosts := strings.Join(bound[m.Alias], ", ")
		if hosts == "" {
			hosts = "-"
		}
		rows = append(rows, []string{m.Alias, typ, m.Fingerprint, created, hosts})
	}
	printTable(os.Stdout, rows)
}

func cmdPubkey() {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	alias := fs.String("alias", "", "key alias (or pass it as the first argument)")
	copyOut := fs.Bool("copy", false, "copy to the clipboard")
	if args := parseInterleaved(fs, os.Args[2:]); *alias == "" && len(args) > 0 {
		*alias = args[0]
	}
	if *alias == "" {
		fatal(errors.New(i18n.T("pubkey.usage")))
	}
	meta, err := store.LoadMeta(*alias)
	if err != nil {
		fatal(aliasError(*alias, err))
	}
	line, err := meta.AuthorizedKey()
	if err != nil {
		fatal(err)
	}
	fmt.Println(line)
	if *copyOut {
		cmd := exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader(line + "\n")
		if err := cmd.Run(); err != nil {
			fatal(err)
		}
		fmt.Fprintln(os.Stderr, i18n.T("pubkey.copied"))
	}
}

// cmdKeygen generates a key in memory and stores it encrypted, so the private
// key never exists in plaintext on disk.
func cmdKeygen() {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	alias := fs.String("alias", "", "key alias (or pass it as the first argument)")
	typ := fs.String("type", "ed25519", "key type: ed25519, ecdsa or rsa")
	bits := fs.Int("bits", 3072, "RSA key size")
	comment := fs.String("comment", "", "optional comment")
	if args := parseInterleaved(fs, os.Args[2:]); *alias == "" && len(args) > 0 {
		*alias = args[0]
	}
	if *alias == "" {
		fatal(errors.New(i18n.T("keygen.usage")))
	}
	if err := store.ValidateAlias(*alias); err != nil {
		fatal(aliasError(*alias, err))
	}
	if taken, err := aliasTaken(*alias); err != nil {
		fatal(err)
	} else if taken {
		fatal(errors.New(i18n.T("import.err_alias_exists", *alias)))
	}

	var key interface{}
	var err error
	switch strings.ToLower(*typ) {
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		if *bits < 2048 {
			fatal(errors.New(i18n.T("keygen.err_rsa_bits")))
		}
		key, err = rsa.GenerateKey(rand.Reader, *bits)
	default:
		fatal(errors.New(i18n.T("keygen.err_type", *typ)))
	}
	if err != nil {
		fatal(err)
	}
	rec, err := store.NewRecordFromKey(*alias, key, *comment)
	if err != nil {
		fatal(err)
	}

	mk := unlockMasterKey(i18n.T("auth.reason_keygen", *alias))
	if err := store.SaveEncryptedRecord(rec, mk); err != nil {
		fatal(err)
	}
	meta, err := store.LoadMeta(*alias)
	if err != nil {
		fatal(err)
	}
	line, _ := meta.AuthorizedKey()
	fmt.Println(i18n.T("keygen.done", *alias, rec.Fingerprint))
	fmt.Println()
	fmt.Println(line)
	fmt.Println()
	fmt.Println(i18n.T("keygen.next", *alias))
}

func agentSocket() string {
	cfg, err := config.Load()
	if err != nil {
		fatal(fmt.Errorf(i18n.T("cli.config_invalid"), err))
	}
	return cfg.Socket
}

func cmdBind() {
	fs := flag.NewFlagSet("bind", flag.ExitOnError)
	args := parseInterleaved(fs, os.Args[2:])
	if len(args) != 2 {
		fatal(errors.New(i18n.T("bind.usage")))
	}
	host, alias := args[0], args[1]
	if _, err := store.LoadMeta(alias); err != nil {
		fatal(aliasError(alias, err))
	}
	if err := store.SyncPubKeys(); err != nil {
		fatal(err)
	}
	pub, err := store.PubKeyPath(alias)
	if err != nil {
		fatal(aliasError(alias, err))
	}

	created, err := sshconfig.SetIdentity(host, tildify(agentSocket()), tildify(pub))
	var elsewhere *sshconfig.ErrDefinedElsewhere
	if errors.As(err, &elsewhere) {
		fatal(errors.New(i18n.T("bind.err_elsewhere", host, elsewhere.File,
			"IdentityAgent "+tildify(agentSocket())+"\n    IdentityFile "+tildify(pub)+"\n    IdentitiesOnly yes")))
	}
	if err != nil {
		fatal(err)
	}
	if created {
		fmt.Println(i18n.T("bind.created", host))
	}
	fmt.Println(i18n.T("bind.done", host, alias))
}

func cmdUnbind() {
	fs := flag.NewFlagSet("unbind", flag.ExitOnError)
	args := parseInterleaved(fs, os.Args[2:])
	if len(args) != 1 {
		fatal(errors.New(i18n.T("unbind.usage")))
	}
	changed, err := sshconfig.ClearIdentity(args[0], store.PubKeysDir())
	var elsewhere *sshconfig.ErrDefinedElsewhere
	if errors.As(err, &elsewhere) {
		fatal(errors.New(i18n.T("unbind.err_elsewhere", args[0], elsewhere.File)))
	}
	if err != nil {
		fatal(err)
	}
	if !changed {
		fmt.Println(i18n.T("unbind.none", args[0]))
		return
	}
	fmt.Println(i18n.T("unbind.done", args[0]))
}

// Original key file handling after import (P1-1).
const (
	originalKeep    = "keep"
	originalArchive = "archive"
	originalDelete  = "delete"
)

// archiveDir is outside ssh's default identity paths, so ssh stops picking
// up archived keys automatically.
func archiveDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "fssh-archive")
}

// handleOriginalKeyFile deals with the plaintext key left after import.
// mode "" asks in a terminal and keeps the file otherwise.
func handleOriginalKeyFile(path, alias, mode string) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if mode == "" {
		if !isTTY() {
			fmt.Println(i18n.T("import.original_hint", abs))
			return
		}
		fmt.Println()
		fmt.Println(i18n.T("import.original_prompt", abs))
		choice, err := prompt.TTY{}.Text(i18n.T("import.original_choice"))
		if err != nil {
			return
		}
		switch strings.TrimSpace(choice) {
		case "", "1":
			mode = originalArchive
		case "2":
			mode = originalDelete
		default:
			mode = originalKeep
		}
	}

	switch mode {
	case originalArchive:
		dest, err := archiveKeyFile(abs)
		if err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("import.original_failed", err))
			return
		}
		fmt.Println(i18n.T("import.original_archived", dest))
	case originalDelete:
		if isTTY() {
			ok, _ := prompt.TTY{}.Text(i18n.T("import.original_delete_confirm", abs))
			if strings.ToLower(strings.TrimSpace(ok)) != "y" {
				fmt.Println(i18n.T("import.original_kept"))
				return
			}
		}
		if err := os.Remove(abs); err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("import.original_failed", err))
			return
		}
		fmt.Println(i18n.T("import.original_deleted", abs))
	case originalKeep:
		fmt.Println(i18n.T("import.original_kept"))
	default:
		fatal(errors.New(i18n.T("import.err_original_mode", mode)))
	}

	if hosts, err := sshconfig.HostsUsingIdentityFile(abs); err == nil {
		for _, h := range hosts {
			fmt.Println(i18n.T("import.original_referenced", h, h, alias))
		}
	}
}

func archiveKeyFile(path string) (string, error) {
	dir := archiveDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, filepath.Base(path))
	if _, err := os.Stat(dest); err == nil {
		dest = fmt.Sprintf("%s.%d", dest, time.Now().Unix())
	}
	if err := os.Rename(path, dest); err != nil {
		return "", err
	}
	return dest, nil
}
