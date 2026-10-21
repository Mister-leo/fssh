package sshconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupSSH writes files under a temp HOME's .ssh directory and returns HOME.
func setupSSH(t *testing.T, files map[string]string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	for name, content := range files {
		p := filepath.Join(home, ".ssh", name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func readConfig(t *testing.T, home string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseKV(t *testing.T) {
	cases := map[string][2]string{
		"HostName example.com":                    {"hostname", "example.com"},
		"HostName=example.com":                    {"hostname", "example.com"},
		"HostName = example.com":                  {"hostname", "example.com"},
		"  User\tdeploy  ":                        {"user", "deploy"},
		"ProxyCommand ssh -o ControlPath=x -W %h": {"proxycommand", "ssh -o ControlPath=x -W %h"},
		"Compression":                             {"compression", ""},
	}
	for in, want := range cases {
		k, v := parseKV(in)
		if k != want[0] || v != want[1] {
			t.Errorf("parseKV(%q) = %q, %q; want %q, %q", in, k, v, want[0], want[1])
		}
	}
}

func TestLoadHostInfosIncludeAliasesMatch(t *testing.T) {
	setupSSH(t, map[string]string{
		"config": `Include conf.d/*
Include ~/.ssh/extra
Include config

Host web1 web1-alias
    HostName 10.0.0.11

Host *.corp
    User me

Host db
    HostName db.internal
Match host bastion
    HostName wrong.example

Host jump-work
    HostName overridden.example
`,
		"conf.d/b-work": "Host jump-work\n  HostName 192.168.1.5\n",
		"conf.d/a-home": "Host nas\n  HostName nas.local\n",
		"extra":         "Host tilde\n  HostName t.example\n",
	})

	infos, err := LoadHostInfos()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]HostInfo{}
	for _, hi := range infos {
		got[hi.Name] = hi
	}
	if len(infos) != 5 {
		t.Fatalf("hosts = %+v, want 5 (wildcards skipped, aliases merged)", infos)
	}
	if w := got["web1"]; w.Hostname != "10.0.0.11" || len(w.Aliases) != 1 || w.Aliases[0] != "web1-alias" {
		t.Errorf("web1 = %+v", w)
	}
	if got["db"].Hostname != "db.internal" {
		t.Errorf("Match block HostName leaked into db: %+v", got["db"])
	}
	// included before the main file's definition, so the included one wins
	if j := got["jump-work"]; j.Hostname != "192.168.1.5" || !strings.HasSuffix(j.Source, "conf.d/b-work") {
		t.Errorf("jump-work = %+v", j)
	}
	if got["nas"].Hostname != "nas.local" || got["tilde"].Hostname != "t.example" {
		t.Errorf("glob or ~ include not followed: %+v", infos)
	}
	if hi, ok, _ := FindHost("web1-alias"); !ok || hi.Name != "web1" {
		t.Errorf("FindHost by alias = %+v, %v", hi, ok)
	}
}

func TestWriteHostConfigPreservesUnknownContent(t *testing.T) {
	home := setupSSH(t, map[string]string{"config": `Host app app-alias
    HostName 10.0.0.5
    User old
    # tunnel to the database
    LocalForward 5432 localhost:5432
    SetEnv FOO=bar

Host other
    HostName 10.0.0.6
`})
	cfg, err := LoadHostConfig("app")
	if err != nil {
		t.Fatal(err)
	}
	cfg.User = "new"
	if err := WriteHostConfig(cfg, true); err != nil {
		t.Fatal(err)
	}
	out := readConfig(t, home)
	for _, want := range []string{"Host app app-alias", "User new", "# tunnel to the database", "LocalForward 5432 localhost:5432", "SetEnv FOO=bar", "Host other"} {
		if !strings.Contains(out, want) {
			t.Errorf("lost %q after edit:\n%s", want, out)
		}
	}
	if strings.Contains(out, "User old") {
		t.Errorf("old value kept:\n%s", out)
	}
}

func TestSetAndClearIdentity(t *testing.T) {
	home := setupSSH(t, map[string]string{
		"config": `Host github.com
    User git
    IdentityFile ~/.ssh/id_work
    LocalForward 1 x:1

Host db
    HostName db
`,
		"conf.d/x": "Host included\n  HostName i\n",
	})
	pubDir := filepath.Join(home, ".fssh", "pubkeys")
	sock := filepath.Join(home, ".fssh", "agent.sock")

	created, err := SetIdentity("github.com", sock, filepath.Join(pubDir, "work.pub"))
	if err != nil || created {
		t.Fatalf("SetIdentity existing = %v, %v", created, err)
	}
	out := readConfig(t, home)
	if strings.Contains(out, "id_work") || !strings.Contains(out, "IdentitiesOnly yes") || !strings.Contains(out, "LocalForward 1 x:1") {
		t.Fatalf("unexpected block:\n%s", out)
	}
	cfg, _ := LoadHostConfig("github.com")
	if BoundKey(cfg, pubDir) != "work" {
		t.Fatalf("BoundKey = %q", BoundKey(cfg, pubDir))
	}
	if hosts, _ := HostsBoundTo("work", pubDir); len(hosts) != 1 || hosts[0] != "github.com" {
		t.Fatalf("HostsBoundTo = %v", hosts)
	}

	if created, err := SetIdentity("gitlab.com", sock, filepath.Join(pubDir, "home.pub")); err != nil || !created {
		t.Fatalf("SetIdentity new = %v, %v", created, err)
	}
	if cfg, err := LoadHostConfig("gitlab.com"); err != nil || BoundKey(cfg, pubDir) != "home" {
		t.Fatalf("new block not bound: %+v %v", cfg, err)
	}

	// Include-defined hosts are not edited
	os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Include conf.d/*\n"+readConfig(t, home)), 0600)
	var elsewhere *ErrDefinedElsewhere
	if _, err := SetIdentity("included", sock, "x.pub"); !errors.As(err, &elsewhere) {
		t.Fatalf("SetIdentity(included) err = %v", err)
	}

	if changed, err := ClearIdentity("github.com", pubDir); err != nil || !changed {
		t.Fatalf("ClearIdentity = %v, %v", changed, err)
	}
	cfg, _ = LoadHostConfig("github.com")
	if BoundKey(cfg, pubDir) != "" || cfg.IdentitiesOnly != "" || cfg.User != "git" {
		t.Fatalf("after clear: %+v", cfg)
	}
}

func TestAgentBlock(t *testing.T) {
	home := setupSSH(t, map[string]string{"config": `# fssh agent configuration
Host *
    IdentityAgent /old/agent.sock

Host a
    HostName a
`})
	sock := filepath.Join(home, ".fssh", "agent.sock")

	if changed, err := EnsureAgentBlock(sock); err != nil || !changed {
		t.Fatalf("EnsureAgentBlock = %v, %v", changed, err)
	}
	out := readConfig(t, home)
	if !strings.HasPrefix(out, managedBegin) || strings.Contains(out, "/old/agent.sock") || strings.Count(out, "Host *") != 1 {
		t.Fatalf("legacy block not replaced:\n%s", out)
	}
	if ok, _ := AgentConfigured(sock); !ok {
		t.Fatal("AgentConfigured = false")
	}
	if changed, _ := EnsureAgentBlock(sock); changed {
		t.Fatal("EnsureAgentBlock must be idempotent")
	}
	if removed, err := RemoveAgentBlock(); err != nil || !removed {
		t.Fatalf("RemoveAgentBlock = %v, %v", removed, err)
	}
	if out := readConfig(t, home); out != "Host a\n    HostName a\n" {
		t.Fatalf("after remove:\n%q", out)
	}
}

func TestAgentCoverage(t *testing.T) {
	home := setupSSH(t, map[string]string{"config": "Host github.com\n    IdentityAgent ~/.fssh/agent.sock\n"})
	sock := filepath.Join(home, ".fssh", "agent.sock")
	if g, p, _ := AgentCoverage(sock); g || !p {
		t.Fatalf("per-host only: global=%v partial=%v", g, p)
	}
	os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Host *\n    IdentityAgent "+sock+"\n"), 0600)
	if g, _, _ := AgentCoverage(sock); !g {
		t.Fatal("Host * block not detected as global")
	}
	os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("IdentityAgent "+sock+"\nHost a\n"), 0600)
	if g, _, _ := AgentCoverage(sock); !g {
		t.Fatal("top-level directive not detected as global")
	}
}

func TestBackupsArePruned(t *testing.T) {
	home := setupSSH(t, map[string]string{"config": "Host a\n    HostName a\n"})
	cfgPath := filepath.Join(home, ".ssh", "config")
	for i := 0; i < 8; i++ {
		os.WriteFile(fmt.Sprintf("%s.bak.%d", cfgPath, 1000+i), []byte("x"), 0600)
	}
	os.WriteFile(cfgPath+".bak.manual", []byte("mine"), 0600)
	if _, err := SetIdentity("a", "/s", "/p.pub"); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(cfgPath + ".bak.*")
	if len(matches) != keepBackups+1 { // + the user's own .bak.manual
		t.Fatalf("backups after prune: %v", matches)
	}
	if _, err := os.Stat(cfgPath + ".bak.manual"); err != nil {
		t.Fatal("non-timestamp backup must be left alone")
	}
}

func TestRemoveFsshSettings(t *testing.T) {
	home := setupSSH(t, map[string]string{"config": `Host github.com
  IdentityAgent ~/.fssh/agent.sock
  IdentityFile ~/.fssh/pubkeys/work.pub
  IdentitiesOnly yes

Host box
  HostName 10.0.0.1
  IdentityAgent ~/.fssh/agent.sock
  IdentityFile ~/.fssh/pubkeys/home.pub
  IdentityFile ~/.ssh/id_other
  IdentitiesOnly yes

Host untouched
  HostName u
`})
	pubDir := filepath.Join(home, ".fssh", "pubkeys")
	hosts, err := RemoveFsshSettings(pubDir, filepath.Join(home, ".fssh", "agent.sock"))
	if err != nil || len(hosts) != 2 {
		t.Fatalf("RemoveFsshSettings = %v, %v", hosts, err)
	}
	out := readConfig(t, home)
	if strings.Contains(out, "github.com") {
		t.Errorf("block that only held fssh settings should go:\n%s", out)
	}
	for _, want := range []string{"Host box", "HostName 10.0.0.1", "IdentityFile ~/.ssh/id_other", "IdentitiesOnly yes", "Host untouched"} {
		if !strings.Contains(out, want) {
			t.Errorf("lost %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "fssh") {
		t.Errorf("fssh settings left:\n%s", out)
	}
}
