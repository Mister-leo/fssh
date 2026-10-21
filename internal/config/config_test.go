package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig 在临时 HOME 下写入 ~/.fssh/config.json（content 为空则不创建文件）
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if content != "" {
		dir := filepath.Join(home, ".fssh")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func TestLoadNoFileUsesDefaults(t *testing.T) {
	home := writeConfig(t, "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.RequireTouchPerSign {
		t.Error("RequireTouchPerSign default should be true")
	}
	if c.UnlockTTLSeconds != defaultUnlockTTLSeconds {
		t.Errorf("UnlockTTLSeconds = %d, want %d", c.UnlockTTLSeconds, defaultUnlockTTLSeconds)
	}
	if want := filepath.Join(home, ".fssh", "agent.sock"); c.Socket != want {
		t.Errorf("Socket = %q, want %q", c.Socket, want)
	}
	if c.LogLevel != "info" || c.LogFormat != "plain" {
		t.Errorf("log defaults = %q/%q", c.LogLevel, c.LogFormat)
	}
}

func TestLoadMissingFieldsKeepDefaults(t *testing.T) {
	writeConfig(t, `{"log_level": "debug"}`)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.RequireTouchPerSign {
		t.Error("absent require_touch_id_per_sign should default to true")
	}
	if c.UnlockTTLSeconds != defaultUnlockTTLSeconds {
		t.Errorf("absent unlock_ttl_seconds = %d, want %d", c.UnlockTTLSeconds, defaultUnlockTTLSeconds)
	}
	if c.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", c.LogLevel)
	}
}

func TestLoadExplicitFalseAndZeroAreRespected(t *testing.T) {
	writeConfig(t, `{"require_touch_id_per_sign": false, "unlock_ttl_seconds": 0}`)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.RequireTouchPerSign {
		t.Error("explicit require_touch_id_per_sign=false was overridden to true")
	}
	if c.UnlockTTLSeconds != 0 {
		t.Errorf("explicit unlock_ttl_seconds=0 became %d", c.UnlockTTLSeconds)
	}
}

func TestLoadExpandsHome(t *testing.T) {
	home := writeConfig(t, `{"socket": "~/custom/agent.sock"}`)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, "custom", "agent.sock"); c.Socket != want {
		t.Errorf("Socket = %q, want %q", c.Socket, want)
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	writeConfig(t, `{not json`)
	if _, err := Load(); err == nil {
		t.Fatal("expected error for malformed config.json")
	}
}
