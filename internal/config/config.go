package config

import (
    "encoding/json"
    "errors"
    "os"
    "path/filepath"
    "strings"
)

type Config struct {
    Socket               string `json:"socket"`
    RequireTouchPerSign  bool   `json:"require_touch_id_per_sign"`
    LogOut               string `json:"log_out"`
    LogErr               string `json:"log_err"`
    UnlockTTLSeconds     int    `json:"unlock_ttl_seconds"`
    LogLevel             string `json:"log_level"`
    LogFormat            string `json:"log_format"`
    LogTimeFormat        string `json:"log_time_format"`
    Language             string `json:"language"` // "zh" or "en", empty = follow system
    // ForwardedSign controls signature requests arriving through agent
    // forwarding (ssh -A): "prompt" asks every time, "deny" refuses them.
    ForwardedSign        string `json:"forwarded_sign"`
}

const (
    ForwardedSignPrompt = "prompt"
    ForwardedSignDeny   = "deny"
)

func defaultSocket() string {
    home, _ := os.UserHomeDir()
    return filepath.Join(home, ".fssh", "agent.sock")
}

const defaultUnlockTTLSeconds = 600

// Default returns a config with all defaults applied.
// Non-string defaults live here rather than in ApplyDefaults, because a zero
// value (false / 0) can be an explicit user choice.
func Default() *Config {
    c := &Config{
        RequireTouchPerSign: true,
        UnlockTTLSeconds:    defaultUnlockTTLSeconds,
    }
    c.ApplyDefaults()
    return c
}

func Load() (*Config, error) {
    home, err := os.UserHomeDir()
    if err != nil {
        return nil, err
    }
    p := filepath.Join(home, ".fssh", "config.json")
    b, err := os.ReadFile(p)
    if err != nil {
        if errors.Is(err, os.ErrNotExist) {
            return Default(), nil
        }
        return nil, err
    }
    // Unmarshal over the defaults so that fields absent from the file keep
    // their default while explicit values (including false / 0) win.
    c := Default()
    if err := json.Unmarshal(b, c); err != nil {
        return nil, err
    }
    c.Socket = expandHome(c.Socket)
    c.LogOut = expandHome(c.LogOut)
    c.LogErr = expandHome(c.LogErr)
    c.ApplyDefaults()
    return c, nil
}

// ApplyDefaults fills empty string fields.
func (c *Config) ApplyDefaults() {
    if c.Socket == "" { c.Socket = defaultSocket() }
    if c.LogLevel == "" { c.LogLevel = "info" }
    if c.LogFormat == "" { c.LogFormat = "plain" }
    if c.LogTimeFormat == "" { c.LogTimeFormat = "2006-01-02T15:04:05Z07:00" }
    if c.ForwardedSign != ForwardedSignDeny { c.ForwardedSign = ForwardedSignPrompt }
}

func SetupLogging(c *Config) {
    if c.LogOut != "" {
        if f, err := os.OpenFile(c.LogOut, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
            os.Stdout = f
        }
    }
    if c.LogErr != "" {
        if f, err := os.OpenFile(c.LogErr, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
            os.Stderr = f
        }
    }
}

func expandHome(p string) string {
    if p == "" { return p }
    if strings.HasPrefix(p, "~") {
        home, _ := os.UserHomeDir()
        if home != "" {
            return filepath.Join(home, strings.TrimPrefix(p, "~"))
        }
    }
    return p
}