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
}

func defaultSocket() string {
    home, _ := os.UserHomeDir()
    return filepath.Join(home, ".fssh", "agent.sock")
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
            c := &Config{}
            c.ApplyDefaults()
            return c, nil
        }
        return nil, err
    }
    var c Config
    if err := json.Unmarshal(b, &c); err != nil {
        return nil, err
    }
    c.Socket = expandHome(c.Socket)
    c.LogOut = expandHome(c.LogOut)
    c.LogErr = expandHome(c.LogErr)
    c.ApplyDefaults()
    return &c, nil
}

func (c *Config) ApplyDefaults() {
    if c.Socket == "" { c.Socket = defaultSocket() }
    // default true unless explicitly set false in file
    if !c.RequireTouchPerSign { c.RequireTouchPerSign = true }
    if c.LogLevel == "" { c.LogLevel = "info" }
    if c.LogFormat == "" { c.LogFormat = "plain" }
    if c.LogTimeFormat == "" { c.LogTimeFormat = "2006-01-02T15:04:05Z07:00" }
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