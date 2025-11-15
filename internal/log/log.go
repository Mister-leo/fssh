package log

import (
    "encoding/json"
    "fmt"
    "os"
    "time"
    "fssh/internal/config"
)

var level = "info"
var format = "plain"
var timefmt = "2006-01-02T15:04:05Z07:00"

func Init(cfg *config.Config) {
    if cfg == nil { return }
    level = cfg.LogLevel
    format = cfg.LogFormat
    timefmt = cfg.LogTimeFormat
    config.SetupLogging(cfg)
}

func Debug(msg string, fields map[string]interface{}) { if should("debug") { out("debug", msg, fields) } }
func Info(msg string, fields map[string]interface{})  { if should("info") { out("info", msg, fields) } }
func Warn(msg string, fields map[string]interface{})  { if should("warn") { out("warn", msg, fields) } }
func Error(msg string, fields map[string]interface{}) { out("error", msg, fields) }

func should(l string) bool {
    switch level {
    case "debug": return true
    case "info": return l != "debug"
    case "warn": return l == "warn" || l == "error"
    case "error": return l == "error"
    default: return true
    }
}

func out(l, msg string, fields map[string]interface{}) {
    ts := time.Now().Format(timefmt)
    if format == "json" {
        m := map[string]interface{}{"time": ts, "level": l, "msg": msg}
        for k, v := range fields { m[k] = v }
        b, _ := json.Marshal(m)
        fmt.Fprintln(os.Stderr, string(b))
        return
    }
    fmt.Fprintf(os.Stderr, "%s %s %s", ts, l, msg)
    for k, v := range fields {
        fmt.Fprintf(os.Stderr, " %s=%v", k, v)
    }
    fmt.Fprintln(os.Stderr)
}