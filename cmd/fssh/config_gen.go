package main

import (
    "bufio"
    "errors"
    "flag"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "time"
    "fssh/internal/config"
)

func cmdConfigGen() {
    fs := flag.NewFlagSet("config-gen", flag.ExitOnError)
    host := fs.String("host", "", "host name")
    user := fs.String("user", "", "user")
    port := fs.String("port", "", "port")
    write := fs.Bool("write", false, "write to ~/.ssh/config")
    overwrite := fs.Bool("overwrite", false, "overwrite existing host block")
    globalAlgos := fs.Bool("global-algos", false, "write RSA-SHA2 algorithms to Host *")
    fs.Parse(os.Args[2:])
    if *host == "" { fatal(errors.New("host is required")) }
    cfg, _ := config.Load()
    block := buildHostBlock(*host, *user, *port, cfg.Socket)
    if !*write {
        fmt.Print(block)
        return
    }
    home, _ := os.UserHomeDir()
    p := filepath.Join(home, ".ssh", "config")
    _ = os.MkdirAll(filepath.Dir(p), 0700)
    bak := p + ".bak." + fmt.Sprintf("%d", time.Now().Unix())
    _ = copyFile(p, bak)
    content := readFileOrEmpty(p)
    var out string
    if hasHostBlock(content, *host) {
        if !*overwrite { out = content } else { out = replaceHostBlock(content, *host, block) }
    } else {
        out = strings.TrimRight(content, "\n") + "\n\n" + block
    }
    if *globalAlgos {
        out = ensureGlobalAlgos(out)
    }
    if err := os.WriteFile(p, []byte(out), 0600); err != nil { fatal(err) }
    fmt.Println("wrote", p)
}

func buildHostBlock(host, user, port, sock string) string {
    var b strings.Builder
    b.WriteString("Host "); b.WriteString(host); b.WriteString("\n")
    if user != "" { b.WriteString("  User "); b.WriteString(user); b.WriteString("\n") }
    if port != "" { b.WriteString("  Port "); b.WriteString(port); b.WriteString("\n") }
    b.WriteString("  IdentityAgent "); b.WriteString(sock); b.WriteString("\n")
    return b.String()
}

func readFileOrEmpty(p string) string {
    b, err := os.ReadFile(p)
    if err != nil { return "" }
    return string(b)
}

func hasHostBlock(content, host string) bool {
    s := bufio.NewScanner(strings.NewReader(content))
    for s.Scan() {
        line := strings.TrimSpace(s.Text())
        if strings.HasPrefix(strings.ToLower(line), "host ") {
            parts := strings.Fields(line[5:])
            for _, h := range parts { if h == host { return true } }
        }
    }
    return false
}

func replaceHostBlock(content, host, block string) string {
    lines := strings.Split(content, "\n")
    var out []string
    in := false
    match := func(line string) bool {
        line = strings.TrimSpace(line)
        if !strings.HasPrefix(strings.ToLower(line), "host ") { return false }
        parts := strings.Fields(line[5:])
        for _, h := range parts { if h == host { return true } }
        return false
    }
    for i := 0; i < len(lines); i++ {
        if !in && match(lines[i]) { in = true; out = append(out, strings.TrimRight(block, "\n")); continue }
        if in {
            if strings.HasPrefix(strings.ToLower(strings.TrimSpace(lines[i])), "host ") { in = false; out = append(out, lines[i]); continue }
            continue
        }
        out = append(out, lines[i])
    }
    if in { in = false }
    return strings.Join(out, "\n")
}

func ensureGlobalAlgos(content string) string {
    s := bufio.NewScanner(strings.NewReader(content))
    found := false
    for s.Scan() {
        if strings.HasPrefix(strings.ToLower(strings.TrimSpace(s.Text())), "host *") { found = true; break }
    }
    if found && strings.Contains(content, "PubkeyAcceptedAlgorithms") { return content }
    var b strings.Builder
    b.WriteString(strings.TrimRight(content, "\n"))
    b.WriteString("\n\nHost *\n  PubkeyAcceptedAlgorithms +rsa-sha2-512,rsa-sha2-256\n")
    return b.String()
}

func copyFile(src, dst string) error {
    b, err := os.ReadFile(src)
    if err != nil { return nil }
    return os.WriteFile(dst, b, 0600)
}