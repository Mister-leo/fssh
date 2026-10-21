package main

import (
    "bufio"
    "crypto/rand"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"

    "fssh/internal/store"
    "fssh/internal/keychain"
    "fssh/internal/config"
    "fssh/internal/log"
    agentserver "fssh/internal/agent"
    "golang.org/x/term"
)

func main() {
    if len(os.Args) < 2 {
        runShell()
        return
    }
    cmd := os.Args[1]
    switch cmd {
    case "init":
        cmdInit()
    case "import":
        cmdImport()
    case "list":
        cmdList()
    case "export":
        cmdExport()
    case "status":
        cmdStatus()
    case "agent":
        cmdAgent()
    case "remove":
        cmdRemove()
    case "rekey":
        cmdRekey()
    case "shell":
        runShell()
    case "sshd-align":
        cmdAlignSSHD()
    case "config-gen":
        cmdConfigGen()
    default:
        usage()
        os.Exit(2)
    }
}

func usage() {
    fmt.Fprintf(os.Stderr, "usage: fssh <init|import|list|export|remove|rekey|status|agent|shell|sshd-align|config-gen>\n")
}

func cmdInit() {
    fs := flag.NewFlagSet("init", flag.ExitOnError)
    force := fs.Bool("force", false, "recreate master key if exists")
    mode := fs.String("mode", "", "authentication mode: touchid or otp (empty = interactive prompt)")
    seedTTL := fs.Int("seed-unlock-ttl", 3600, "OTP seed cache time (seconds), OTP mode only")
    algorithm := fs.String("algorithm", "SHA1", "TOTP algorithm: SHA1, SHA256, SHA512, OTP mode only")
    digits := fs.Int("digits", 6, "TOTP digits: 6 or 8, OTP mode only")
    interactive := fs.Bool("interactive", false, "run full setup wizard")
    nonInteractive := fs.Bool("non-interactive", false, "disable all interactive prompts")
    fs.Parse(os.Args[2:])

    // Decide whether to run interactive mode
    isTTY := term.IsTerminal(int(os.Stdin.Fd()))
    shouldRunInteractive := *interactive || (isTTY && *mode == "" && !*nonInteractive)

    if shouldRunInteractive {
        runInteractiveSetup(*force, *seedTTL, *algorithm, *digits)
    } else {
        runLegacyInit(*force, *mode, *seedTTL, *algorithm, *digits)
    }
}

// runLegacyInit executes the original non-interactive initialization
func runLegacyInit(force bool, mode string, seedTTL int, algorithm string, digits int) {
    // Default to touchid if mode not specified
    if mode == "" {
        mode = "touchid"
    }

    // 根据模式选择初始化方式
    switch mode {
    case "touchid":
        initTouchIDMode(force)
    case "otp":
        initOTPMode(force, seedTTL, algorithm, digits)
    default:
        fatal(fmt.Errorf("不支持的认证模式: %s (支持 touchid 或 otp)", mode))
    }
}

func cmdImport() {
    fs := flag.NewFlagSet("import", flag.ExitOnError)
    alias := fs.String("alias", "", "alias name")
    file := fs.String("file", "", "path to private key file")
    pass := fs.String("passphrase", "", "DEPRECATED: passphrase in CLI may leak; prefer --ask-passphrase or --passphrase-file or --passphrase-stdin")
    ask := fs.Bool("ask-passphrase", false, "read passphrase securely from TTY")
    passFile := fs.String("passphrase-file", "", "read passphrase from file path")
    passStdin := fs.Bool("passphrase-stdin", false, "read passphrase from stdin")
    comment := fs.String("comment", "", "optional comment")
    fs.Parse(os.Args[2:])

    if *alias == "" || *file == "" {
        fatal(errors.New("alias and file are required"))
    }

    // 1. 读取私钥文件
    b, err := os.ReadFile(*file)
    if err != nil {
        fatal(err)
    }

    // 2. 先询问私钥密码
    p, err := resolvePassphrase(*pass, *ask, *passFile, *passStdin, "Input key passphrase: ")
    if err != nil { fatal(err) }

    // 3. 解密私钥并创建记录（验证私钥和密码是否正确）
    rec, err := store.NewRecordFromPrivateKeyBytes(*alias, b, p, *comment)
    if err != nil {
        fatal(err)
    }

    // 4. 私钥验证成功后，再要求 Touch ID 获取 master key
    mk, err := keychain.LoadMasterKey()
    if err != nil {
        fatal(err)
    }

    // 5. 用 master key 加密并保存私钥
    if err := store.SaveEncryptedRecord(rec, mk); err != nil {
        fatal(err)
    }
    fmt.Printf("imported %s fingerprint=%s\n", rec.Alias, rec.Fingerprint)
}

func cmdList() {
    dir := store.KeysDir()
    entries, err := os.ReadDir(dir)
    if err != nil && !os.IsNotExist(err) {
        fatal(err)
    }
    if len(entries) == 0 {
        fmt.Println("no keys imported")
        return
    }
    for _, e := range entries {
        if e.IsDir() || !strings.HasSuffix(e.Name(), ".enc") {
            continue
        }
        p := filepath.Join(dir, e.Name())
        data, err := os.ReadFile(p)
        if err != nil {
            fatal(err)
        }
        var m store.EncryptedFile
        if err := json.Unmarshal(data, &m); err != nil {
            fatal(err)
        }
        fmt.Printf("alias=%s fingerprint=%s created=%s\n", m.Alias, m.Fingerprint, m.CreatedAt)
    }
}

func cmdExport() {
    fs := flag.NewFlagSet("export", flag.ExitOnError)
    alias := fs.String("alias", "", "alias name")
    out := fs.String("out", "", "output path")
    pass := fs.String("passphrase", "", "DEPRECATED: passphrase in CLI may leak; prefer --ask-passphrase or --passphrase-file or --passphrase-stdin")
    ask := fs.Bool("ask-passphrase", false, "read passphrase securely from TTY")
    passFile := fs.String("passphrase-file", "", "read passphrase from file path")
    passStdin := fs.Bool("passphrase-stdin", false, "read passphrase from stdin")
    force := fs.Bool("force", false, "overwrite output if exists")
    fs.Parse(os.Args[2:])
    if *alias == "" || *out == "" {
        fatal(errors.New("alias and out are required"))
    }
    if !*force {
        if _, err := os.Stat(*out); err == nil {
            fatal(fmt.Errorf("output exists: %s", *out))
        }
    }
    mk, err := keychain.LoadMasterKey()
    if err != nil {
        fatal(err)
    }
    rec, err := store.LoadDecryptedRecord(*alias, mk)
    if err != nil {
        fatal(err)
    }
    p, err := resolvePassphrase(*pass, *ask, *passFile, *passStdin, "Export PEM passphrase (optional, press Enter for none): ")
    if err != nil { fatal(err) }
    pemBytes, err := store.ExportPKCS8PEM(rec, p)
    if err != nil {
        fatal(err)
    }
    if err := os.WriteFile(*out, pemBytes, 0600); err != nil {
        fatal(err)
    }
    fmt.Printf("exported %s to %s (PKCS#8 PEM)%s\n", rec.Alias, *out, func() string { if p != "" { return " with passphrase" } ; return "" }())
}

func cmdStatus() {
    exists, err := keychain.MasterKeyExists()
    if err != nil {
        fatal(err)
    }
    fmt.Printf("master_key=%v\n", exists)
    dir := store.KeysDir()
    _, err = os.Stat(dir)
    fmt.Printf("store_dir=%s exists=%v\n", dir, err == nil)
}

func cmdAgent() {
    cfg, err := config.Load()
    if err != nil {
        fatal(fmt.Errorf("load ~/.fssh/config.json: %w", err))
    }
    fs := flag.NewFlagSet("agent", flag.ExitOnError)
    sock := fs.String("socket", cfg.Socket, "unix socket path for SSH agent")
    require := fs.Bool("require-touch-id-per-sign", cfg.RequireTouchPerSign, "require Touch ID on every signature")
    ttl := fs.Int("unlock-ttl-seconds", cfg.UnlockTTLSeconds, "unlock cache TTL in seconds, 0 = authenticate on every signature (secure mode)")
    fs.Parse(os.Args[2:])
    log.Init(cfg)
    if err := agentserver.StartWithOptions(*sock, *require, *ttl); err != nil {
        fatal(err)
    }
}

func cmdRemove() {
    fs := flag.NewFlagSet("remove", flag.ExitOnError)
    alias := fs.String("alias", "", "alias name")
    fs.Parse(os.Args[2:])
    if *alias == "" { fatal(errors.New("alias is required")) }
    if _, err := keychain.LoadMasterKey(); err != nil { fatal(err) }
    path := filepath.Join(store.KeysDir(), *alias+".enc")
    if err := os.Remove(path); err != nil { fatal(err) }
    fmt.Printf("removed %s\n", *alias)
}

func cmdRekey() {
    fs := flag.NewFlagSet("rekey", flag.ExitOnError)
    fs.Parse(os.Args[2:])
    old, err := keychain.LoadMasterKey()
    if err != nil { fatal(err) }
    newk := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, newk); err != nil { fatal(err) }
    dir := store.KeysDir()
    entries, err := os.ReadDir(dir)
    if err != nil && !os.IsNotExist(err) { fatal(err) }
    for _, e := range entries {
        if e.IsDir() || !strings.HasSuffix(e.Name(), ".enc") { continue }
        alias := strings.TrimSuffix(e.Name(), ".enc")
        rec, err := store.LoadDecryptedRecord(alias, old)
        if err != nil { fatal(err) }
        if err := store.SaveEncryptedRecord(rec, newk); err != nil { fatal(err) }
    }
    if err := keychain.StoreMasterKey(newk, true); err != nil { fatal(err) }
    fmt.Println("rekeyed master key and re-encrypted all records")
}

func fatal(err error) {
    fmt.Fprintln(os.Stderr, "error:", err)
    os.Exit(1)
}

func resolvePassphrase(cli string, ask bool, file string, stdin bool, prompt string) (string, error) {
    cnt := 0
    if cli != "" { cnt++ }
    if ask { cnt++ }
    if file != "" { cnt++ }
    if stdin { cnt++ }
    if cnt > 1 { return "", errors.New("specify only one of passphrase sources") }
    if cli != "" { return cli, nil }
    if ask {
        fd := int(os.Stdin.Fd())
        if term.IsTerminal(fd) {
            // Disable bracketed paste and focus events before reading password
            fmt.Fprint(os.Stderr, "\033[?2004l")  // Disable bracketed paste mode
            fmt.Fprint(os.Stderr, prompt)
            b, err := term.ReadPassword(fd)
            fmt.Fprintln(os.Stderr)
            // Re-enable bracketed paste after reading
            fmt.Fprint(os.Stderr, "\033[?2004h")
            if err != nil { return "", err }
            return string(b), nil
        }
        r := bufio.NewReader(os.Stdin)
        s, err := r.ReadString('\n')
        if err != nil && err != io.EOF { return "", err }
        return strings.TrimRight(s, "\r\n"), nil
    }
    if file != "" {
        b, err := os.ReadFile(file)
        if err != nil { return "", err }
        return strings.TrimRight(string(b), "\r\n"), nil
    }
    if stdin {
        r := bufio.NewReader(os.Stdin)
        s, err := r.ReadString('\n')
        if err != nil && err != io.EOF { return "", err }
        return strings.TrimRight(s, "\r\n"), nil
    }
    return "", nil
}
