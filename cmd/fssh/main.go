package main

import (
    "bufio"
    "errors"
    "flag"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"

    "fssh/internal/sshconfig"
    "fssh/internal/store"
    "fssh/internal/auth"
    "fssh/internal/config"
    "fssh/internal/i18n"
    "fssh/internal/log"
    "fssh/internal/otp"
    agentserver "fssh/internal/agent"
    "golang.org/x/term"
)

// commandNames lists commands in the order shown by `fssh help`.
var commandNames = []string{
    "init", "import", "keygen", "list", "pubkey", "bind", "unbind", "export", "remove",
    "backup", "restore", "rekey", "mode", "status", "doctor", "agent", "log", "otp", "shell",
    "config-gen", "sshd-align", "uninstall", "version", "help",
}

func main() {
    if len(os.Args) < 2 {
        if !isInitialized() {
            fmt.Println(i18n.T("cli.not_initialized"))
        }
        runShell()
        return
    }
    cmd := os.Args[1]
    if cmd != "agent" {
        // info logs are for the long-running agent; interactive commands only show problems
        log.SetLevel("warn")
    }
    switch cmd {
    case "help", "-h", "--help":
        cmdHelp(os.Args[2:])
    case "version", "-v", "--version":
        fmt.Println(versionString())
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
    case "keygen":
        cmdKeygen()
    case "pubkey":
        cmdPubkey()
    case "bind":
        cmdBind()
    case "unbind":
        cmdUnbind()
    case "doctor":
        cmdDoctor()
    case "backup":
        cmdBackup()
    case "restore":
        cmdRestore()
    case "mode":
        cmdMode()
    case "uninstall":
        cmdUninstall()
    case "otp":
        cmdOTP()
    case "log":
        cmdLog()
    case "sshd-align":
        cmdAlignSSHD()
    case "config-gen":
        cmdConfigGen()
    default:
        fmt.Fprintln(os.Stderr, i18n.T("cli.unknown_command", cmd))
        fmt.Fprintln(os.Stderr)
        printHelp(os.Stderr)
        os.Exit(2)
    }
}

func printHelp(w io.Writer) {
    fmt.Fprintln(w, i18n.T("help.title"))
    fmt.Fprintln(w)
    fmt.Fprintln(w, i18n.T("help.usage"))
    fmt.Fprintln(w)
    fmt.Fprintln(w, i18n.T("help.commands"))
    for _, name := range commandNames {
        fmt.Fprintf(w, "  %-12s %s\n", name, i18n.T("cmd."+name))
    }
    fmt.Fprintln(w)
    fmt.Fprintln(w, i18n.T("help.footer"))
}

// cmdHelp prints general help, or `fssh help <command>` shows that command's flags.
func cmdHelp(args []string) {
    if len(args) == 0 {
        printHelp(os.Stdout)
        return
    }
    name := args[0]
    known := false
    for _, c := range commandNames {
        if c == name {
            known = true
            break
        }
    }
    if !known {
        fmt.Fprintln(os.Stderr, i18n.T("cli.unknown_command", name))
        os.Exit(2)
    }
    fmt.Printf("fssh %s - %s\n\n", name, i18n.T("cmd."+name))
    switch name {
    case "status", "doctor", "shell", "version", "help":
        return // no flags
    case "bind":
        fmt.Println(i18n.T("bind.usage"))
        return
    case "unbind":
        fmt.Println(i18n.T("unbind.usage"))
        return
    case "otp":
        printOTPHelp()
        return
    case "mode":
        fmt.Println(i18n.T("mode.usage"))
        return
    }
    // Re-dispatch with -h: each command's FlagSet prints its flags and exits 0.
    os.Args = []string{os.Args[0], name, "-h"}
    main()
}

// isInitialized reports whether `fssh init` has run, without touching the
// Keychain (which could trigger an authorization prompt).
func isInitialized() bool {
    home, err := os.UserHomeDir()
    if err != nil {
        return false
    }
    for _, p := range []string{
        filepath.Join(home, ".fssh", "auth_mode.json"),
        store.KeysDir(),
    } {
        if _, err := os.Stat(p); err == nil {
            return true
        }
    }
    return false
}

func cmdInit() {
    fs := flag.NewFlagSet("init", flag.ExitOnError)
    force := fs.Bool("force", false, "start over: move existing keys aside and create a new master key")
    mode := fs.String("mode", "", "authentication mode: touchid or otp (empty = interactive prompt)")
    seedTTL := fs.Int("seed-unlock-ttl", 3600, "OTP seed cache time (seconds), OTP mode only")
    algorithm := fs.String("algorithm", "SHA1", "TOTP algorithm: SHA1, SHA256, SHA512, OTP mode only")
    digits := fs.Int("digits", 6, "TOTP digits: 6 or 8, OTP mode only")
    interactive := fs.Bool("interactive", false, "run full setup wizard")
    nonInteractive := fs.Bool("non-interactive", false, "disable all interactive prompts")
    fs.Parse(os.Args[2:])
    o := otpOptions{seedTTL: *seedTTL, algorithm: *algorithm, digits: *digits}

    if *interactive || (isTTY() && *mode == "" && !*nonInteractive) {
        runInteractiveSetup(*force, o)
        return
    }
    runNonInteractiveInit(*force, *mode, o)
}

// runNonInteractiveInit initializes one auth mode without the wizard.
func runNonInteractiveInit(force bool, mode string, o otpOptions) {
    if mode == "" {
        mode = string(auth.ModeTouchID)
    }
    target := auth.AuthMode(mode)
    if target != auth.ModeTouchID && target != auth.ModeOTP {
        fatal(errors.New(i18n.T("init.err_mode", mode)))
    }

    initialized, current, err := auth.IsInitialized()
    if err != nil {
        fatal(err)
    }
    switch {
    case initialized && !force && current == target:
        fmt.Println(i18n.T("init.already", current))
        return
    case initialized && !force:
        fatal(errors.New(i18n.T("init.already_other", current, target)))
    case initialized && force:
        fmt.Println(i18n.T("init.force_reset"))
        resetStore()
    default:
        moveAsideOrphans()
    }
    initMode(target, o)
}

// moveAsideOrphans handles records left without a master key (e.g. the
// Keychain item was deleted): a new master key could never decrypt them,
// so they are moved aside instead of silently mixed in.
func moveAsideOrphans() {
    if metas, _ := store.ListMeta(); len(metas) > 0 {
        fmt.Println(i18n.T("init.orphans", len(metas)))
        resetStore()
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
    force := fs.Bool("force", false, "overwrite an existing alias / allow importing an already imported key")
    original := fs.String("original", "", "what to do with the plaintext key file after import: archive, delete or keep (default: ask)")
    fs.Parse(os.Args[2:])
    switch *original {
    case "", originalKeep, originalArchive, originalDelete:
    default:
        fatal(errors.New(i18n.T("import.err_original_mode", *original)))
    }

    if *alias == "" || *file == "" {
        fatal(errors.New(i18n.T("import.err_args_required")))
    }

    // 1. 校验别名，已存在时先失败，避免白输密码
    if err := store.ValidateAlias(*alias); err != nil {
        fatal(aliasError(*alias, err))
    }
    if taken, err := aliasTaken(*alias); err != nil {
        fatal(err)
    } else if taken && !*force {
        fatal(errors.New(i18n.T("import.err_alias_exists", *alias)))
    }

    // 2. 读取私钥文件
    b, err := os.ReadFile(*file)
    if err != nil {
        if errors.Is(err, os.ErrNotExist) {
            fatal(errors.New(i18n.T("import.err_file_not_found", *file)))
        }
        fatal(errors.New(i18n.T("import.err_read_file", err)))
    }

    // 3. 解密私钥并创建记录；在终端中且未指定文件/stdin 密码源时，按需提示输入密码
    p, err := resolvePassphrase(*pass, *ask, *passFile, *passStdin, i18n.T("import.prompt_passphrase"))
    if err != nil { fatal(err) }
    interactive := term.IsTerminal(int(os.Stdin.Fd())) && *passFile == "" && !*passStdin && *pass == ""
    rec, err := parseKeyWithRetry(*alias, b, p, *comment, interactive, "")
    if err != nil {
        fatal(err)
    }

    // 4. 同一把私钥已用其他别名导入时提示
    if existing, ok, err := store.FindByFingerprint(rec.Fingerprint); err != nil {
        fatal(err)
    } else if ok && existing != *alias && !*force {
        fatal(errors.New(i18n.T("import.err_already_imported", existing, rec.Fingerprint)))
    }

    // 5. 私钥验证成功后，再认证获取 master key（Touch ID 或 OTP）
    mk := unlockMasterKey(i18n.T("auth.reason_import", *alias))

    // 6. 用 master key 加密并保存私钥
    if err := store.SaveEncryptedRecord(rec, mk); err != nil {
        fatal(err)
    }
    fmt.Println(i18n.T("import.done", rec.Alias, rec.Fingerprint))

    // 7. 明文私钥仍在磁盘上，ssh 也可能绕过 fssh 直接使用它
    handleOriginalKeyFile(*file, rec.Alias, *original)
}

func cmdExport() {
    fs := flag.NewFlagSet("export", flag.ExitOnError)
    alias := fs.String("alias", "", "alias name")
    out := fs.String("out", "", "output path")
    format := fs.String("format", "openssh", "openssh (usable by ssh, optional passphrase) or pkcs8 (unencrypted PEM)")
    pass := fs.String("passphrase", "", "DEPRECATED: passphrase in CLI may leak; prefer --ask-passphrase or --passphrase-file or --passphrase-stdin")
    ask := fs.Bool("ask-passphrase", false, "read passphrase securely from TTY")
    passFile := fs.String("passphrase-file", "", "read passphrase from file path")
    passStdin := fs.Bool("passphrase-stdin", false, "read passphrase from stdin")
    force := fs.Bool("force", false, "overwrite output if exists")
    fs.Parse(os.Args[2:])
    if *alias == "" || *out == "" {
        fatal(errors.New(i18n.T("export.usage")))
    }
    if *format != "openssh" && *format != "pkcs8" {
        fatal(errors.New(i18n.T("export.err_format", *format)))
    }
    if !*force {
        if _, err := os.Stat(*out); err == nil {
            fatal(errors.New(i18n.T("export.err_exists", *out)))
        }
    }
    // 先确认密钥存在，再认证
    if _, err := store.LoadMeta(*alias); err != nil {
        fatal(aliasError(*alias, err))
    }
    p, err := resolvePassphrase(*pass, *ask, *passFile, *passStdin, i18n.T("export.prompt_passphrase"))
    if err != nil { fatal(err) }
    if p != "" && *format == "pkcs8" {
        fatal(errors.New(i18n.T("export.err_pkcs8_passphrase")))
    }
    mk := unlockMasterKey(i18n.T("auth.reason_export", *alias))
    rec, err := store.LoadDecryptedRecord(*alias, mk)
    if err != nil {
        fatal(err)
    }
    var data []byte
    if *format == "pkcs8" {
        data = store.ExportPKCS8PEM(rec)
    } else if data, err = store.ExportOpenSSH(rec, p); err != nil {
        fatal(err)
    }
    if err := os.WriteFile(*out, data, 0600); err != nil {
        fatal(err)
    }
    if p == "" {
        fmt.Println(i18n.T("export.done_plain", rec.Alias, *out))
    } else {
        fmt.Println(i18n.T("export.done", rec.Alias, *out))
    }
}

func cmdAgent() {
    cfg, err := config.Load()
    if err != nil {
        fatal(fmt.Errorf(i18n.T("cli.config_invalid"), err))
    }
    fs := flag.NewFlagSet("agent", flag.ExitOnError)
    sock := fs.String("socket", cfg.Socket, "unix socket path for SSH agent")
    require := fs.Bool("require-touch-id-per-sign", cfg.RequireTouchPerSign, "require Touch ID on every signature")
    ttl := fs.Int("unlock-ttl-seconds", cfg.UnlockTTLSeconds, "unlock cache TTL in seconds, 0 = authenticate on every signature (secure mode)")
    fs.Parse(os.Args[2:])
    log.Init(cfg)
    if err := agentserver.StartWithOptions(*sock, *require, *ttl, cfg.ForwardedSign); err != nil {
        fatal(err)
    }
}

func cmdRemove() {
    fs := flag.NewFlagSet("remove", flag.ExitOnError)
    alias := fs.String("alias", "", "alias name")
    yes := fs.Bool("yes", false, "skip the confirmation prompt")
    fs.Parse(os.Args[2:])
    if *alias == "" { fatal(errors.New(i18n.T("remove.err_alias_required"))) }

    // 先确认密钥存在并让用户确认，再要求认证
    meta, err := store.LoadMeta(*alias)
    if err != nil { fatal(aliasError(*alias, err)) }
    if !*yes {
        if !term.IsTerminal(int(os.Stdin.Fd())) { fatal(errors.New(i18n.T("remove.err_need_yes"))) }
        if !otp.PromptConfirm(i18n.T("remove.confirm", meta.Alias, meta.Fingerprint)) {
            fmt.Println(i18n.T("remove.cancelled"))
            return
        }
    }

    unlockMasterKey(i18n.T("auth.reason_remove", *alias))
    if err := store.RemoveRecord(*alias); err != nil { fatal(aliasError(*alias, err)) }
    fmt.Println(i18n.T("remove.done", *alias))
    if hosts, err := sshconfig.HostsBoundTo(*alias, store.PubKeysDir()); err == nil && len(hosts) > 0 {
        fmt.Println(i18n.T("remove.bound_hosts", strings.Join(hosts, ", ")))
    }
}

func cmdRekey() {
    fs := flag.NewFlagSet("rekey", flag.ExitOnError)
    fs.Parse(os.Args[2:])

    p, err := auth.GetAuthProvider(0)
    if err != nil { fatal(err) }
    rk, err := p.PrepareRekey(auth.Request{Reason: i18n.T("auth.reason_rekey")})
    if err != nil { fatal(err) }
    if p.Mode() == auth.ModeOTP {
        migrateOTPKeychain(rk.OldKey)
    }

    // 先在临时目录重新加密并校验，提交新 master key 后再替换，任何一步失败都不影响现有密钥
    n, err := store.ReencryptAll([][]byte{rk.OldKey}, rk.NewKey, rk.Commit)
    if err != nil { fatal(err) }
    fmt.Println(i18n.T("rekey.done", n))
    restartManagedAgent()
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
    if cnt > 1 { return "", errors.New(i18n.T("cli.one_passphrase_source")) }
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
