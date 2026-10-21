package main

import (
    "context"
    "errors"
    "fmt"
    "net"
    "os"
    "os/exec"
    "strings"
    "sync"
    "syscall"
    "time"

    "fssh/internal/i18n"
    "fssh/internal/sshconfig"
    "github.com/peterh/liner"
)

var shellCommands = []string{"list", "search", "connect", "add", "edit", "delete", "show", "info", "global", "suspend", "help", "exit", "quit"}

func runShell() {
    ctx := &ShellContext{}
    if err := reloadHosts(ctx); err != nil {
        fatal(err)
    }

    l := setupLiner(ctx)
    ctx.liner = l
    defer func() {
        if ctx.liner != nil {
            ctx.liner.Close()
        }
    }()

    fmt.Println(i18n.T("shell.banner"))
    for {
        line, err := ctx.liner.Prompt("fssh> ")
        if err != nil {
            return
        }
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        ctx.liner.AppendHistory(line)
        if line == "exit" || line == "quit" {
            return
        }
        if line == "suspend" {
            // Close liner to restore terminal
            ctx.liner.Close()
            // Send SIGTSTP to suspend the process
            _ = syscall.Kill(syscall.Getpid(), syscall.SIGTSTP)
            // When resumed (SIGCONT), recreate liner
            ctx.liner = setupLiner(ctx)
            continue
        }
        if line == "help" {
            fmt.Println("Commands:")
            fmt.Println("  list [-r]         - List all SSH hosts (-r: resolve IP addresses)")
            fmt.Println("  search <term>     - Search hosts by name/alias/hostname")
            fmt.Println("  connect <host> [ssh args] - Connect to host; unknown hosts and extra")
            fmt.Println("                      arguments are passed to ssh (e.g. connect me@1.2.3.4 -p 2222)")
            fmt.Println("  add               - Add new SSH host")
            fmt.Println("  edit <host>       - Edit existing host")
            fmt.Println("  delete <host>     - Delete host")
            fmt.Println("  show <host>       - Show host details")
            fmt.Println("  info <id|alias|hostname|ip> - Show host info by any identifier")
            fmt.Println("  global [show|edit|set|unset] - Manage global SSH config (Host *)")
            fmt.Println("    global show           - Display current global config")
            fmt.Println("    global edit           - Edit global config interactively")
            fmt.Println("    global set <key> <value> - Set a single option")
            fmt.Println("    global unset <key>    - Remove a single option")
            fmt.Println("  suspend           - Suspend fssh (use 'fg' to resume)")
            fmt.Println("  help              - Show this help")
            fmt.Println("  exit / quit       - Exit shell")
            fmt.Println()
            fmt.Println("Shortcuts: Type host name directly to connect")
            continue
        }
        if line == "add" {
            if err := cmdAdd(ctx); err != nil {
                fmt.Fprintf(os.Stderr, "Error: %v\n", err)
            }
            continue
        }
        if strings.HasPrefix(line, "edit ") {
            args := strings.TrimSpace(line[5:])
            if err := cmdEdit(ctx, args); err != nil {
                fmt.Fprintf(os.Stderr, "Error: %v\n", err)
            }
            continue
        }
        if strings.HasPrefix(line, "delete ") {
            args := strings.TrimSpace(line[7:])
            if err := cmdDelete(ctx, args); err != nil {
                fmt.Fprintf(os.Stderr, "Error: %v\n", err)
            }
            continue
        }
        if strings.HasPrefix(line, "show ") {
            args := strings.TrimSpace(line[5:])
            if err := cmdShow(ctx, args); err != nil {
                fmt.Fprintf(os.Stderr, "Error: %v\n", err)
            }
            continue
        }
        if strings.HasPrefix(line, "info ") {
            args := strings.TrimSpace(line[5:])
            if err := cmdInfo(ctx, args); err != nil {
                fmt.Fprintf(os.Stderr, "Error: %v\n", err)
            }
            continue
        }
        if strings.HasPrefix(line, "global") {
            args := ""
            if len(line) > 6 {
                args = strings.TrimSpace(line[6:])
            }
            if err := cmdGlobal(ctx, args); err != nil {
                fmt.Fprintf(os.Stderr, "Error: %v\n", err)
            }
            continue
        }
        if line == "list" || line == "list -r" || line == "list --resolve" {
            printHosts(ctx, ctx.infos, line != "list")
            continue
        }
        if strings.HasPrefix(line, "search ") {
            term := strings.ToLower(strings.TrimSpace(line[7:]))
            if term == "" {
                continue
            }
            var matches []sshconfig.HostInfo
            for _, hi := range ctx.infos {
                hay := strings.ToLower(strings.Join(append(hi.Names(), hi.Hostname), " "))
                if strings.Contains(hay, term) {
                    matches = append(matches, hi)
                }
            }
            printHosts(ctx, matches, false)
            continue
        }
        if strings.HasPrefix(line, "connect ") {
            args, err := splitArgs(strings.TrimSpace(line[8:]))
            if err != nil {
                fmt.Fprintf(os.Stderr, "Error: %v\n", err)
                continue
            }
            if len(args) == 0 {
                continue
            }
            // Known hosts may be given by id, alias, hostname or IP; anything
            // else is handed to ssh unchanged (user@host, extra options).
            if name := resolveHostQuery(ctx, args[0]); name != "" {
                args[0] = name
            }
            runSSH(ctx, args)
            continue
        }
        host := resolveHostQuery(ctx, line)
        if host == "" {
            fmt.Fprintf(os.Stderr, "unknown host: %s (use `connect %s` to pass it to ssh directly)\n", line, line)
            continue
        }
        runSSH(ctx, []string{host})
    }
}

// runSSH hands the terminal to ssh and reports a failing exit status.
func runSSH(ctx *ShellContext, args []string) {
    ctx.liner.Close()
    cmd := exec.Command("ssh", append([]string{"-tt"}, args...)...)
    cmd.Stdin = os.Stdin
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    err := cmd.Run()
    ctx.liner = setupLiner(ctx)

    var ee *exec.ExitError
    switch {
    case errors.As(err, &ee):
        fmt.Fprintf(os.Stderr, "ssh exited with status %d\n", ee.ExitCode())
    case err != nil:
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
    }
}

// printHosts lists hosts as "id  name (aliases)  hostname  [key]".
func printHosts(ctx *ShellContext, infos []sshconfig.HostInfo, resolve bool) {
    var ips []string
    if resolve {
        ips = resolveAll(infos)
    }
    for i, hi := range infos {
        name := hi.Name
        if len(hi.Aliases) > 0 {
            name += " (" + strings.Join(hi.Aliases, ", ") + ")"
        }
        line := fmt.Sprintf("%s\t%s\t%s", ctx.idOf[hi.Name], name, displayHostname(hi))
        if resolve {
            line += "\t" + ips[i]
        }
        if key := ctx.boundKey[hi.Name]; key != "" {
            line += "\t[key: " + key + "]"
        }
        fmt.Println(line)
    }
}

// resolveAll looks up every host concurrently with a short timeout.
func resolveAll(infos []sshconfig.HostInfo) []string {
    out := make([]string, len(infos))
    var wg sync.WaitGroup
    for i, hi := range infos {
        wg.Add(1)
        go func(i int, host string) {
            defer wg.Done()
            ip, fake := lookupIP(host, 500*time.Millisecond)
            switch {
            case fake:
                out[i] = "(proxy fake-ip)"
            case ip == "":
                out[i] = "-"
            default:
                out[i] = ip
            }
        }(i, displayHostname(hi))
    }
    wg.Wait()
    return out
}

// fakeIPNet is the benchmark range 198.18.0.0/15, which proxy tools (Clash,
// Surge, ...) hand out in "fake-ip" mode; such addresses are not the server's.
var fakeIPNet = &net.IPNet{IP: net.IPv4(198, 18, 0, 0).To4(), Mask: net.CIDRMask(15, 32)}

// lookupIP resolves host, preferring IPv4. fake reports that only proxy
// fake-ip addresses came back.
func lookupIP(host string, timeout time.Duration) (ip string, fake bool) {
    if host == "" {
        return "", false
    }
    if net.ParseIP(host) != nil {
        return host, false
    }
    c, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    addrs, err := net.DefaultResolver.LookupIPAddr(c, host)
    if err != nil {
        return "", false
    }
    var v6 string
    for _, a := range addrs {
        if fakeIPNet.Contains(a.IP) {
            fake = true
            continue
        }
        if v4 := a.IP.To4(); v4 != nil {
            return v4.String(), false
        }
        if v6 == "" {
            v6 = a.IP.String()
        }
    }
    if v6 != "" {
        return v6, false
    }
    return "", fake
}

// splitArgs splits a command line like a shell: whitespace separates
// arguments, single and double quotes group, backslash escapes.
func splitArgs(s string) ([]string, error) {
    var args []string
    var cur strings.Builder
    inArg, escaped := false, false
    var quote rune
    for _, r := range s {
        switch {
        case escaped:
            cur.WriteRune(r)
            escaped = false
        case r == '\\' && quote != '\'':
            escaped, inArg = true, true
        case quote != 0:
            if r == quote {
                quote = 0
            } else {
                cur.WriteRune(r)
            }
        case r == '\'' || r == '"':
            quote, inArg = r, true
        case r == ' ' || r == '\t':
            if inArg {
                args = append(args, cur.String())
                cur.Reset()
                inArg = false
            }
        default:
            cur.WriteRune(r)
            inArg = true
        }
    }
    if quote != 0 || escaped {
        return nil, errors.New("unterminated quote or escape")
    }
    if inArg {
        args = append(args, cur.String())
    }
    return args, nil
}

// setupLiner creates the line editor. The completer reads ctx at completion
// time, so hosts added during the session complete too.
func setupLiner(ctx *ShellContext) *liner.State {
    l := liner.NewLiner()
    l.SetCtrlCAborts(true)

    l.SetCompleter(func(line string) []string {
        line = strings.TrimSpace(line)
        candidates := append(append(append([]string{}, ctx.hosts...), ctx.hostnames...), ctx.ids...)
        candidates = append(candidates, ctx.ips...)
        var out []string
        if line == "" {
            return append(append([]string{}, shellCommands...), candidates...)
        }
        // Tab completion for commands that take host arguments
        for _, cmdPrefix := range []string{"connect ", "edit ", "delete ", "show ", "info "} {
            if strings.HasPrefix(line, cmdPrefix) {
                p := strings.TrimSpace(line[len(cmdPrefix):])
                for _, c := range candidates {
                    if strings.HasPrefix(c, p) {
                        out = append(out, cmdPrefix+c)
                    }
                }
                return out
            }
        }
        // Tab completion for global subcommands
        if strings.HasPrefix(line, "global ") {
            subCmd := strings.TrimSpace(line[7:])
            globalSubCmds := []string{"show", "edit", "set", "unset"}

            // Complete subcommand
            if !strings.Contains(subCmd, " ") {
                for _, sc := range globalSubCmds {
                    if strings.HasPrefix(sc, subCmd) {
                        out = append(out, "global "+sc)
                    }
                }
                return out
            }

            // Complete option names for "global set" and "global unset"
            if strings.HasPrefix(subCmd, "set ") || strings.HasPrefix(subCmd, "unset ") {
                var prefix string
                if strings.HasPrefix(subCmd, "set ") {
                    prefix = strings.TrimSpace(subCmd[4:])
                } else {
                    prefix = strings.TrimSpace(subCmd[6:])
                }

                // Only complete key name (before space)
                if !strings.Contains(prefix, " ") {
                    optionNames := sshconfig.GetGlobalOptionNames()
                    for _, opt := range optionNames {
                        if strings.HasPrefix(strings.ToLower(opt), strings.ToLower(prefix)) {
                            if strings.HasPrefix(subCmd, "set ") {
                                out = append(out, "global set "+opt)
                            } else {
                                out = append(out, "global unset "+opt)
                            }
                        }
                    }
                    return out
                }
            }

            return out
        }
        for _, c := range append(append([]string{}, shellCommands...), candidates...) {
            if strings.HasPrefix(c, line) {
                out = append(out, c)
            }
        }
        return out
    })
    return l
}

func displayHostname(hi sshconfig.HostInfo) string {
    if hi.Hostname != "" { return hi.Hostname }
    return hi.Name
}
