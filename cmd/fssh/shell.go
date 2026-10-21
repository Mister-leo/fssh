package main

import (
    "fmt"
    "net"
    "os"
    "os/exec"
    "strconv"
    "strings"
    "syscall"

    "fssh/internal/i18n"
    "fssh/internal/sshconfig"
    "github.com/peterh/liner"
)

func runShell() {
    infos, err := sshconfig.LoadHostInfos()
    if err != nil {
        fatal(err)
    }

    // Load imported keys
    importedKeys, _ := listImportedKeys()

    // Create context with all mappings
    ctx := &ShellContext{
        infos:        infos,
        hosts:        make([]string, 0, len(infos)),
        byName:       make(map[string]sshconfig.HostInfo),
        byHostname:   make(map[string]sshconfig.HostInfo),
        ipToName:     make(map[string]string),
        idToName:     make(map[string]string),
        hostnames:    make([]string, 0, len(infos)),
        ips:          make([]string, 0, len(infos)),
        ids:          make([]string, 0, len(infos)),
        importedKeys: importedKeys,
    }

    for _, hi := range infos {
        ctx.hosts = append(ctx.hosts, hi.Name)
        ctx.byName[hi.Name] = hi
    }
    for _, hi := range infos {
        hn := displayHostname(hi)
        if hn != "" {
            ctx.byHostname[hn] = hi
            ctx.hostnames = append(ctx.hostnames, hn)
        }
    }
    for i, hi := range infos {
        id := strconv.Itoa(i + 1)
        ctx.idToName[id] = hi.Name
        ctx.ids = append(ctx.ids, id)
    }
    for _, hi := range infos {
        hn := displayHostname(hi)
        ip := resolveIPName(hn)
        if ip != "" {
            ctx.ips = append(ctx.ips, ip)
            if _, ok := ctx.ipToName[ip]; !ok {
                ctx.ipToName[ip] = hi.Name
            }
        }
    }

    commands := []string{"list", "search", "connect", "add", "edit", "delete", "show", "info", "global", "suspend", "help", "exit", "quit"}
    l := setupLiner(commands, ctx.hosts, ctx.hostnames, ctx.ips, ctx.ids)
    ctx.liner = l
    defer func() {
        if l != nil {
            l.Close()
        }
    }()

    fmt.Println(i18n.T("shell.banner"))
    for {
        line, err := l.Prompt("fssh> ")
        if err != nil {
            return
        }
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        l.AppendHistory(line)
        if line == "exit" || line == "quit" {
            return
        }
        if line == "suspend" {
            // Close liner to restore terminal
            l.Close()
            // Send SIGTSTP to suspend the process
            _ = syscall.Kill(syscall.Getpid(), syscall.SIGTSTP)
            // When resumed (SIGCONT), recreate liner
            l = setupLiner(commands, ctx.hosts, ctx.hostnames, ctx.ips, ctx.ids)
            ctx.liner = l
            continue
        }
        if line == "help" {
            fmt.Println("Commands:")
            fmt.Println("  list              - List all SSH hosts")
            fmt.Println("  search <term>     - Search hosts by name/IP")
            fmt.Println("  connect <host>    - Connect to host")
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
        if line == "list" {
            for i, hi := range ctx.infos {
                target := hi.Hostname
                if target == "" { target = hi.Name }
                ip := resolveIPName(target)
                if ip == "" { ip = "-" }
                fmt.Printf("%d\t%s(%s)\n", i+1, hi.Name, ip)
            }
            continue
        }
        if strings.HasPrefix(line, "search ") {
            term := strings.TrimSpace(line[7:])
            if term == "" {
                continue
            }
            tl := strings.ToLower(term)
            for i, hi := range ctx.infos {
                hn := hi.Hostname
                target := hn
                if target == "" { target = hi.Name }
                ip := resolveIPName(target)
                match := strings.Contains(strings.ToLower(hi.Name), tl) || (hn != "" && strings.Contains(strings.ToLower(hn), tl)) || (ip != "" && strings.Contains(strings.ToLower(ip), tl))
                if match {
                    if ip == "" { ip = "-" }
                    fmt.Printf("%d\t%s(%s)\n", i+1, hi.Name, ip)
                }
            }
            continue
        }
        if strings.HasPrefix(line, "connect ") {
            host := strings.TrimSpace(line[8:])
            if host == "" {
                continue
            }
            if name, ok := ctx.idToName[host]; ok {
                host = name
            }
            _, found := ctx.byName[host]
            if !found {
                if hi, ok := ctx.byHostname[host]; ok {
                    host = hi.Name
                    found = true
                }
            }
            if !found {
                if name, ok := ctx.ipToName[host]; ok {
                    host = name
                    found = true
                }
            }
            if !found {
                fmt.Fprintf(os.Stderr, "unknown host: %s\n", host)
                continue
            }
            l.Close()
            cmd := exec.Command("ssh", "-tt", host)
            cmd.Stdin = os.Stdin
            cmd.Stdout = os.Stdout
            cmd.Stderr = os.Stderr
            _ = cmd.Run()
            l = setupLiner(commands, ctx.hosts, ctx.hostnames, ctx.ips, ctx.ids)
            ctx.liner = l
            continue
        }
        host := line
        if name, ok := ctx.idToName[host]; ok {
            host = name
        }
        _, found := ctx.byName[host]
        if !found {
            if hi, ok := ctx.byHostname[host]; ok {
                host = hi.Name
                found = true
            }
        }
        if !found {
            if name, ok := ctx.ipToName[host]; ok {
                host = name
                found = true
            }
        }
        if !found {
            fmt.Fprintf(os.Stderr, "unknown host: %s\n", host)
            continue
        }
        l.Close()
        cmd := exec.Command("ssh", "-tt", host)
        cmd.Stdin = os.Stdin
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr
        _ = cmd.Run()
        l = setupLiner(commands, ctx.hosts, ctx.hostnames, ctx.ips, ctx.ids)
        ctx.liner = l
    }
}

func setupLiner(commands, hosts, hostnames, ips, ids []string) *liner.State {
    l := liner.NewLiner()
    l.SetCtrlCAborts(true)

    l.SetCompleter(func(line string) []string {
        line = strings.TrimSpace(line)
        var out []string
        if line == "" {
            out = append(out, commands...)
            out = append(out, hosts...)
            out = append(out, hostnames...)
            out = append(out, ips...)
            out = append(out, ids...)
            return out
        }
        // Tab completion for commands that take host arguments
        for _, cmdPrefix := range []string{"connect ", "edit ", "delete ", "show ", "info "} {
            if strings.HasPrefix(line, cmdPrefix) {
                p := strings.TrimSpace(line[len(cmdPrefix):])
                for _, h := range hosts {
                    if strings.HasPrefix(h, p) {
                        out = append(out, cmdPrefix+h)
                    }
                }
                for _, h := range hostnames {
                    if strings.HasPrefix(h, p) {
                        out = append(out, cmdPrefix+h)
                    }
                }
                for _, ip := range ips {
                    if strings.HasPrefix(ip, p) {
                        out = append(out, cmdPrefix+ip)
                    }
                }
                for _, id := range ids {
                    if strings.HasPrefix(id, p) {
                        out = append(out, cmdPrefix+id)
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
        for _, c := range commands {
            if strings.HasPrefix(c, line) {
                out = append(out, c)
            }
        }
        for _, h := range hosts {
            if strings.HasPrefix(h, line) {
                out = append(out, h)
            }
        }
        for _, h := range hostnames {
            if strings.HasPrefix(h, line) {
                out = append(out, h)
            }
        }
        for _, ip := range ips {
            if strings.HasPrefix(ip, line) {
                out = append(out, ip)
            }
        }
        for _, id := range ids {
            if strings.HasPrefix(id, line) {
                out = append(out, id)
            }
        }
        return out
    })
    return l
}

func resolveIPName(target string) string {
    if target == "" { return "" }
    ips, err := net.LookupIP(target)
    if err != nil || len(ips) == 0 { return "" }
    for _, ip := range ips {
        if ip.To4() != nil { return ip.String() }
    }
    return ips[0].String()
}

func displayHostname(hi sshconfig.HostInfo) string {
    if hi.Hostname != "" { return hi.Hostname }
    return hi.Name
}