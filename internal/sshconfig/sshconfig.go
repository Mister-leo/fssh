package sshconfig

import (
    "bufio"
    "os"
    "path/filepath"
    "sort"
    "strings"
)

// HostInfo is one Host entry. Names listed on the same Host line are merged:
// Name is the first, Aliases the rest.
type HostInfo struct {
    Name     string
    Aliases  []string
    Hostname string
    Source   string // file the Host line was found in
}

// Names returns Name followed by Aliases.
func (h HostInfo) Names() []string {
    return append([]string{h.Name}, h.Aliases...)
}

const maxIncludeDepth = 16

func LoadHosts() ([]string, error) {
    infos, err := LoadHostInfos()
    if err != nil { return nil, err }
    hosts := make([]string, 0, len(infos))
    for _, hi := range infos { hosts = append(hosts, hi.Name) }
    sort.Strings(hosts)
    return hosts, nil
}

// LoadHostInfos parses ~/.ssh/config, following Include directives.
func LoadHostInfos() ([]HostInfo, error) {
    home, err := os.UserHomeDir()
    if err != nil {
        return nil, err
    }
    p := &hostParser{
        sshDir: filepath.Join(home, ".ssh"),
        home:   home,
        byName: map[string]*HostInfo{},
        seen:   map[string]bool{},
    }
    if err := p.parseFile(filepath.Join(home, ".ssh", "config"), 0); err != nil {
        return nil, err
    }
    out := make([]HostInfo, 0, len(p.order))
    for _, hi := range p.order {
        out = append(out, *hi)
    }
    sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
    return out, nil
}

// FindHost returns the entry whose Name or Aliases contain name.
func FindHost(name string) (HostInfo, bool, error) {
    infos, err := LoadHostInfos()
    if err != nil {
        return HostInfo{}, false, err
    }
    for _, hi := range infos {
        for _, n := range hi.Names() {
            if n == name {
                return hi, true, nil
            }
        }
    }
    return HostInfo{}, false, nil
}

type hostParser struct {
    sshDir, home string
    byName       map[string]*HostInfo
    order        []*HostInfo
    seen         map[string]bool // include loop protection
}

func (p *hostParser) parseFile(path string, depth int) error {
    if depth > maxIncludeDepth || p.seen[path] {
        return nil
    }
    p.seen[path] = true
    f, err := os.Open(path)
    if err != nil {
        if os.IsNotExist(err) {
            return nil
        }
        // Unreadable included files are skipped, like ssh does for globs.
        if depth > 0 {
            return nil
        }
        return err
    }
    defer f.Close()

    var current *HostInfo // nil inside Match blocks or wildcard-only Host lines
    s := bufio.NewScanner(f)
    for s.Scan() {
        line := strings.TrimSpace(s.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        k, v := parseKV(line)
        switch k {
        case "include":
            for _, pattern := range strings.Fields(v) {
                for _, inc := range p.expandInclude(pattern) {
                    if err := p.parseFile(inc, depth+1); err != nil {
                        return err
                    }
                }
            }
        case "match":
            current = nil
        case "host":
            current = nil
            var names []string
            for _, h := range strings.Fields(v) {
                if strings.ContainsAny(h, "*?!") {
                    continue
                }
                if _, dup := p.byName[h]; dup {
                    continue // first definition wins, as in ssh
                }
                names = append(names, h)
            }
            if len(names) == 0 {
                continue
            }
            current = &HostInfo{Name: names[0], Aliases: names[1:], Source: path}
            for _, n := range names {
                p.byName[n] = current
            }
            p.order = append(p.order, current)
        case "hostname":
            if current != nil && current.Hostname == "" {
                current.Hostname = v
            }
        }
    }
    return s.Err()
}

// expandInclude resolves an Include argument: "~" expands to home, relative
// paths are relative to ~/.ssh, and glob patterns are expanded in order.
func (p *hostParser) expandInclude(pattern string) []string {
    if strings.HasPrefix(pattern, "~/") {
        pattern = filepath.Join(p.home, pattern[2:])
    } else if !filepath.IsAbs(pattern) {
        pattern = filepath.Join(p.sshDir, pattern)
    }
    matches, err := filepath.Glob(pattern)
    if err != nil {
        return nil
    }
    sort.Strings(matches)
    return matches
}

// LoadHostConfigs loads all hosts with complete configuration
// This is a wrapper around LoadAllHostConfigs from writer.go
func LoadHostConfigs() (map[string]*HostConfig, error) {
	return LoadAllHostConfigs()
}

// parseKV splits "Key Value", "Key=Value" and "Key = Value" like ssh does:
// the key ends at the first whitespace or '=', and one optional '=' may
// follow. A '=' inside the value (e.g. "ProxyCommand ... -o A=b") is kept.
func parseKV(line string) (string, string) {
    line = strings.TrimSpace(line)
    i := strings.IndexAny(line, " \t=")
    if i < 0 {
        return strings.ToLower(line), ""
    }
    k := strings.ToLower(line[:i])
    rest := strings.TrimLeft(line[i:], " \t")
    if strings.HasPrefix(rest, "=") {
        rest = strings.TrimLeft(rest[1:], " \t")
    }
    return k, strings.TrimSpace(rest)
}
