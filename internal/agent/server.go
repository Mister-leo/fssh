package agentserver

import (
    "crypto/x509"
    "fmt"
    "net"
    "os"
    "path/filepath"

    "fssh/internal/keychain"
    "fssh/internal/store"
    xagent "golang.org/x/crypto/ssh/agent"
)

func defaultSocket() string {
    home, _ := os.UserHomeDir()
    return filepath.Join(home, ".fssh", "agent.sock")
}

func Start(socketPath string) error { return StartWithOptions(socketPath, true, 0) }

func StartWithOptions(socketPath string, requireTouchPerSign bool, ttlSeconds int) error {
    if socketPath == "" {
        socketPath = defaultSocket()
    }
    _ = os.Remove(socketPath)
    if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
        return err
    }
    ln, err := net.Listen("unix", socketPath)
    if err != nil {
        return err
    }

    var ag xagent.Agent
    if requireTouchPerSign {
        sa, err := newSecureAgentWithTTL(ttlSeconds)
        if err != nil { ln.Close(); return err }
        ag = sa
    } else {
        mk, err := keychain.LoadMasterKey()
        if err != nil { ln.Close(); return err }
        keyring := xagent.NewKeyring()
        dir := store.KeysDir()
        entries, err := os.ReadDir(dir)
        if err == nil {
            for _, e := range entries {
                if e.IsDir() || filepath.Ext(e.Name()) != ".enc" { continue }
                alias := e.Name()[:len(e.Name())-4]
                rec, err := store.LoadDecryptedRecord(alias, mk)
                if err != nil { continue }
                pk, err := x509.ParsePKCS8PrivateKey(rec.PKCS8DER)
                if err != nil { continue }
                _ = keyring.Add(xagent.AddedKey{PrivateKey: pk, Comment: rec.Alias})
            }
        }
        ag = keyring
    }

    go func() {
        for {
            conn, err := ln.Accept()
            if err != nil {
                return
            }
            go func(c net.Conn) {
                _ = xagent.ServeAgent(ag, c)
                c.Close()
            }(conn)
        }
    }()

    fmt.Println("SSH_AUTH_SOCK=", socketPath)
    // Block until interrupted; for CLI we can keep running.
    select {}
}