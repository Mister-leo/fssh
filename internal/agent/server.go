package agentserver

import (
    "crypto/x509"
    "errors"
    "fmt"
    "net"
    "os"
    "path/filepath"

    "fssh/internal/auth"
    "fssh/internal/config"
    "fssh/internal/i18n"
    "fssh/internal/log"
    "fssh/internal/prompt"
    "fssh/internal/store"
    xagent "golang.org/x/crypto/ssh/agent"
    "golang.org/x/term"
)

func defaultSocket() string {
    home, _ := os.UserHomeDir()
    return filepath.Join(home, ".fssh", "agent.sock")
}

func Start(socketPath string) error {
    return StartWithOptions(socketPath, true, 0, config.ForwardedSignPrompt)
}

func StartWithOptions(socketPath string, requireTouchPerSign bool, ttlSeconds int, forwardedPolicy string) error {
    log.Info("启动 fssh SSH 认证代理", nil)

    if socketPath == "" {
        socketPath = defaultSocket()
    }

    // 只创建一个 provider，预解锁与签名共享同一份缓存
    provider, err := auth.GetAuthProvider(ttlSeconds)
    if err != nil {
        return err
    }

    log.Info("认证模式", map[string]interface{}{
        "mode": provider.Mode(),
    })

    // OTP 模式在终端前台运行时预先解锁；由 launchd 启动时没有终端，跳过，首次签名时弹窗输入
    interactive := term.IsTerminal(int(os.Stdin.Fd()))
    if provider.Mode() == auth.ModeOTP && requireTouchPerSign && interactive {
        fmt.Println(i18n.T("agent.otp_preunlock"))
        if _, err := provider.UnlockMasterKey(auth.Request{
            Reason:   i18n.T("agent.otp_preunlock_reason"),
            Prompter: prompt.TTY{},
        }); err != nil {
            return err
        }
        fmt.Println("✓ " + i18n.T("agent.otp_preunlock_done"))
    }

    // sockaddr_un.sun_path is 104 bytes on macOS, including the final NUL
    if len(socketPath) > 103 {
        return errors.New(i18n.T("agent.err_socket_too_long", socketPath, len(socketPath)))
    }
    _ = os.Remove(socketPath)
    if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
        return err
    }
    ln, err := net.Listen("unix", socketPath)
    if err != nil {
        return err
    }

    // 签名请求来自其他终端或程序，agent 的终端不是用户正在看的地方，一律用系统弹窗
    gui := prompt.GUI{}

    var serve func(c net.Conn)
    if requireTouchPerSign {
        sa := newSecureAgent(provider, gui, forwardedPolicy)
        serve = func(c net.Conn) { _ = xagent.ServeAgent(sa.forConn(c), c) }
        log.Info("安全模式: 每次签名需要认证", map[string]interface{}{
            "ttl_seconds": ttlSeconds,
        })
    } else {
        // 便利模式：启动时解密所有私钥
        mk, err := provider.UnlockMasterKey(auth.Request{Reason: i18n.T("agent.convenience_reason")})
        if err != nil { ln.Close(); return err }
        keyring := xagent.NewKeyring()
        metas, err := store.ListMeta()
        if err != nil { ln.Close(); return err }
        for _, m := range metas {
            rec, err := store.LoadDecryptedRecord(m.Alias, mk)
            if err != nil {
                log.Warn("解密私钥失败，已跳过", map[string]interface{}{"alias": m.Alias, "error": err.Error()})
                continue
            }
            pk, err := x509.ParsePKCS8PrivateKey(rec.PKCS8DER)
            if err != nil { continue }
            _ = keyring.Add(xagent.AddedKey{PrivateKey: pk, Comment: rec.Alias})
        }
        serve = func(c net.Conn) { _ = xagent.ServeAgent(keyring, c) }
        log.Info("便利模式: 启动时解密所有私钥", nil)
    }

    go func() {
        for {
            conn, err := ln.Accept()
            if err != nil {
                return
            }
            go func(c net.Conn) {
                serve(c)
                c.Close()
            }(conn)
        }
    }()

    fmt.Println()
    fmt.Println("✓ " + i18n.T("agent.started", socketPath))
    fmt.Println(i18n.T("agent.started_hint"))
    fmt.Println()

    // Block until interrupted
    select {}
}
