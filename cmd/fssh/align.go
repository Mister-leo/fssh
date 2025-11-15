package main

import (
    "errors"
    "flag"
    "os"
    "os/exec"
    "strings"
)

func cmdAlignSSHD() {
    fs := flag.NewFlagSet("sshd-align", flag.ExitOnError)
    host := fs.String("host", "", "target host")
    sudo := fs.Bool("sudo", false, "use sudo on remote")
    fs.Parse(os.Args[2:])
    if *host == "" { fatal(errors.New("host is required")) }
    s := ""
    if *sudo { s = "sudo " }
    script := `set -e
CFG=/etc/ssh/sshd_config
TS=$(date +%s)
` + s + `cp "$CFG" "$CFG.bak.$TS" || cp "$CFG" "$CFG.bak.$TS"
` + s + `grep -qi '^PubkeyAuthentication' "$CFG" && ` + s + `sed -i -E 's/^#?PubkeyAuthentication.*/PubkeyAuthentication yes/i' "$CFG" || echo 'PubkeyAuthentication yes' | ` + s + `tee -a "$CFG" >/dev/null
` + s + `grep -qi '^PubkeyAcceptedAlgorithms' "$CFG" && ` + s + `sed -i -E 's/^#?PubkeyAcceptedAlgorithms.*/PubkeyAcceptedAlgorithms +rsa-sha2-512,rsa-sha2-256/i' "$CFG" || echo 'PubkeyAcceptedAlgorithms +rsa-sha2-512,rsa-sha2-256' | ` + s + `tee -a "$CFG" >/dev/null
` + s + `grep -qi '^PubkeyAcceptedKeyTypes' "$CFG" && ` + s + `sed -i -E 's/^#?PubkeyAcceptedKeyTypes.*/PubkeyAcceptedKeyTypes +rsa-sha2-512,rsa-sha2-256/i' "$CFG" || echo 'PubkeyAcceptedKeyTypes +rsa-sha2-512,rsa-sha2-256' | ` + s + `tee -a "$CFG" >/dev/null
` + s + `systemctl reload sshd || ` + s + `systemctl reload ssh || ` + s + `service ssh reload || ` + s + `service sshd reload || kill -HUP $(pidof sshd) || true
`
    cmd := exec.Command("ssh", *host, "bash", "-s")
    cmd.Stdin = strings.NewReader(script)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil { fatal(err) }
}
