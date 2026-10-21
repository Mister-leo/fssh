package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fssh/internal/i18n"
	"fssh/internal/keychain"
	"fssh/internal/otp"
	"fssh/internal/prompt"
	"fssh/internal/sshconfig"
	"fssh/internal/store"
)

// cmdUninstall undoes what the wizard set up. Keys and the master key are
// kept unless --purge is given, so reinstalling restores everything.
func cmdUninstall() {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "also delete all keys (~/.fssh) and the master key")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	fs.Parse(os.Args[2:])

	if !*yes && !isTTY() {
		fatal(errors.New(i18n.T("remove.err_need_yes")))
	}
	fmt.Println(i18n.T("uninstall.plan"))
	if *purge {
		fmt.Println(i18n.T("uninstall.plan_purge"))
	}
	fmt.Println()
	if !*yes && !otp.PromptConfirm(i18n.T("uninstall.confirm")) {
		fmt.Println(i18n.T("remove.cancelled"))
		return
	}
	if *purge && !*yes && !confirmPurge() {
		fmt.Println(i18n.T("remove.cancelled"))
		return
	}

	sock := agentSocket()

	// 1. auto-start: stop the managed agent and remove its plist
	if _, err := os.Stat(launchAgentPlist()); err == nil {
		target := fmt.Sprintf("gui/%d/%s", os.Getuid(), plistLabel)
		_ = exec.Command("launchctl", "bootout", target).Run()
		if err := os.Remove(launchAgentPlist()); err != nil {
			fmt.Fprintln(os.Stderr, "⚠️  "+err.Error())
		} else {
			fmt.Println("✓ " + i18n.T("uninstall.launchd_removed"))
		}
	}

	// 2. ssh config: the managed Host * block and per-host bindings
	if removed, err := sshconfig.RemoveAgentBlock(); err != nil {
		fmt.Fprintln(os.Stderr, "⚠️  "+err.Error())
	} else if removed {
		fmt.Println("✓ " + i18n.T("uninstall.sshconfig_block"))
	}
	if hosts, err := sshconfig.RemoveFsshSettings(store.PubKeysDir(), sock); err != nil {
		fmt.Fprintln(os.Stderr, "⚠️  "+err.Error())
	} else if len(hosts) > 0 {
		fmt.Println("✓ " + i18n.T("uninstall.sshconfig_hosts", strings.Join(hosts, ", ")))
	}

	// 3. shell startup files
	for _, rc := range allShellRCFiles() {
		if removed, err := removeShellEnv(rc); err != nil {
			fmt.Fprintln(os.Stderr, "⚠️  "+err.Error())
		} else if removed {
			fmt.Println("✓ " + i18n.T("uninstall.shellenv", tildify(rc)))
		}
	}
	os.Remove(sock)

	// 4. data
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".fssh")
	if *purge {
		keychain.DeleteMasterKey()
		if err := os.RemoveAll(dataDir); err != nil {
			fmt.Fprintln(os.Stderr, "⚠️  "+err.Error())
		} else {
			fmt.Println("✓ " + i18n.T("uninstall.purged", tildify(dataDir)))
		}
	} else {
		fmt.Println(i18n.T("uninstall.kept", tildify(dataDir)))
	}

	// 5. the binary itself
	fmt.Println()
	exe, _ := os.Executable()
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if strings.Contains(exe, "/Cellar/") {
		fmt.Println(i18n.T("uninstall.binary_brew"))
	} else {
		fmt.Println(i18n.T("uninstall.binary", exe))
	}
}

// confirmPurge offers a backup and asks the user to type DELETE.
func confirmPurge() bool {
	if metas, _ := store.ListMeta(); len(metas) > 0 {
		fmt.Println(i18n.T("uninstall.purge_warning", len(metas)))
		if otp.PromptConfirm(i18n.T("reset.offer_backup")) {
			runBackup(defaultBackupPath())
		}
	}
	answer, err := prompt.TTY{}.Text(i18n.T("reset.confirm"))
	return err == nil && strings.TrimSpace(answer) == "DELETE"
}
