# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

fssh is a macOS SSH private key manager and SSH agent. Private keys are stored encrypted under a master key; each signature is unlocked with Touch ID (master key in the Keychain) or OTP (password + TOTP; master key derived from an encrypted seed). It also ships an interactive shell for the hosts in `~/.ssh/config`.

Open problems and their status are tracked in `docs/known-issues.md`; fix designs are in `docs/fix-plan.md`. Tick an item there when it is fixed and add newly found problems to it.

## Build and Development Commands

```bash
go build ./cmd/fssh          # writes ./fssh (git-ignored; never commit it)
go vet ./...
go test -race ./...

# Release build as CI does it (CGO is required: Touch ID + Keychain)
CGO_ENABLED=1 GOARCH=arm64 go build -ldflags "-X main.version=v1.2.3" ./cmd/fssh
```

### Testing rules

- **Never call the Keychain while `HOME` points at a temp dir.** macOS looks for the login keychain under `$HOME/Library/Keychains` and shows a "Keychain Not Found" dialog on the user's screen. Tests that use a fake HOME must avoid Keychain paths: write `~/.fssh/auth_mode.json` with mode `otp` first (see `cmd/fssh/m3_test.go: fakeHome`), or stub the call (`deleteMasterKey` in `cmd/fssh/mode.go`).
- Keychain tests are opt-in: `FSSH_KEYCHAIN_TESTS=1 go test ./cmd/fssh -run Keychain`. They use `FSSH_KEYCHAIN_SERVICE` to isolate the item name and symlink the real `~/Library` into the temp HOME.
- `FSSH_KEYCHAIN_SERVICE=<name>` isolates manual runs from the real master key.
- `ssh` reads config from the passwd home, not `$HOME`; use `ssh -F <file> -G <host>` to inspect a test config.
- Unix socket paths are limited to 103 bytes; use a short `--socket` in temp dirs.
- OTP codes are single-use (replay guard in `~/.fssh/otp/last_counter`); tests that need several codes per 30 s window set `p.counters = nopCounters{}`.

## Architecture

### Authentication (`internal/auth`)

`AuthProvider` (auth.go) is the only way to obtain the master key:

```go
UnlockMasterKey(req Request) ([]byte, error)   // Request{Reason, NoCache, Prompter}
PrepareRekey(req Request) (*Rekey, error)        // OldKey, NewKey, Commit()
IsAvailable() bool; Mode() AuthMode; ClearCache()
```

- `Reason` is shown in the prompt (which process / key / host).
- `NoCache` forces authentication and skips the TTL cache (forwarded agent requests, rekey, mode switch).
- Both providers hold a mutex across the whole prompt, so concurrent signatures show one prompt.
- `touchid.go`: Keychain master key + `macos.RequireBiometry(reason)`; falls back to the login password when biometry is unavailable (`macos.BiometryAvailable`).
- `otp.go`: password decrypts the seed (seed cache = `seed_unlock_ttl_seconds`), then a TOTP code (master key cache = `unlock_ttl_seconds`). Config is re-read on every authentication so rekey / password changes apply without restarting the agent.
- Commands must never call `keychain.LoadMasterKey` directly; use `unlockMasterKey(reason)` in `cmd/fssh/unlock.go` (it also migrates the master key copy old versions stored in the Keychain in OTP mode).

### Prompts (`internal/prompt`)

`Prompter` = `Password`, `Text`, `Notify`. `TTY` for commands; `GUI` (osascript dialogs/notifications, text passed as script arguments — never interpolate into AppleScript) for the agent, whose terminal is not where the user is.

### OTP (`internal/otp`)

- Seed (20 bytes) encrypted with PBKDF2-SHA256 (100k iterations) + AES-256-GCM. Master key = HKDF-SHA256(seed, master_key_salt, "fssh-master-key-v1") — `otp.MasterKey`.
- Secret shown as Base32 + `otpauth://` URI (`seed.go`).
- Recovery codes: each code encrypts its own copy of the seed (`recovery_wrapped`); `recovery_codes_hash` only locates the copy. Configs with hashes but no wrapped copies are legacy (`LegacyRecovery`).
- `NewConfig` builds a config in memory; callers verify a code before `SaveConfig`.

### Storage (`internal/store`)

- `~/.fssh/keys/<alias>.enc`: JSON, PKCS#8 DER encrypted with AES-256-GCM under HKDF(master, per-file salt, alias), fingerprint as AAD.
- `~/.fssh/pubkeys/<alias>.pub`: authorized_keys line, written on save, backfilled by `SyncPubKeys`; used by `fssh bind` (IdentityFile + IdentitiesOnly).
- `ReencryptAll(oldKeys, newKey, commit)`: stage in `keys.new`, verify, run `commit` (persist the new master key), then swap directories. Used by rekey, mode switch and the OTP Keychain migration. Any failure before commit leaves everything untouched.
- `ValidateAlias` for new aliases; `RecordPath`/`checkAliasPath` block path traversal for existing ones.
- `backup.go`: scrypt + AES-256-GCM backup of all decrypted records (`fssh backup/restore`).
- `ExportOpenSSH`; encrypted PKCS#8 export is intentionally unsupported.

### SSH Agent (`internal/agent`)

- `server.go`: one provider shared by pre-unlock and signing; per-connection `connAgent` via `secureAgent.forConn`.
- `peer.go`: requesting process via `LOCAL_PEERPID` + `kern.procargs2`.
- `sessionbind.go`: `session-bind@openssh.com` (verified host-key signature) gives the destination host (looked up in known_hosts) and the forwarding flag.
- Forwarded requests always use `NoCache`; `forwarded_sign: deny` refuses them.
- Every signature is appended to `~/.fssh/audit.log` (`internal/audit`, shown by `fssh log`).
- `ssh-add -x/-X` lock/unlock; `-D` clears the unlock cache (keys stay in the store); Add/Remove are refused.
- Convenience mode (`require_touch_id_per_sign: false`) uses `agent.NewKeyring` with all keys decrypted at start.

### ssh config (`internal/sshconfig`)

- `LoadHostInfos` follows `Include` (relative to `~/.ssh`, `~`, globs, loop-safe), merges aliases on one `Host` line, treats `Match` as a block boundary.
- Writers only edit `~/.ssh/config`, never included files (`ErrDefinedElsewhere`).
- `WriteHostConfig` keeps the original Host line and every directive HostConfig does not model (`mergePreserved`).
- `SetIdentity` / `ClearIdentity` / `RemoveFsshSettings` edit identity lines only.
- fssh's global block is wrapped in `# >>> fssh managed >>>` / `# <<< fssh managed <<<` (`EnsureAgentBlock`, `RemoveAgentBlock`; legacy `# fssh agent configuration` blocks are recognised). `AgentCoverage` tells global vs per-host use.
- Each write backs up to `config.bak.<unix>`, keeping the newest 5.

### CLI (`cmd/fssh`)

| File | Contents |
|---|---|
| `main.go` | dispatch, help/version, init entry, import/export/remove/agent/rekey |
| `setup*.go` | `fssh init` wizard (steps come from one list) |
| `mode.go` | init per mode, `fssh mode switch`, start over (`resetStore`) |
| `keys_cmd.go` | list, pubkey, keygen, bind/unbind, original key file handling |
| `keyimport.go` | passphrase prompting/retry, friendly key errors |
| `backup_cmd.go`, `uninstall.go`, `shellenv.go`, `doctor.go` (status + doctor), `log_cmd.go`, `otp_cmd.go` | one feature each |
| `shell.go`, `shell_commands.go` | interactive shell |
| `table.go` | display-width aware tables (CJK) |

Adding a command: add it to `commandNames` and the `main()` switch, add `cmd.<name>` to the messages (a test enforces it).

### i18n (`internal/i18n`)

All user-facing text is bilingual: `i18n.T("key", args...)`, messages in `messages.go`. `TestMessagesComplete` requires both languages with the same format verbs in the same order. Language: `FSSH_LANG` > config `language` > `LC_ALL`/`LC_MESSAGES`/`LANG` > macOS `AppleLanguages`. Pass already-formatted text to `errors.New`, not `fmt.Errorf`. Log messages and low-level technical errors stay English/Chinese as written.

## File Storage

```
~/.fssh/
├── config.json        # user config
├── auth_mode.json     # touchid | otp (0600)
├── keys/*.enc         # encrypted private keys
├── pubkeys/*.pub      # public keys for IdentityFile
├── audit.log          # signature requests (JSON lines, 0600)
├── agent.sock
└── otp/
    ├── config.enc     # encrypted seed, recovery copies, TOTP settings
    └── last_counter   # last accepted TOTP step (replay guard)
~/Library/LaunchAgents/com.fssh.agent.plist   # logs to ~/Library/Logs/fssh/agent.log
```

## Distribution

- CI (`.github/workflows/build.yml`) runs on macOS with CGO, tests with `-race`, builds a universal binary; tags `v*` create a release.
- `contrib/install.sh` installs a release (sha256 check, removes quarantine); `contrib/homebrew/fssh.rb` is the tap formula (builds from source).
- Binaries are not Apple-signed (decision recorded in `docs/fix-plan.md`); Keychain may ask again after upgrades.

## Security Considerations

- Never log master keys, seeds, passwords, recovery codes or decrypted keys.
- Files under `~/.fssh` are 0600, directories 0700.
- OTP's second factor is a local check: password + `~/.fssh` suffice to derive the master key. Document, do not overstate.
- Re-encryption must go through `store.ReencryptAll` so failures never strand keys.
