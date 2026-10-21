# fssh — SSH key manager for macOS, unlocked by Touch ID or OTP

[中文文档](README_CN.md)

![Touch ID Fingerprint](images/finger.png)

## What is fssh?

fssh keeps your SSH private keys encrypted and acts as your SSH agent. Instead of plaintext key files or passphrases, every signature is unlocked with Touch ID (or your macOS login password), or with a password plus an authenticator code (OTP mode).

- **No plaintext keys on disk** — keys are encrypted with AES-256-GCM; `fssh keygen` creates new keys that never touch the disk unencrypted
- **Know who is asking** — the unlock prompt shows which program wants which key for which server, and warns about forwarded (`ssh -A`) requests
- **The right key for each host** — `fssh bind github.com work` makes a host use exactly one key
- **Interactive shell** — browse, search and connect to the hosts in `~/.ssh/config`, with Tab completion
- **Self-check** — `fssh doctor` finds setup problems and tells you how to fix them

```
┌─────────────┐     ┌──────────────────────┐     ┌──────────────┐
│ ssh / git   │ ──▶ │ fssh agent           │ ──▶ │ remote server│
└─────────────┘     │ Touch ID / OTP prompt│     └──────────────┘
                    │ decrypts one key     │
                    └──────────────────────┘
```

**Interactive shell:**

![Interactive Shell](images/shell.png)

---

## Install

fssh supports macOS on Apple Silicon and Intel.

**Homebrew** (builds from source):

```bash
brew tap Mister-leo/fssh
brew install fssh
```

**Install script** (release binary; verifies the checksum and removes the download quarantine):

```bash
curl -fsSL https://raw.githubusercontent.com/Mister-leo/fssh/main/contrib/install.sh | sh
```

**From source** (Go 1.21+, Xcode command line tools):

```bash
go build -o fssh ./cmd/fssh
sudo install -m 755 fssh /usr/local/bin/fssh
```

The release binary is not signed by Apple. The install script and Homebrew avoid Gatekeeper; for a manual download run `xattr -d com.apple.quarantine fssh` first.

## Quick start

```bash
fssh init      # setup wizard
fssh doctor    # check everything is connected
ssh my-server  # Touch ID / OTP prompt appears
```

The wizard walks through:

1. **Authentication** — Touch ID (recommended; Macs without a usable sensor get the login-password prompt instead) or OTP
2. **Install** fssh to `/usr/local/bin` (skipped for Homebrew installs)
3. **Import keys** from `~/.ssh`, then archive the plaintext originals to `~/.ssh/fssh-archive/` (or delete / keep them)
4. **Auto-start** the agent at login (LaunchAgent)
5. **Start** the agent
6. **Configure ssh** — a marked block at the top of `~/.ssh/config` makes every host use the fssh agent
7. **Shell environment** (optional) — exports `SSH_AUTH_SOCK` for `ssh-add` and tools that ignore `~/.ssh/config`

Running `fssh init` again offers to keep the setup, switch the auth mode (keeping all keys), or start over.

## Everyday use

### Unlocking

Use `ssh`, `git`, `scp` as usual. After you authenticate, the agent caches the unlock for `unlock_ttl_seconds` (default 600), so a burst of connections — or Ansible against 50 hosts — needs only one prompt. Set it to `0` to authenticate every signature.

The prompt says who is asking, e.g. *"git → ssh wants to use key "work" to log in to github.com"*. Requests arriving through agent forwarding (`ssh -A`) are flagged and **always** ask, ignoring the cache; set `"forwarded_sign": "deny"` to refuse them outright. `fssh log` lists recent signature requests.

### Several keys

Without a binding, ssh offers every key in the agent to every server: you may push with the wrong GitHub account, and servers reject you after ~6 keys ("Too many authentication failures"). Bind hosts to keys:

```bash
fssh bind github.com work        # adds IdentityFile ~/.fssh/pubkeys/work.pub + IdentitiesOnly yes
fssh bind gitlab.com personal
fssh list                        # shows which hosts use which key
fssh unbind gitlab.com
```

### New keys

```bash
fssh keygen deploy                  # ed25519; --type ecdsa|rsa, --bits 4096
fssh pubkey deploy --copy           # public key to the clipboard
```

### Interactive shell

Run `fssh` (or `fssh shell`):

```
fssh> list                       # all hosts (follows Include, merges aliases)
fssh> list -r                    # with resolved IPs (proxy fake-ip addresses are hidden)
fssh> search prod
fssh> web1                       # connect by name, alias, number, hostname or IP
fssh> connect me@10.0.0.9 -p 2222   # anything ssh accepts
fssh> show web1                  # details, including the bound fssh key
fssh> add / edit web1 / delete web1
fssh> global show                # the Host * block
```

`edit` keeps every option it does not manage (LocalForward, SetEnv, comments, extra aliases). Hosts defined in `Include`d files are shown but not edited.

## Commands

| Command | Description |
|---|---|
| `fssh init` | Setup wizard (`--mode touchid\|otp` for non-interactive, `--force` to start over) |
| `fssh import --alias A --file F` | Import a private key; asks for its passphrase; `--original archive\|delete\|keep` |
| `fssh keygen A` | Generate a key directly into encrypted storage |
| `fssh list [--json]` | List keys with type, fingerprint and bound hosts |
| `fssh pubkey A [--copy]` | Print a public key |
| `fssh bind HOST A` / `fssh unbind HOST` | Pin a host to one key |
| `fssh export --alias A --out F` | Export in OpenSSH format (`--ask-passphrase` to encrypt; `--format pkcs8` for unencrypted PKCS#8) |
| `fssh remove --alias A` | Delete a key (asks for confirmation; `--yes` in scripts) |
| `fssh backup [--out F]` / `fssh restore F` | Encrypted backup of all keys, restorable on another Mac or auth mode |
| `fssh rekey` | Rotate the master key (keys are re-encrypted atomically) |
| `fssh mode switch touchid\|otp` | Change the auth mode, keeping every key |
| `fssh status` | Overview: mode, keys, agent, auto-start, ssh config |
| `fssh doctor` | Find problems and print the fix |
| `fssh agent` | Run the agent in the foreground |
| `fssh log [-n N]` | Recent signature requests (who, which key, which host, result) |
| `fssh otp recover\|change-password\|regen-recovery\|show-secret` | OTP maintenance |
| `fssh shell` | Interactive host manager (default when run without arguments) |
| `fssh uninstall [--purge]` | Remove fssh from ssh config, auto-start and shell files |
| `fssh help [command]`, `fssh version` | Help and version |

## Configuration

`~/.fssh/config.json` (all fields optional):

```json
{
  "socket": "~/.fssh/agent.sock",
  "require_touch_id_per_sign": true,
  "unlock_ttl_seconds": 600,
  "forwarded_sign": "prompt",
  "language": "",
  "log_level": "info",
  "log_format": "plain"
}
```

| Field | Default | Meaning |
|---|---|---|
| `require_touch_id_per_sign` | `true` | `false` = convenience mode: decrypt all keys when the agent starts and never prompt again |
| `unlock_ttl_seconds` | `600` | How long one unlock is reused; `0` = authenticate every signature |
| `forwarded_sign` | `prompt` | Requests via `ssh -A`: `prompt` (always ask) or `deny` |
| `language` | system | `zh` or `en`; also `FSSH_LANG`, then `LANG`, then the macOS language |

## Authentication modes

### Touch ID (recommended)

A random 32-byte master key lives in the macOS Keychain; fssh shows the Touch ID prompt before using it. Macs without a usable sensor (no Touch ID, no enrolled finger, lid closed) get the macOS login-password prompt instead.

### OTP

For people who prefer a password plus authenticator codes:

```bash
fssh init --mode otp
```

You choose a password (12+ characters), add the secret to an authenticator app (QR code shown if `qrencode` is installed), and confirm with a code before anything is saved. You also get 10 single-use **recovery codes**.

- Forgot the password: `fssh otp recover` (uses one recovery code)
- New phone: `fssh otp show-secret`
- Change password / new recovery codes: `fssh otp change-password`, `fssh otp regen-recovery`
- When the agent runs in the background, password and code are asked in macOS dialogs.
- A code is accepted only once; wait for the next one if you just used it.

**Security boundary:** the OTP secret is stored on this Mac, encrypted with your password. Someone who has both your password and a copy of `~/.fssh` can derive the master key without the authenticator. The code check stops someone who only knows the password from using fssh on this Mac, but it is not a hardware second factor. Use FileVault.

### Switching

```bash
fssh mode switch otp       # or touchid
```

Every key is re-encrypted for the new mode and verified before the switch is committed; on OTP you confirm a code first.

## Agent behaviour

| ssh-add | fssh agent |
|---|---|
| `ssh-add -l` | lists imported keys |
| `ssh-add -x` / `-X` | locks / unlocks the agent (nothing is listed or signed while locked) |
| `ssh-add -D` | prints "All identities removed" but **keeps** the keys (they live in fssh's encrypted store); it forgets the cached unlock, so the next signature asks again |
| `ssh-add <file>` | refused: use `fssh import` |

## Backup, new Mac, uninstall

```bash
fssh backup                         # ~/fssh-backup-<time>.fsshbak, protected by a backup passphrase
fssh restore fssh-backup-....fsshbak   # on the new Mac, after fssh init
fssh uninstall                      # keeps ~/.fssh; --purge deletes keys and the master key
```

## Upgrading from earlier versions

- **OTP users:** older versions showed the TOTP secret in a format authenticator apps cannot use. Run `fssh otp show-secret` and add the secret again. Old recovery codes cannot recover anything; run `fssh otp regen-recovery`.
- **OTP users:** older versions also stored the master key in the Keychain, which bypassed OTP. It is removed automatically after your next OTP unlock.
- After every upgrade macOS may ask whether fssh may use the Keychain; click "Always Allow".
- Run `fssh doctor`: it also creates the public key files `fssh bind` needs for keys imported earlier.

## Troubleshooting

Start with `fssh doctor`. Common cases:

- **ssh does not ask for Touch ID / OTP** — the agent is not running, or ssh is not configured to use it. `fssh doctor` prints the exact fix.
- **ssh asks for a key file passphrase** — the agent refused (locked, cancelled, not running) and ssh fell back to a plaintext key in `~/.ssh`. Archive imported originals: `fssh import ... --original archive`, or follow `fssh doctor`.
- **"Too many authentication failures"** — too many keys offered; bind the host: `fssh bind <host> <alias>`.
- **"incorrect signature type" / "no mutual signature supported"** — old RSA server; `fssh sshd-align --host <server>` enables RSA-SHA2 on it.
- **OTP code rejected** — check the phone clock; a code works only once.
- **Agent logs** — `~/Library/Logs/fssh/agent.log`.

## Security notes

- Keys are encrypted with AES-256-GCM using per-key HKDF-SHA256 keys; the fingerprint is authenticated data.
- Touch ID mode: the master key is in the Keychain; the Touch ID check is enforced by fssh (an app-level check, not a Keychain access-control flag).
- Convenience mode keeps decrypted keys in agent memory until it stops.
- Agent forwarding exposes your keys to the remote host while connected; fssh asks for every forwarded signature.
- Enable FileVault.

## Development

```bash
go build ./cmd/fssh
go test -race ./...
```

Tests that touch the Keychain are opt-in (`FSSH_KEYCHAIN_TESTS=1`) and use an isolated item name (`FSSH_KEYCHAIN_SERVICE`). Do not point `HOME` at a temporary directory while calling the Keychain: macOS looks for the login keychain under `$HOME` and shows a "Keychain Not Found" dialog.

## Credits

This project was developed with assistance from TRAE AI software.
