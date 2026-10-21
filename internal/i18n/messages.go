package i18n

// messages maps a key to its translations. Every entry must provide both
// languages with the same format verbs (enforced by TestMessagesComplete).
var messages = map[string]map[Lang]string{
	// ---- help ----
	"help.title": {
		EN: "fssh - SSH private key manager unlocked by Touch ID / OTP",
		ZH: "fssh - 使用 Touch ID / OTP 解锁的 SSH 私钥管理器",
	},
	"help.usage": {
		EN: "Usage: fssh <command> [flags]",
		ZH: "用法: fssh <命令> [参数]",
	},
	"help.commands": {
		EN: "Commands:",
		ZH: "命令:",
	},
	"help.footer": {
		EN: "Run `fssh help <command>` for command flags. Run `fssh` without arguments to open the interactive shell.",
		ZH: "运行 `fssh help <命令>` 查看该命令的参数；不带参数运行 `fssh` 进入交互式 Shell。",
	},
	"cmd.init":       {EN: "Interactive setup: authentication, key import, auto-start", ZH: "交互式设置向导：初始化认证、导入密钥、配置开机自启"},
	"cmd.import":     {EN: "Import an SSH private key into encrypted storage", ZH: "导入 SSH 私钥并加密保存"},
	"cmd.list":       {EN: "List imported keys", ZH: "列出已导入的密钥"},
	"cmd.export":     {EN: "Export a private key (backup)", ZH: "导出私钥（备份）"},
	"cmd.remove":     {EN: "Remove an imported key", ZH: "删除已导入的密钥"},
	"cmd.rekey":      {EN: "Rotate the master key and re-encrypt all keys", ZH: "更换主密钥并重新加密所有私钥"},
	"cmd.status":     {EN: "Show initialization status", ZH: "查看初始化状态"},
	"cmd.agent":      {EN: "Start the SSH agent", ZH: "启动 SSH Agent"},
	"cmd.shell":      {EN: "Interactive SSH host manager (default)", ZH: "交互式 SSH 主机管理（默认命令）"},
	"cmd.config-gen": {EN: "Generate a ~/.ssh/config host entry", ZH: "生成 ~/.ssh/config 主机配置"},
	"cmd.sshd-align": {EN: "Align a remote server's sshd config for RSA-SHA2", ZH: "调整远程服务器的 sshd 配置以支持 RSA-SHA2"},
	"cmd.version":    {EN: "Show version", ZH: "显示版本"},
	"cmd.help":       {EN: "Show help", ZH: "显示帮助"},

	// ---- cli ----
	"cli.unknown_command": {
		EN: "unknown command: %s",
		ZH: "未知命令: %s",
	},
	"cli.not_initialized": {
		EN: "fssh is not initialized yet. Run `fssh init` to set it up. Opening the SSH host shell.",
		ZH: "fssh 尚未初始化，运行 `fssh init` 开始设置。下面进入 SSH 主机管理 Shell。",
	},
	"shell.banner": {
		EN: "fssh shell - type `help` for commands, `exit` to quit",
		ZH: "fssh shell - 输入 help 查看命令，exit 退出",
	},

	// ---- key / import ----
	"key.err_alias_invalid": {
		EN: "invalid alias %q: use letters, digits, '.', '_' or '-', starting with a letter or digit, at most 64 characters",
		ZH: "别名 %q 不合法：只能包含字母、数字、. _ -，以字母或数字开头，最长 64 个字符",
	},
	"key.err_not_found": {
		EN: "key %q not found. Run `fssh list` to see imported keys",
		ZH: "找不到密钥 %q，运行 `fssh list` 查看已导入的密钥",
	},
	"import.err_args_required": {
		EN: "--alias and --file are required",
		ZH: "必须提供 --alias 和 --file",
	},
	"import.err_alias_exists": {
		EN: "alias %q already exists. Choose another alias, or add --force to overwrite it",
		ZH: "别名 %q 已存在。请换一个别名，或加 --force 覆盖",
	},
	"import.err_already_imported": {
		EN: "this key is already imported as %q (fingerprint %s). Add --force to import it again under a new alias",
		ZH: "该私钥已导入为 %q（指纹 %s）。如需以新别名再导入一份，请加 --force",
	},
	"import.err_file_not_found": {
		EN: "private key file not found: %s",
		ZH: "找不到私钥文件: %s",
	},
	"import.err_read_file": {
		EN: "failed to read private key file: %v",
		ZH: "读取私钥文件失败: %v",
	},
	"import.err_passphrase_required": {
		EN: "this private key is passphrase protected. Run it in a terminal to be prompted, or use --ask-passphrase / --passphrase-file / --passphrase-stdin",
		ZH: "该私钥有密码保护：请在终端中运行以输入密码，或使用 --ask-passphrase / --passphrase-file / --passphrase-stdin",
	},
	"import.err_passphrase_wrong": {
		EN: "incorrect private key passphrase",
		ZH: "私钥密码不正确",
	},
	"import.err_too_many_attempts": {
		EN: "incorrect passphrase %d times, import aborted",
		ZH: "私钥密码连续 %d 次不正确，已放弃导入",
	},
	"import.err_not_private_key": {
		EN: "not a recognised private key (did you pick the .pub public key file?)",
		ZH: "无法识别为私钥（是否误选了 .pub 公钥文件？）",
	},
	"import.err_parse": {
		EN: "failed to parse private key: %v",
		ZH: "解析私钥失败: %v",
	},
	"import.prompt_passphrase": {
		EN: "Enter key passphrase: ",
		ZH: "请输入私钥密码: ",
	},
	"import.passphrase_retry": {
		EN: "Incorrect passphrase, %d attempt(s) left",
		ZH: "密码不正确，还可重试 %d 次",
	},
	"import.done": {
		EN: "Imported %s (fingerprint %s)",
		ZH: "已导入 %s（指纹 %s）",
	},

	// ---- remove ----
	"remove.err_alias_required": {
		EN: "--alias is required",
		ZH: "必须提供 --alias",
	},
	"remove.confirm": {
		EN: "Remove key %q (fingerprint %s)? This cannot be undone",
		ZH: "确定删除密钥 %q（指纹 %s）？删除后无法恢复",
	},
	"remove.err_need_yes": {
		EN: "refusing to remove without confirmation in a non-interactive session; add --yes",
		ZH: "非交互环境下删除需要加 --yes 确认",
	},
	"remove.cancelled": {
		EN: "Cancelled",
		ZH: "已取消",
	},
	"remove.done": {
		EN: "Removed %s",
		ZH: "已删除 %s",
	},

	// ---- security (M2) ----
	"help.usage_otp": {
		EN: "Usage: fssh otp <subcommand>",
		ZH: "用法: fssh otp <子命令>",
	},
	"cmd.log": {
		EN: "Show recent signature requests",
		ZH: "查看签名请求记录",
	},
	"cmd.otp": {
		EN: "Manage OTP mode: recovery, password, secret",
		ZH: "OTP 模式管理：恢复、改密码、恢复码、密钥",
	},
	"cmd.otp.recover": {
		EN: "Reset a forgotten OTP password with a recovery code",
		ZH: "用恢复码重置忘记的 OTP 密码",
	},
	"cmd.otp.change-password": {
		EN: "Change the OTP password",
		ZH: "修改 OTP 密码",
	},
	"cmd.otp.regen-recovery": {
		EN: "Generate 10 new recovery codes (old ones stop working)",
		ZH: "重新生成 10 个恢复码（旧的作废）",
	},
	"cmd.otp.show-secret": {
		EN: "Show the TOTP secret and QR code again (e.g. for a new phone)",
		ZH: "重新显示 TOTP 密钥和二维码（如添加到新手机）",
	},
	"cli.err_need_tty": {
		EN: "this command must be run interactively in a terminal",
		ZH: "该命令需要在终端中交互运行",
	},
	"auth.reason_default": {
		EN: "unlock the fssh master key",
		ZH: "解锁 fssh 主密钥",
	},
	"auth.reason_import": {
		EN: "import key \"%s\" into fssh",
		ZH: "将密钥「%s」导入 fssh",
	},
	"auth.reason_import_wizard": {
		EN: "import SSH keys into fssh",
		ZH: "导入 SSH 密钥到 fssh",
	},
	"auth.reason_export": {
		EN: "export key \"%s\"",
		ZH: "导出密钥「%s」",
	},
	"auth.reason_remove": {
		EN: "remove key \"%s\"",
		ZH: "删除密钥「%s」",
	},
	"auth.reason_rekey": {
		EN: "rotate the fssh master key and re-encrypt all keys",
		ZH: "更换 fssh 主密钥并重新加密所有私钥",
	},
	"agent.reason_host": {
		EN: "%s wants to use key \"%s\" to log in to %s",
		ZH: "「%s」请求使用密钥「%s」登录 %s",
	},
	"agent.reason": {
		EN: "%s wants to use key \"%s\"",
		ZH: "「%s」请求使用密钥「%s」",
	},
	"agent.reason_forwarded": {
		EN: "⚠️ Forwarded request (ssh -A): a remote server is asking to use your key.",
		ZH: "⚠️ 远程转发请求（ssh -A）：远程服务器正在请求使用你的密钥。",
	},
	"agent.unknown_process": {
		EN: "an unknown process",
		ZH: "未知进程",
	},
	"agent.notify_forward_denied": {
		EN: "Refused %s using key \"%s\" via agent forwarding (forwarded_sign=deny)",
		ZH: "已拒绝「%s」通过转发使用密钥「%s」（forwarded_sign=deny）",
	},
	"agent.notify_decrypt_failed": {
		EN: "Could not decrypt key \"%s\"; the master key may have changed. Please retry.",
		ZH: "密钥「%s」解密失败，主密钥可能已更换，请重试",
	},
	"agent.otp_preunlock": {
		EN: "OTP: unlock now so SSH connections don't ask for the password again",
		ZH: "OTP 认证：现在预先解锁，之后的 SSH 连接无需再输入密码",
	},
	"agent.otp_preunlock_reason": {
		EN: "start the fssh agent",
		ZH: "启动 fssh agent",
	},
	"agent.otp_preunlock_done": {
		EN: "OTP authentication succeeded",
		ZH: "OTP 认证成功",
	},
	"agent.convenience_reason": {
		EN: "start the fssh agent (convenience mode decrypts all keys)",
		ZH: "启动 fssh agent（便捷模式：一次性解密所有私钥）",
	},
	"agent.restarted": {
		EN: "Restarted the fssh agent so it uses the new master key",
		ZH: "已重启 fssh agent，使新主密钥生效",
	},
	"agent.restart_manual": {
		EN: "Restart the agent to use the new master key: launchctl kickstart -k %s",
		ZH: "请手动重启 agent 使新主密钥生效: launchctl kickstart -k %s",
	},
	"rekey.done": {
		EN: "Rotated the master key and re-encrypted %d key(s)",
		ZH: "已更换主密钥并重新加密 %d 个私钥",
	},
	"migrate.otp_keychain_done": {
		EN: "Removed the master key copy older versions left in the Keychain; OTP mode now always requires the password and code",
		ZH: "已从 Keychain 移除旧版本遗留的主密钥副本，OTP 模式现在必须通过密码和验证码解锁",
	},
	"migrate.otp_keychain_differs": {
		EN: "The Keychain holds an older master key that differs from your OTP key (left from Touch ID mode). Your keys have been re-encrypted under the OTP key and no longer need it, but while it exists the macOS login password alone can unlock fssh.",
		ZH: "Keychain 中有一个与 OTP 不同的旧主密钥（来自之前的 Touch ID 模式）。当前密钥已改用 OTP 密钥重新加密，不再需要它；但只要它还在，仅凭 macOS 开机密码就能解锁 fssh。",
	},
	"migrate.otp_keychain_confirm": {
		EN: "Delete it now? Backups of ~/.fssh made before switching to OTP will no longer be decryptable",
		ZH: "现在删除它吗？切换到 OTP 之前备份的 ~/.fssh 将无法再解密",
	},
	"migrate.otp_keychain_kept": {
		EN: "warning: an old master key is still in the Keychain and bypasses OTP. Remove it with: security delete-generic-password -s fssh -a master_key_v1",
		ZH: "警告：Keychain 中仍有旧主密钥，可绕过 OTP。可用以下命令删除: security delete-generic-password -s fssh -a master_key_v1",
	},
	"migrate.otp_keychain_failed": {
		EN: "warning: could not remove the master key left in the Keychain: %v",
		ZH: "警告：移除 Keychain 中遗留的主密钥失败: %v",
	},
	"log.empty": {
		EN: "No signature requests recorded yet",
		ZH: "暂无签名记录",
	},
	"log.header": {
		EN: "TIME\tKEY\tPROCESS\tHOST\tRESULT",
		ZH: "时间\t密钥\t进程\t主机\t结果",
	},
	"log.forwarded": {
		EN: "[forwarded]",
		ZH: "[转发]",
	},
	"log.result_ok": {
		EN: "ok",
		ZH: "成功",
	},
	"log.result_denied": {
		EN: "denied",
		ZH: "已拒绝",
	},
	"log.result_failed": {
		EN: "failed",
		ZH: "失败",
	},
	"prompt.cancel": {
		EN: "Cancel",
		ZH: "取消",
	},
	"prompt.ok": {
		EN: "OK",
		ZH: "确定",
	},
	"otp.prompt_password": {
		EN: "Enter OTP password: ",
		ZH: "请输入 OTP 密码: ",
	},
	"otp.prompt_code": {
		EN: "Enter the %d-digit code: ",
		ZH: "请输入 %d 位验证码: ",
	},
	"otp.prompt_new_password": {
		EN: "New OTP password (at least 12 characters): ",
		ZH: "设置新的 OTP 密码（至少 12 位）: ",
	},
	"otp.prompt_confirm_password": {
		EN: "Confirm new password: ",
		ZH: "确认新密码: ",
	},
	"otp.prompt_recovery_code": {
		EN: "Recovery code (XXXX-XXXX-XXXX-XXXX): ",
		ZH: "请输入恢复码（XXXX-XXXX-XXXX-XXXX）: ",
	},
	"otp.retry_password": {
		EN: "Wrong password, try again.",
		ZH: "密码错误，请重试。",
	},
	"otp.retry_code": {
		EN: "Wrong code, try again.",
		ZH: "验证码错误，请重试。",
	},
	"otp.err_password": {
		EN: "wrong OTP password",
		ZH: "OTP 密码错误",
	},
	"otp.err_code": {
		EN: "wrong verification code 3 times",
		ZH: "验证码连续 3 次错误",
	},
	"otp.err_password_weak": {
		EN: "The password must be at least 12 characters, try again.",
		ZH: "密码至少需要 12 个字符，请重试。",
	},
	"otp.err_password_mismatch": {
		EN: "Passwords do not match, try again.",
		ZH: "两次输入的密码不一致，请重试。",
	},
	"otp.err_password_aborted": {
		EN: "new password not set",
		ZH: "未能设置新密码",
	},
	"otp.err_recovery_code": {
		EN: "invalid or already used recovery code",
		ZH: "恢复码无效或已使用",
	},
	"otp.err_not_configured": {
		EN: "OTP mode is not set up; run `fssh init --mode otp` first",
		ZH: "未配置 OTP 模式，请先运行 `fssh init --mode otp`",
	},
	"otp.err_legacy_recovery": {
		EN: "your recovery codes were created by an older version and cannot recover the password. Log in with your password and run `fssh otp regen-recovery`; if the password is lost too, fssh must be re-initialized",
		ZH: "你的恢复码由旧版本生成，无法用于找回密码。请用密码登录后运行 `fssh otp regen-recovery` 重新生成；如果密码也忘记了，只能重新初始化",
	},
	"otp.legacy_recovery": {
		EN: "Your OTP recovery codes were created by an older version and cannot recover the password. Run `fssh otp regen-recovery` to replace them.",
		ZH: "你的 OTP 恢复码由旧版本生成，无法用于找回密码，请运行 `fssh otp regen-recovery` 重新生成。",
	},
	"otp.reason_change_password": {
		EN: "change the OTP password",
		ZH: "修改 OTP 密码",
	},
	"otp.reason_regen_recovery": {
		EN: "generate new recovery codes",
		ZH: "重新生成恢复码",
	},
	"otp.recover_done": {
		EN: "OTP password reset. %d recovery code(s) left. If you also lost your phone, run `fssh otp show-secret` to add the secret to an authenticator again.",
		ZH: "OTP 密码已重置，剩余恢复码 %d 个。如果手机也丢失了，运行 `fssh otp show-secret` 把密钥重新添加到验证器。",
	},
	"otp.change_password_done": {
		EN: "OTP password changed",
		ZH: "OTP 密码已修改",
	},
	"otp.regen_done": {
		EN: "New recovery codes generated; all previous codes no longer work.",
		ZH: "已生成新的恢复码，旧恢复码全部作废。",
	},
	"otp.show_secret_warning": {
		EN: "⚠️  This secret is equivalent to your authenticator. Do not screenshot or share it.",
		ZH: "⚠️  该密钥等同于你的验证器，请勿截图或分享。",
	},
	"otp.recovery_title": {
		EN: "Recovery codes (store them safely: print them or keep them in a password manager):",
		ZH: "恢复码（请安全保存，打印或存入密码管理器）：",
	},
	"otp.recovery_notes": {
		EN: "⚠️  Each code works once and resets a forgotten OTP password. Keep them safe; lost codes cannot be recovered.",
		ZH: "⚠️  每个恢复码仅可使用一次，用于忘记 OTP 密码时重置密码；请妥善保管，丢失无法找回。",
	},
	"otp.secret_title": {
		EN: "TOTP settings:",
		ZH: "TOTP 配置:",
	},
	"otp.secret_issuer": {
		EN: "Issuer:",
		ZH: "发行者:",
	},
	"otp.secret_account": {
		EN: "Account:",
		ZH: "账户:",
	},
	"otp.secret_key": {
		EN: "Secret:",
		ZH: "密钥:",
	},
	"otp.secret_params": {
		EN: "Algorithm/digits/period:",
		ZH: "算法/位数/间隔:",
	},
	"otp.secret_uri": {
		EN: "otpauth link (can be turned into a QR code):",
		ZH: "otpauth 链接（可生成二维码）:",
	},
	"otp.secret_qr_hint": {
		EN: "(Install qrencode to show a scannable QR code here: brew install qrencode)",
		ZH: "（安装 qrencode 后可在此显示二维码: brew install qrencode）",
	},
	"otp.init_done": {
		EN: "OTP authentication initialized",
		ZH: "OTP 认证已初始化",
	},
	"otp.init_add_to_app": {
		EN: "Scan the QR code with an authenticator app (Google Authenticator, Authy, 1Password, ...) or enter the secret above manually.",
		ZH: "请用验证器 App（Google Authenticator、Authy、1Password 等）扫描二维码，或手动输入上面的密钥。",
	},
	"otp.init_saved": {
		EN: "Configuration saved to: %s",
		ZH: "配置已保存到: %s",
	},
	"otp.init_security": {
		EN: "⚠️  Security tips:\n  1. Enable FileVault full-disk encryption\n  2. Keep the recovery codes safe; they cannot be shown again",
		ZH: "⚠️  安全提示:\n  1. 建议启用 FileVault 全盘加密\n  2. 妥善保管恢复码，之后无法再次查看",
	},
	"otp.init_next": {
		EN: "Next steps:\n  1. Import an SSH key: fssh import --alias myserver --file ~/.ssh/id_ed25519\n  2. Start the agent: fssh agent",
		ZH: "下一步:\n  1. 导入 SSH 私钥: fssh import --alias myserver --file ~/.ssh/id_ed25519\n  2. 启动 agent: fssh agent",
	},

	// ---- usability (M3) ----
	"cmd.keygen": {
		EN: "Generate a new key directly into encrypted storage",
		ZH: "生成新密钥并直接加密保存（明文不落盘）",
	},
	"cmd.pubkey": {
		EN: "Print a key's public key (--copy to clipboard)",
		ZH: "输出密钥的公钥（--copy 复制到剪贴板）",
	},
	"cmd.bind": {
		EN: "Make a host use one specific key",
		ZH: "让某台主机只使用指定的密钥",
	},
	"cmd.unbind": {
		EN: "Remove a host's key binding",
		ZH: "取消主机与密钥的绑定",
	},
	"cmd.doctor": {
		EN: "Check the setup and suggest fixes",
		ZH: "检查配置并给出修复建议",
	},
	"auth.reason_keygen": {
		EN: "save new key \"%s\" in fssh",
		ZH: "将新密钥「%s」保存到 fssh",
	},
	"list.empty": {
		EN: "No keys yet. Import one with `fssh import` or create one with `fssh keygen`.",
		ZH: "还没有密钥。用 `fssh import` 导入，或用 `fssh keygen` 生成。",
	},
	"list.header": {
		EN: "ALIAS\tTYPE\tFINGERPRINT\tCREATED\tHOSTS",
		ZH: "别名\t类型\t指纹\t创建时间\t绑定主机",
	},
	"pubkey.usage": {
		EN: "usage: fssh pubkey <alias> [--copy]",
		ZH: "用法: fssh pubkey <别名> [--copy]",
	},
	"pubkey.copied": {
		EN: "Copied to the clipboard",
		ZH: "已复制到剪贴板",
	},
	"keygen.usage": {
		EN: "usage: fssh keygen <alias> [--type ed25519|ecdsa|rsa] [--bits 3072]",
		ZH: "用法: fssh keygen <别名> [--type ed25519|ecdsa|rsa] [--bits 3072]",
	},
	"keygen.err_type": {
		EN: "unsupported key type %q: use ed25519, ecdsa or rsa",
		ZH: "不支持的密钥类型 %q：可选 ed25519、ecdsa、rsa",
	},
	"keygen.err_rsa_bits": {
		EN: "RSA keys must be at least 2048 bits",
		ZH: "RSA 密钥至少 2048 位",
	},
	"keygen.done": {
		EN: "Created key %s (fingerprint %s). Public key:",
		ZH: "已生成密钥 %s（指纹 %s），公钥如下:",
	},
	"keygen.next": {
		EN: "Add the public key to the server's ~/.ssh/authorized_keys (or GitHub/GitLab), then bind it to a host:\n  fssh bind <host> %s",
		ZH: "把公钥添加到服务器的 ~/.ssh/authorized_keys（或 GitHub/GitLab），再绑定到主机:\n  fssh bind <主机> %s",
	},
	"bind.usage": {
		EN: "usage: fssh bind <host> <alias>   e.g. fssh bind github.com work",
		ZH: "用法: fssh bind <主机> <别名>   例如 fssh bind github.com work",
	},
	"bind.created": {
		EN: "Added a new `Host %s` entry to ~/.ssh/config",
		ZH: "已在 ~/.ssh/config 中新建 `Host %s`",
	},
	"bind.done": {
		EN: "%s now uses only key %s (other keys in the agent are not offered)",
		ZH: "%s 现在只使用密钥 %s（不再尝试 agent 中的其他密钥）",
	},
	"bind.err_elsewhere": {
		EN: "host %s is defined in %s, which fssh does not edit. Add these lines to its Host block:\n    %s",
		ZH: "主机 %s 定义在 %s 中，fssh 不修改该文件。请在其 Host 块中加入:\n    %s",
	},
	"unbind.usage": {
		EN: "usage: fssh unbind <host>",
		ZH: "用法: fssh unbind <主机>",
	},
	"unbind.done": {
		EN: "%s is no longer bound to a key",
		ZH: "%s 已取消密钥绑定",
	},
	"unbind.none": {
		EN: "%s is not bound to an fssh key",
		ZH: "%s 没有绑定 fssh 密钥",
	},
	"unbind.err_elsewhere": {
		EN: "host %s is defined in %s, which fssh does not edit",
		ZH: "主机 %s 定义在 %s 中，fssh 不修改该文件",
	},
	"remove.bound_hosts": {
		EN: "These hosts were bound to the removed key and will fail to log in: %s. Rebind them with `fssh bind` or run `fssh unbind <host>`.",
		ZH: "以下主机绑定了已删除的密钥，将无法登录: %s。请用 `fssh bind` 重新绑定，或运行 `fssh unbind <主机>`。",
	},
	"setup.bind_hint": {
		EN: "Tip: with several keys, bind each host to one key so the right account is used: fssh bind github.com <alias>",
		ZH: "提示：有多把密钥时，建议把主机绑定到指定密钥，避免用错账号: fssh bind github.com <别名>",
	},
	"import.err_original_mode": {
		EN: "invalid --original %q: use archive, delete or keep",
		ZH: "--original 取值 %q 无效：可选 archive、delete、keep",
	},
	"import.original_prompt": {
		EN: "The plaintext private key is still at %s, and ssh can keep using it directly, bypassing fssh.\n  1) Archive: move it to ~/.ssh/fssh-archive/ (ssh no longer uses it; still plaintext, delete it once everything works) [default]\n  2) Delete it\n  3) Keep it",
		ZH: "明文私钥仍在 %s，ssh 仍可能绕过 fssh 直接使用它。\n  1) 归档：移到 ~/.ssh/fssh-archive/（ssh 不再自动使用；仍是明文，确认无误后可删除）[默认]\n  2) 删除\n  3) 保留",
	},
	"import.original_choice": {
		EN: "Choice [1]: ",
		ZH: "请选择 [1]: ",
	},
	"import.original_delete_confirm": {
		EN: "Delete %s permanently? Make sure you have a backup (y/N): ",
		ZH: "永久删除 %s？请确认已有备份 (y/N): ",
	},
	"import.original_archived": {
		EN: "Archived to %s",
		ZH: "已归档到 %s",
	},
	"import.original_deleted": {
		EN: "Deleted %s",
		ZH: "已删除 %s",
	},
	"import.original_kept": {
		EN: "Kept the plaintext key file; ssh may still use it without fssh",
		ZH: "已保留明文私钥文件；ssh 仍可能不经过 fssh 直接使用它",
	},
	"import.original_failed": {
		EN: "could not handle the original key file: %v",
		ZH: "处理原私钥文件失败: %v",
	},
	"import.original_hint": {
		EN: "The plaintext key is still at %s. Archive it with --original archive or delete it once you have a backup.",
		ZH: "明文私钥仍在 %s。可用 --original archive 归档，或在备份后删除。",
	},
	"import.original_referenced": {
		EN: "~/.ssh/config: host %s uses this file via IdentityFile. Switch it to fssh with: fssh bind %s %s",
		ZH: "~/.ssh/config 中主机 %s 通过 IdentityFile 使用该文件，建议改为: fssh bind %s %s",
	},
	"status.mode": {
		EN: "Auth mode",
		ZH: "认证模式",
	},
	"status.initialized": {
		EN: "Initialized",
		ZH: "已初始化",
	},
	"status.keys": {
		EN: "Keys",
		ZH: "密钥数量",
	},
	"status.agent": {
		EN: "Agent",
		ZH: "Agent",
	},
	"status.agent_running": {
		EN: "running, %d key(s) (%s)",
		ZH: "运行中，%d 把密钥（%s）",
	},
	"status.agent_down": {
		EN: "not running (%s)",
		ZH: "未运行（%s）",
	},
	"status.launchagent": {
		EN: "Auto-start",
		ZH: "开机自启",
	},
	"status.sshconfig": {
		EN: "ssh config uses fssh",
		ZH: "ssh 配置已接入",
	},
	"status.authsock": {
		EN: "SSH_AUTH_SOCK",
		ZH: "SSH_AUTH_SOCK",
	},
	"status.authsock_unset": {
		EN: "(not set)",
		ZH: "（未设置）",
	},
	"status.authsock_fssh": {
		EN: "fssh agent",
		ZH: "fssh agent",
	},
	"status.ttl": {
		EN: "Unlock cache",
		ZH: "免验证时间",
	},
	"status.ttl_value": {
		EN: "%d seconds",
		ZH: "%d 秒",
	},
	"status.convenience": {
		EN: "convenience mode (keys decrypted at start)",
		ZH: "便捷模式（启动时解密全部密钥）",
	},
	"status.forwarded": {
		EN: "Forwarded requests",
		ZH: "转发签名请求",
	},
	"status.recovery": {
		EN: "Recovery codes left",
		ZH: "剩余恢复码",
	},
	"status.recovery_legacy": {
		EN: "old format, cannot recover (run fssh otp regen-recovery)",
		ZH: "旧版格式，无法使用（运行 fssh otp regen-recovery）",
	},
	"status.yes": {
		EN: "yes",
		ZH: "是",
	},
	"status.no": {
		EN: "no",
		ZH: "否",
	},
	"doctor.config_invalid": {
		EN: "~/.fssh/config.json is invalid: %v",
		ZH: "~/.fssh/config.json 格式错误: %v",
	},
	"doctor.fix_config": {
		EN: "fix the JSON syntax or delete the file to use defaults",
		ZH: "修正 JSON 格式，或删除该文件以使用默认配置",
	},
	"doctor.init_error": {
		EN: "cannot determine initialization state: %v",
		ZH: "无法确定初始化状态: %v",
	},
	"doctor.not_initialized": {
		EN: "fssh is not initialized",
		ZH: "fssh 尚未初始化",
	},
	"doctor.initialized": {
		EN: "initialized (%s mode)",
		ZH: "已初始化（%s 模式）",
	},
	"doctor.no_keys": {
		EN: "no keys imported yet",
		ZH: "还没有导入任何密钥",
	},
	"doctor.agent_ok": {
		EN: "agent is running and serves %d key(s)",
		ZH: "agent 正在运行，提供 %d 把密钥",
	},
	"doctor.agent_down": {
		EN: "agent is not reachable at %s",
		ZH: "无法连接 agent（%s）",
	},
	"doctor.no_launchagent": {
		EN: "agent does not start automatically at login",
		ZH: "agent 不会在登录时自动启动",
	},
	"doctor.fix_launchagent": {
		EN: "run `fssh init` again and accept the auto-start step",
		ZH: "重新运行 `fssh init` 并完成开机自启步骤",
	},
	"doctor.launchagent_binary_missing": {
		EN: "auto-start points to %s, which does not exist",
		ZH: "开机自启指向的 %s 不存在",
	},
	"doctor.log_in_tmp": {
		EN: "agent logs go to /tmp/fssh-agent.log, readable by other users",
		ZH: "agent 日志写在 /tmp/fssh-agent.log，其他用户可读",
	},
	"status.ssh_all": {
		EN: "yes, all hosts",
		ZH: "是，所有主机",
	},
	"status.ssh_partial": {
		EN: "only some hosts",
		ZH: "仅部分主机",
	},
	"doctor.ssh_partial": {
		EN: "only some hosts in ~/.ssh/config use the fssh agent; the others use plaintext keys or another agent",
		ZH: "~/.ssh/config 中只有部分主机使用 fssh agent，其余主机会使用明文私钥或其他 agent",
	},
	"doctor.ssh_ok": {
		EN: "ssh is configured to use the fssh agent",
		ZH: "ssh 已配置使用 fssh agent",
	},
	"doctor.ssh_env_only": {
		EN: "only SSH_AUTH_SOCK points to fssh; apps that do not inherit it (IDEs, git GUIs) bypass fssh",
		ZH: "只有 SSH_AUTH_SOCK 指向 fssh；不继承该变量的程序（IDE、git 图形客户端）会绕过 fssh",
	},
	"doctor.ssh_missing": {
		EN: "ssh is not configured to use the fssh agent",
		ZH: "ssh 没有配置使用 fssh agent",
	},
	"doctor.fix_ssh": {
		EN: "add to the top of ~/.ssh/config:\n  Host *\n      IdentityAgent %s",
		ZH: "在 ~/.ssh/config 开头加入:\n  Host *\n      IdentityAgent %s",
	},
	"doctor.plaintext_imported": {
		EN: "%s is a plaintext copy of imported key %s; ssh can still use it and bypass fssh",
		ZH: "%s 是已导入密钥 %s 的明文副本，ssh 仍可绕过 fssh 直接使用",
	},
	"doctor.plaintext_encrypted": {
		EN: "%s is a passphrase-protected private key not managed by fssh",
		ZH: "%s 是未由 fssh 管理的私钥（有密码保护）",
	},
	"doctor.plaintext_unprotected": {
		EN: "%s is an unencrypted private key not managed by fssh",
		ZH: "%s 是未由 fssh 管理的私钥（无密码保护）",
	},
	"doctor.unbound": {
		EN: "%d keys but no host is bound to one: every key is offered to every server (wrong account, \"Too many authentication failures\")",
		ZH: "有 %d 把密钥，但没有主机绑定指定密钥：每台服务器都会依次尝试所有密钥（可能用错账号或报 Too many authentication failures）",
	},
	"doctor.recovery_low": {
		EN: "only %d OTP recovery code(s) left",
		ZH: "OTP 恢复码只剩 %d 个",
	},
	"doctor.all_ok": {
		EN: "Everything looks good.",
		ZH: "一切正常。",
	},
	"doctor.summary": {
		EN: "%d problem(s), %d warning(s)",
		ZH: "%d 个问题，%d 个警告",
	},
}
