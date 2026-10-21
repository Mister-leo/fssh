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

	// ---- setup wizard ----
	"setup.err_home": {
		EN: "cannot find the home directory: %v",
		ZH: "无法获取用户主目录: %v",
	},
	"keys.none_found": {
		EN: "No SSH private keys found in ~/.ssh/. Import later with `fssh import --alias <name> --file <path>`, or create one with `fssh keygen <name>`.",
		ZH: "~/.ssh/ 中没有找到 SSH 私钥。之后可用 `fssh import --alias <名字> --file <路径>` 导入，或用 `fssh keygen <名字>` 生成。",
	},
	"keys.found": {
		EN: "Found %d SSH private key(s):",
		ZH: "找到 %d 个 SSH 私钥:",
	},
	"keys.encrypted_tag": {
		EN: "[passphrase protected]",
		ZH: "[有密码保护]",
	},
	"keys.select_hint": {
		EN: "Enter the numbers of the keys to import (e.g. 1,3 or 1-3), all, or none:",
		ZH: "输入要导入的密钥编号（例如 1,3 或 1-3），all 表示全部，none 表示跳过:",
	},
	"keys.select_prompt": {
		EN: "Keys to import [all]: ",
		ZH: "要导入的密钥 [all]: ",
	},
	"keys.err_read_input": {
		EN: "could not read input: %v",
		ZH: "读取输入失败: %v",
	},
	"keys.skipped": {
		EN: "Skipped key import",
		ZH: "已跳过导入",
	},
	"keys.err_selection": {
		EN: "invalid selection: %v",
		ZH: "选择无效: %v",
	},
	"keys.none_selected": {
		EN: "No keys selected",
		ZH: "未选择任何密钥",
	},
	"keys.importing": {
		EN: "Importing %d key(s)...",
		ZH: "正在导入 %d 个密钥...",
	},
	"keys.already_imported": {
		EN: "already imported as %s, skipped",
		ZH: "已导入为 %s，跳过",
	},
	"keys.err_save": {
		EN: "could not save the key: %v",
		ZH: "保存密钥失败: %v",
	},
	"keys.imported_count": {
		EN: "Imported %d of %d selected key(s)",
		ZH: "已导入 %d/%d 个所选密钥",
	},
	"keys.none_imported": {
		EN: "No keys were imported",
		ZH: "没有导入任何密钥",
	},
	"keys.err_no_ssh_dir": {
		EN: "SSH directory not found: %s",
		ZH: "找不到 SSH 目录: %s",
	},
	"keys.err_read_ssh_dir": {
		EN: "cannot read the SSH directory: %v",
		ZH: "读取 SSH 目录失败: %v",
	},
	"keys.alias_prompt": {
		EN: "Alias [%s]: ",
		ZH: "别名 [%s]: ",
	},
	"keys.alias_taken": {
		EN: "alias %s is already used, choose another",
		ZH: "别名 %s 已被使用，请换一个",
	},
	"keys.err_range": {
		EN: "invalid range: %s",
		ZH: "范围格式无效: %s",
	},
	"keys.err_number": {
		EN: "invalid number: %s",
		ZH: "编号无效: %s",
	},
	"keys.err_range_bounds": {
		EN: "range %d-%d is out of bounds (1-%d)",
		ZH: "范围 %d-%d 超出有效编号（1-%d）",
	},
	"keys.err_number_bounds": {
		EN: "number %d is out of bounds (1-%d)",
		ZH: "编号 %d 超出有效范围（1-%d）",
	},
	"binary.err_path": {
		EN: "cannot locate the fssh executable: %v",
		ZH: "无法定位 fssh 可执行文件: %v",
	},
	"binary.installed": {
		EN: "fssh is already installed at %s",
		ZH: "fssh 已安装在 %s",
	},
	"binary.brew": {
		EN: "Installed by Homebrew (%s); upgrade with brew upgrade fssh",
		ZH: "由 Homebrew 安装（%s），用 brew upgrade fssh 升级",
	},
	"binary.exists": {
		EN: "another fssh exists at %s",
		ZH: "%s 已存在另一个 fssh",
	},
	"binary.replace": {
		EN: "Replace it with this version?",
		ZH: "用当前版本替换它吗？",
	},
	"binary.skipped": {
		EN: "Skipped installation",
		ZH: "已跳过安装",
	},
	"binary.installing": {
		EN: "Installing fssh to %s (requires sudo)...",
		ZH: "正在安装 fssh 到 %s（需要 sudo）...",
	},
	"binary.err_install": {
		EN: "installation failed: %v (install manually: sudo cp fssh /usr/local/bin/)",
		ZH: "安装失败: %v（可手动安装: sudo cp fssh /usr/local/bin/）",
	},
	"binary.done": {
		EN: "Installed fssh to %s",
		ZH: "已安装 fssh 到 %s",
	},
	"launchd.replacing": {
		EN: "Updating the existing auto-start configuration",
		ZH: "正在更新已有的开机自启配置",
	},
	"launchd.err": {
		EN: "auto-start setup failed: %v",
		ZH: "配置开机自启失败: %v",
	},
	"launchd.created": {
		EN: "Created %s",
		ZH: "已创建 %s",
	},
	"launchd.loaded": {
		EN: "The agent will start automatically at login",
		ZH: "agent 将在登录时自动启动",
	},
	"agentstart.running": {
		EN: "The fssh agent is running",
		ZH: "fssh agent 正在运行",
	},
	"agentstart.waiting": {
		EN: "Waiting for the agent to start...",
		ZH: "等待 agent 启动...",
	},
	"agentstart.timeout": {
		EN: "the agent did not start within 10 seconds; check ~/Library/Logs/fssh/agent.log or run `fssh doctor`",
		ZH: "agent 10 秒内未启动；请查看 ~/Library/Logs/fssh/agent.log 或运行 `fssh doctor`",
	},
	"sshsetup.err": {
		EN: "could not update ~/.ssh/config: %v",
		ZH: "更新 ~/.ssh/config 失败: %v",
	},
	"sshsetup.other_agent": {
		EN: "~/.ssh/config already uses another agent: %s",
		ZH: "~/.ssh/config 已在使用另一个 agent: %s",
	},
	"sshsetup.other_agent_confirm": {
		EN: "Let the fssh agent take precedence for all hosts?",
		ZH: "让 fssh agent 对所有主机优先生效吗？",
	},
	"sshsetup.skipped": {
		EN: "Skipped ~/.ssh/config",
		ZH: "已跳过修改 ~/.ssh/config",
	},
	"sshsetup.explain": {
		EN: "To make ssh use fssh for every host, a marked block is added to the top of ~/.ssh/config (a backup is kept).",
		ZH: "为了让 ssh 对所有主机使用 fssh，将在 ~/.ssh/config 开头加入一个带标记的配置块（会保留备份）。",
	},
	"sshsetup.confirm": {
		EN: "Update ~/.ssh/config?",
		ZH: "修改 ~/.ssh/config 吗？",
	},
	"sshsetup.done": {
		EN: "Updated ~/.ssh/config",
		ZH: "已更新 ~/.ssh/config",
	},

	// ---- delivery (M4) ----
	"cmd.backup": {
		EN: "Back up all keys to an encrypted file",
		ZH: "把所有密钥备份到加密文件",
	},
	"cmd.restore": {
		EN: "Restore keys from a backup file",
		ZH: "从备份文件恢复密钥",
	},
	"cmd.mode": {
		EN: "Show or switch the auth mode (keys are kept)",
		ZH: "查看或切换认证模式（保留所有密钥）",
	},
	"cmd.uninstall": {
		EN: "Remove fssh from ssh config, auto-start and shell (--purge also deletes keys)",
		ZH: "从 ssh 配置、开机自启和 shell 中移除 fssh（--purge 同时删除密钥）",
	},
	"agent.err_socket_too_long": {
		EN: "socket path is %s (%d bytes); macOS allows at most 103 bytes. Set a shorter \"socket\" in ~/.fssh/config.json",
		ZH: "socket 路径 %s 长度为 %d 字节，macOS 最多允许 103 字节。请在 ~/.fssh/config.json 中设置更短的 \"socket\"",
	},
	"auth.reason_backup": {
		EN: "back up all fssh keys",
		ZH: "备份所有 fssh 密钥",
	},
	"auth.reason_restore": {
		EN: "restore %d key(s) into fssh",
		ZH: "向 fssh 恢复 %d 个密钥",
	},
	"auth.reason_mode_switch": {
		EN: "switch fssh to %s mode",
		ZH: "将 fssh 切换到 %s 模式",
	},
	"auth.reason_mode_verify": {
		EN: "confirm the new fssh master key",
		ZH: "确认新的 fssh 主密钥",
	},
	"backup.explain": {
		EN: "The backup holds every key and is protected by a backup passphrase (independent of Touch ID/OTP). It can be restored on another Mac with `fssh restore`. Keep the passphrase safe: without it the backup cannot be opened.",
		ZH: "备份包含所有密钥，由单独的备份密码保护（与 Touch ID/OTP 无关），可在其他 Mac 上用 `fssh restore` 恢复。请牢记备份密码，丢失将无法打开备份。",
	},
	"backup.prompt_passphrase": {
		EN: "Backup passphrase (at least 12 characters): ",
		ZH: "设置备份密码（至少 12 位）: ",
	},
	"backup.done": {
		EN: "Backed up %d key(s) to %s",
		ZH: "已备份 %d 个密钥到 %s",
	},
	"restore.usage": {
		EN: "usage: fssh restore <backup file> [--force]",
		ZH: "用法: fssh restore <备份文件> [--force]",
	},
	"restore.prompt_passphrase": {
		EN: "Backup passphrase: ",
		ZH: "备份密码: ",
	},
	"restore.err_passphrase": {
		EN: "wrong backup passphrase, or the file is damaged",
		ZH: "备份密码错误，或文件已损坏",
	},
	"restore.skip_same": {
		EN: "skip %s: already imported as %s",
		ZH: "跳过 %s：已导入为 %s",
	},
	"restore.skip_alias": {
		EN: "skip %s: alias already used by another key (use --force to overwrite)",
		ZH: "跳过 %s：该别名已被另一把密钥使用（加 --force 覆盖）",
	},
	"restore.nothing": {
		EN: "Nothing to restore",
		ZH: "没有需要恢复的密钥",
	},
	"restore.done": {
		EN: "Restored %d of %d key(s)",
		ZH: "已恢复 %d/%d 个密钥",
	},
	"export.usage": {
		EN: "usage: fssh export --alias <alias> --out <file> [--format openssh|pkcs8] [--ask-passphrase]",
		ZH: "用法: fssh export --alias <别名> --out <文件> [--format openssh|pkcs8] [--ask-passphrase]",
	},
	"export.err_format": {
		EN: "unknown --format %q: use openssh or pkcs8",
		ZH: "--format %q 无效：可选 openssh 或 pkcs8",
	},
	"export.err_exists": {
		EN: "%s already exists (use --force to overwrite)",
		ZH: "%s 已存在（加 --force 覆盖）",
	},
	"export.err_pkcs8_passphrase": {
		EN: "encrypted PKCS#8 export is not supported; use --format openssh with a passphrase",
		ZH: "不支持导出加密的 PKCS#8；请使用 --format openssh 并设置密码",
	},
	"export.prompt_passphrase": {
		EN: "Passphrase for the exported file (Enter for none): ",
		ZH: "为导出文件设置密码（直接回车表示不加密）: ",
	},
	"export.done": {
		EN: "Exported %s to %s (OpenSSH format, passphrase protected)",
		ZH: "已导出 %s 到 %s（OpenSSH 格式，有密码保护）",
	},
	"export.done_plain": {
		EN: "Exported %s to %s. ⚠️  The file is an unencrypted private key: store it safely and delete it when no longer needed.",
		ZH: "已导出 %s 到 %s。⚠️  该文件是未加密的私钥，请妥善保管，用完后删除。",
	},
	"init.err_mode": {
		EN: "unsupported auth mode %q (use touchid or otp)",
		ZH: "不支持的认证模式 %q（可选 touchid 或 otp）",
	},
	"init.already": {
		EN: "fssh is already initialized (%s mode)",
		ZH: "fssh 已初始化（%s 模式）",
	},
	"init.already_other": {
		EN: "fssh is already initialized in %s mode. Switch with `fssh mode switch %s` (keeps your keys), or start over with `fssh init --force`",
		ZH: "fssh 已以 %s 模式初始化。可用 `fssh mode switch %s` 切换（保留密钥），或用 `fssh init --force` 全部重来",
	},
	"init.force_reset": {
		EN: "--force: starting over; existing keys are moved aside",
		ZH: "--force：全部重来，现有密钥将被移到一旁",
	},
	"init.orphans": {
		EN: "Found %d key(s) without a usable master key; they are moved aside",
		ZH: "发现 %d 个已没有可用主密钥的密钥，将其移到一旁",
	},
	"init.keychain_dialog_hint": {
		EN: "macOS may ask whether fssh may use the Keychain: click \"Always Allow\" (or enter your login password).",
		ZH: "macOS 可能询问是否允许 fssh 使用钥匙串：请点击「始终允许」（或输入登录密码）。",
	},
	"init.keychain_failed": {
		EN: "❌ Could not store the master key in the Keychain. If you clicked \"Deny\", run `fssh init` again and allow access.",
		ZH: "❌ 无法把主密钥存入钥匙串。如果点了「拒绝」，请重新运行 `fssh init` 并允许访问。",
	},
	"init.touchid_done": {
		EN: "Master key created and protected by Touch ID",
		ZH: "已创建主密钥，由 Touch ID 保护",
	},
	"init.otp_title": {
		EN: "Set up OTP: choose a password, then add the secret to an authenticator app.",
		ZH: "设置 OTP：先设置密码，再把密钥添加到验证器 App。",
	},
	"init.otp_verify_code": {
		EN: "Enter the %d-digit code shown in your authenticator app to confirm: ",
		ZH: "输入验证器 App 中显示的 %d 位验证码以确认: ",
	},
	"init.otp_verify_failed": {
		EN: "the authenticator app did not produce a valid code; nothing was changed. Check the secret and the phone's clock, then try again",
		ZH: "验证器 App 生成的验证码不正确，未做任何更改。请检查密钥和手机时间后重试",
	},
	"mode.usage": {
		EN: "usage: fssh mode switch <touchid|otp>",
		ZH: "用法: fssh mode switch <touchid|otp>",
	},
	"mode.current": {
		EN: "Current auth mode: %s",
		ZH: "当前认证模式: %s",
	},
	"mode.already": {
		EN: "fssh already uses %s mode",
		ZH: "fssh 已经是 %s 模式",
	},
	"mode.switched": {
		EN: "Switched to %s mode; %d key(s) re-encrypted",
		ZH: "已切换到 %s 模式，重新加密了 %d 个密钥",
	},
	"mode.touchid_password_fallback": {
		EN: "Touch ID is not usable on this Mac right now (no sensor, no enrolled finger, or lid closed). Touch ID mode then asks for your macOS login password instead.",
		ZH: "此 Mac 当前无法使用 Touch ID（没有传感器、未录入指纹或合盖使用）。Touch ID 模式将改为询问 macOS 登录密码。",
	},
	"otp.retry_code_used": {
		EN: "This code was already used. Wait for the next one.",
		ZH: "该验证码已使用过，请等待下一个。",
	},
	"reset.warning": {
		EN: "Starting over makes these %d key(s) unusable: %s",
		ZH: "全部重来后，以下 %d 个密钥将无法再使用: %s",
	},
	"reset.offer_backup": {
		EN: "Back them up first (recommended)?",
		ZH: "先备份它们吗（推荐）？",
	},
	"reset.confirm": {
		EN: "Type DELETE to continue: ",
		ZH: "输入 DELETE 继续: ",
	},
	"reset.moved": {
		EN: "Old data moved to: %s",
		ZH: "旧数据已移到: %s",
	},
	"setup.welcome": {
		EN: "Welcome to the fssh setup wizard. Steps:",
		ZH: "欢迎使用 fssh 设置向导，将依次完成:",
	},
	"setup.step": {
		EN: "Step",
		ZH: "步骤",
	},
	"setup.step_auth": {
		EN: "Authentication (Touch ID or OTP)",
		ZH: "认证方式（Touch ID 或 OTP）",
	},
	"setup.step_binary": {
		EN: "Install fssh to /usr/local/bin",
		ZH: "安装 fssh 到 /usr/local/bin",
	},
	"setup.step_import": {
		EN: "Import SSH keys from ~/.ssh",
		ZH: "从 ~/.ssh 导入 SSH 密钥",
	},
	"setup.step_launchd": {
		EN: "Start the agent at login",
		ZH: "登录时自动启动 agent",
	},
	"setup.step_agent": {
		EN: "Start the agent",
		ZH: "启动 agent",
	},
	"setup.step_sshconfig": {
		EN: "Make ssh use fssh",
		ZH: "让 ssh 使用 fssh",
	},
	"setup.step_shellenv": {
		EN: "Shell environment (optional)",
		ZH: "Shell 环境变量（可选）",
	},
	"setup.binary_failed": {
		EN: "installation failed: %v",
		ZH: "安装失败: %v",
	},
	"setup.import_failed": {
		EN: "key import failed: %v (import later with fssh import)",
		ZH: "导入密钥失败: %v（之后可用 fssh import 导入）",
	},
	"setup.launchd_failed": {
		EN: "auto-start setup failed: %v",
		ZH: "配置开机自启失败: %v",
	},
	"setup.agent_failed": {
		EN: "%v",
		ZH: "%v",
	},
	"setup.sshconfig_failed": {
		EN: "%v",
		ZH: "%v",
	},
	"setup.shellenv_failed": {
		EN: "could not update the shell startup file: %v",
		ZH: "更新 shell 配置文件失败: %v",
	},
	"setup.already": {
		EN: "fssh is already initialized (%s mode, %d key(s)).",
		ZH: "fssh 已初始化（%s 模式，%d 个密钥）。",
	},
	"setup.already_choices": {
		EN: "  1) Keep the current setup and continue [default]\n  2) Switch auth mode (keeps all keys)\n  3) Start over (current keys become unusable)\n  4) Exit",
		ZH: "  1) 保留当前配置，继续后面的步骤 [默认]\n  2) 切换认证模式（保留所有密钥）\n  3) 全部重来（现有密钥将无法使用）\n  4) 退出",
	},
	"setup.keep": {
		EN: "Keeping %s mode",
		ZH: "保留 %s 模式",
	},
	"setup.cancelled": {
		EN: "Setup cancelled",
		ZH: "已取消设置",
	},
	"setup.touchid_available": {
		EN: "Touch ID is available",
		ZH: "检测到可用的 Touch ID",
	},
	"setup.touchid_unavailable": {
		EN: "Touch ID is not usable on this Mac right now. Touch ID mode still works and asks for your macOS login password instead.",
		ZH: "此 Mac 当前无法使用 Touch ID。Touch ID 模式仍然可用，会改为询问 macOS 登录密码。",
	},
	"setup.mode_choices": {
		EN: "  1) Touch ID - master key in the Keychain, unlocked by fingerprint (or login password) [recommended]\n  2) OTP - password + authenticator app codes",
		ZH: "  1) Touch ID - 主密钥存于钥匙串，用指纹（或登录密码）解锁 [推荐]\n  2) OTP - 密码 + 验证器 App 验证码",
	},
	"setup.invalid_choice": {
		EN: "Please enter 1 or 2.",
		ZH: "请输入 1 或 2。",
	},
	"setup.complete": {
		EN: "Setup complete 🎉",
		ZH: "设置完成 🎉",
	},
	"setup.complete_not_connected": {
		EN: "ssh is not yet configured to use fssh. Add `IdentityAgent %s` under `Host *` in ~/.ssh/config, or run `fssh doctor` for details.",
		ZH: "ssh 还没有配置使用 fssh。请在 ~/.ssh/config 的 `Host *` 下加入 `IdentityAgent %s`，或运行 `fssh doctor` 查看详情。",
	},
	"setup.next_steps": {
		EN: "Next:\n  ssh your-server          # should ask for Touch ID / OTP\n  fssh doctor              # check the setup\n  fssh bind <host> <alias> # pin a host to one key\n  fssh backup              # keep an encrypted backup of your keys",
		ZH: "接下来:\n  ssh your-server          # 应弹出 Touch ID / OTP 验证\n  fssh doctor              # 检查配置\n  fssh bind <主机> <别名>   # 让主机只使用指定密钥\n  fssh backup              # 备份密钥到加密文件",
	},
	"shellenv.optional": {
		EN: "ssh already uses fssh through ~/.ssh/config. Exporting SSH_AUTH_SOCK additionally lets ssh-add and tools that ignore ~/.ssh/config use fssh, but hides any other ssh-agent from new shells.",
		ZH: "ssh 已通过 ~/.ssh/config 使用 fssh。另外设置 SSH_AUTH_SOCK 可以让 ssh-add 以及不读取 ~/.ssh/config 的工具也使用 fssh，但新开的终端将不再使用其他 ssh-agent。",
	},
	"shellenv.needed": {
		EN: "ssh is not configured through ~/.ssh/config, so SSH_AUTH_SOCK is needed for ssh to use fssh.",
		ZH: "ssh 没有通过 ~/.ssh/config 接入 fssh，需要设置 SSH_AUTH_SOCK 才能使用 fssh。",
	},
	"shellenv.confirm": {
		EN: "Add SSH_AUTH_SOCK to %s?",
		ZH: "把 SSH_AUTH_SOCK 写入 %s 吗？",
	},
	"shellenv.done": {
		EN: "Added to %s (takes effect in new terminal windows)",
		ZH: "已写入 %s（新打开的终端生效）",
	},
	"shellenv.already": {
		EN: "SSH_AUTH_SOCK is already set in %s",
		ZH: "%s 中已设置 SSH_AUTH_SOCK",
	},
	"shellenv.manual": {
		EN: "To set it yourself: export SSH_AUTH_SOCK=%s",
		ZH: "如需手动设置: export SSH_AUTH_SOCK=%s",
	},
	"uninstall.plan": {
		EN: "This removes fssh from: auto-start, ~/.ssh/config (managed block and key bindings) and shell startup files. Your keys in ~/.fssh and the master key are kept.",
		ZH: "将从以下位置移除 fssh：开机自启、~/.ssh/config（托管配置块和密钥绑定）、shell 配置文件。~/.fssh 中的密钥和主密钥会保留。",
	},
	"uninstall.plan_purge": {
		EN: "--purge: ALL keys in ~/.fssh and the master key will be deleted permanently.",
		ZH: "--purge：~/.fssh 中的所有密钥和主密钥将被永久删除。",
	},
	"uninstall.confirm": {
		EN: "Continue?",
		ZH: "继续吗？",
	},
	"uninstall.purge_warning": {
		EN: "%d key(s) will be deleted permanently.",
		ZH: "%d 个密钥将被永久删除。",
	},
	"uninstall.launchd_removed": {
		EN: "Removed auto-start",
		ZH: "已移除开机自启",
	},
	"uninstall.sshconfig_block": {
		EN: "Removed the fssh block from ~/.ssh/config",
		ZH: "已从 ~/.ssh/config 移除 fssh 配置块",
	},
	"uninstall.sshconfig_hosts": {
		EN: "Removed fssh settings from hosts: %s",
		ZH: "已移除以下主机的 fssh 设置: %s",
	},
	"uninstall.shellenv": {
		EN: "Removed SSH_AUTH_SOCK from %s",
		ZH: "已从 %s 移除 SSH_AUTH_SOCK",
	},
	"uninstall.purged": {
		EN: "Deleted %s and the master key",
		ZH: "已删除 %s 和主密钥",
	},
	"uninstall.kept": {
		EN: "Kept %s and the master key. Reinstall to use them again, or run `fssh uninstall --purge` to delete them.",
		ZH: "已保留 %s 和主密钥。重新安装即可继续使用；如需删除请运行 `fssh uninstall --purge`。",
	},
	"uninstall.binary": {
		EN: "Finally remove the program: sudo rm %s",
		ZH: "最后删除程序本身: sudo rm %s",
	},
	"uninstall.binary_brew": {
		EN: "Finally remove the program: brew uninstall fssh",
		ZH: "最后删除程序本身: brew uninstall fssh",
	},

	// ---- interactive shell ----
	"shell.1_no_proxy": {
		EN: "  1) No proxy",
		ZH: "  1) 不使用代理",
	},
	"shell.1_use_fssh_agent": {
		EN: "  1) Use fssh agent",
		ZH: "  1) 使用 fssh agent",
	},
	"shell.1_use_fssh_agent_recommended": {
		EN: "  1) Use fssh agent (recommended)",
		ZH: "  1) 使用 fssh agent（推荐）",
	},
	"shell.2_direct_identityfile": {
		EN: "  2) Direct IdentityFile",
		ZH: "  2) 直接指定 IdentityFile",
	},
	"shell.2_direct_identityfile_path": {
		EN: "  2) Direct IdentityFile path",
		ZH: "  2) 直接指定 IdentityFile 路径",
	},
	"shell.2_socks5_proxy": {
		EN: "  2) SOCKS5 proxy",
		ZH: "  2) SOCKS5 代理",
	},
	"shell.3_none": {
		EN: "  3) None",
		ZH: "  3) 不使用",
	},
	"shell.3_none_password_authentication": {
		EN: "  3) None (password authentication)",
		ZH: "  3) 不使用（密码登录）",
	},
	"shell.3_ssh_jump_host": {
		EN: "  3) SSH jump host",
		ZH: "  3) SSH 跳板机",
	},
	"shell.3_ssh_jump_host_proxyjump": {
		EN: "  3) SSH jump host (ProxyJump)",
		ZH: "  3) SSH 跳板机（ProxyJump）",
	},
	"shell.4_custom_proxycommand": {
		EN: "  4) Custom ProxyCommand",
		ZH: "  4) 自定义 ProxyCommand",
	},
	"shell.add_add_new_ssh_host": {
		EN: "  add               - Add new SSH host",
		ZH: "  add               - 添加主机",
	},
	"shell.add_new_ssh_host": {
		EN: "\n=== Add New SSH Host ===",
		ZH: "\n=== 添加主机 ===",
	},
	"shell.arguments_are_passed_to_ssh_e": {
		EN: "                      arguments are passed to ssh (e.g. connect me@1.2.3.4 -p 2222)",
		ZH: "                      会原样传给 ssh（例如 connect me@1.2.3.4 -p 2222）",
	},
	"shell.backup_created": {
		EN: "✓ Backup created\n",
		ZH: "✓ 已创建备份\n",
	},
	"shell.backup_created_2": {
		EN: "✓ Backup created",
		ZH: "✓ 已创建备份",
	},
	"shell.cancelled": {
		EN: "Cancelled",
		ZH: "已取消",
	},
	"shell.change_identity_configuration_y_n": {
		EN: "\nChange identity configuration? [y/N]: ",
		ZH: "\n修改私钥配置？[y/N]: ",
	},
	"shell.change_proxy_configuration_y_n": {
		EN: "\nChange proxy configuration? [y/N]: ",
		ZH: "\n修改代理配置？[y/N]: ",
	},
	"shell.choice": {
		EN: "Choice: ",
		ZH: "请选择: ",
	},
	"shell.choice_1": {
		EN: "Choice [1]: ",
		ZH: "请选择 [1]: ",
	},
	"shell.commands": {
		EN: "Commands:",
		ZH: "命令:",
	},
	"shell.connect_host_ssh_args_connect_to": {
		EN: "  connect <host> [ssh args] - Connect to host; unknown hosts and extra",
		ZH: "  connect <主机> [ssh 参数] - 连接主机；不在配置中的主机和额外参数",
	},
	"shell.create_it_now_y_n": {
		EN: "Create it now? [Y/n]: ",
		ZH: "现在创建？[Y/n]: ",
	},
	"shell.defined_in_s_read_only_in": {
		EN: "Defined in: %s (read-only in fssh)\n",
		ZH: "定义于: %s（fssh 中只读）\n",
	},
	"shell.delete_host_delete_host": {
		EN: "  delete <host>     - Delete host",
		ZH: "  delete <主机>     - 删除主机",
	},
	"shell.delete_host_s": {
		EN: "\n=== Delete Host: %s ===\n",
		ZH: "\n=== 删除主机: %s ===\n",
	},
	"shell.edit_global_configuration_host": {
		EN: "\n=== Edit Global Configuration (Host *) ===",
		ZH: "\n=== 编辑全局配置（Host *）===",
	},
	"shell.edit_host_edit_existing_host": {
		EN: "  edit <host>       - Edit existing host",
		ZH: "  edit <主机>       - 编辑主机",
	},
	"shell.edit_host_s": {
		EN: "\n=== Edit Host: %s ===\n",
		ZH: "\n=== 编辑主机: %s ===\n",
	},
	"shell.empty": {
		EN: "  (empty)",
		ZH: "  （空）",
	},
	"shell.error_host_alias_is_required": {
		EN: "Error: Host alias is required",
		ZH: "错误：必须填写主机别名",
	},
	"shell.error_hostname_is_required": {
		EN: "Error: Hostname is required",
		ZH: "错误：必须填写主机名",
	},
	"shell.example": {
		EN: "\nExample:",
		ZH: "\n示例:",
	},
	"shell.exit_quit_exit_shell": {
		EN: "  exit / quit       - Exit shell",
		ZH: "  exit / quit       - 退出",
	},
	"shell.failed_to_delete_w": {
		EN: "failed to delete: %w",
		ZH: "删除失败: %w",
	},
	"shell.failed_to_load_global_config_w": {
		EN: "failed to load global config: %w",
		ZH: "读取全局配置失败: %w",
	},
	"shell.failed_to_save_w": {
		EN: "failed to save: %w",
		ZH: "保存失败: %w",
	},
	"shell.failed_to_set_option_w": {
		EN: "failed to set option: %w",
		ZH: "设置选项失败: %w",
	},
	"shell.failed_to_unset_option_w": {
		EN: "failed to unset option: %w",
		ZH: "删除选项失败: %w",
	},
	"shell.fssh_key_s_identitiesonly_s": {
		EN: "fssh key: %s (IdentitiesOnly %s)\n",
		ZH: "fssh 密钥: %s（IdentitiesOnly %s）\n",
	},
	"shell.global_configuration_updated": {
		EN: "\n✓ Global configuration updated",
		ZH: "\n✓ 已更新全局配置",
	},
	"shell.global_edit_edit_global_config_interactively": {
		EN: "    global edit           - Edit global config interactively",
		ZH: "    global edit           - 交互式编辑全局配置",
	},
	"shell.global_edit_edit_global_config_interactively_2": {
		EN: "  global edit           - Edit global config interactively",
		ZH: "  global edit           - 交互式编辑全局配置",
	},
	"shell.global_set_key_value_set_a": {
		EN: "    global set <key> <value> - Set a single option",
		ZH: "    global set <选项> <值> - 设置单个选项",
	},
	"shell.global_set_key_value_set_a_2": {
		EN: "  global set <key> <value> - Set a single option",
		ZH: "  global set <选项> <值> - 设置单个选项",
	},
	"shell.global_show_display_current_global_config": {
		EN: "    global show           - Display current global config",
		ZH: "    global show           - 查看全局配置",
	},
	"shell.global_show_display_current_global_config_2": {
		EN: "  global show           - Display current global config",
		ZH: "  global show           - 查看全局配置",
	},
	"shell.global_show_edit_set_unset_manage": {
		EN: "  global [show|edit|set|unset] - Manage global SSH config (Host *)",
		ZH: "  global [show|edit|set|unset] - 管理全局配置（Host *）",
	},
	"shell.global_ssh_configuration_host": {
		EN: "\n=== Global SSH Configuration (Host *) ===",
		ZH: "\n=== 全局 SSH 配置（Host *）===",
	},
	"shell.global_unset_key_remove_a_single": {
		EN: "    global unset <key>    - Remove a single option",
		ZH: "    global unset <选项>   - 删除单个选项",
	},
	"shell.global_unset_key_remove_a_single_2": {
		EN: "  global unset <key>    - Remove a single option",
		ZH: "  global unset <选项>   - 删除单个选项",
	},
	"shell.help_show_this_help": {
		EN: "  help              - Show this help",
		ZH: "  help              - 显示帮助",
	},
	"shell.host_alias_e_g_myserver": {
		EN: "Host alias (e.g., myserver): ",
		ZH: "主机别名（例如 myserver）: ",
	},
	"shell.host_block_does_not_exist": {
		EN: "\nHost * block does not exist.",
		ZH: "\nHost * 配置块不存在。",
	},
	"shell.host_not_found_s": {
		EN: "host not found: %s",
		ZH: "找不到主机: %s",
	},
	"shell.host_not_found_w": {
		EN: "host not found: %w",
		ZH: "找不到主机: %w",
	},
	"shell.host_s_added_to_ssh_config": {
		EN: "\n✓ Host '%s' added to ~/.ssh/config\n",
		ZH: "\n✓ 已将主机 %s 添加到 ~/.ssh/config\n",
	},
	"shell.host_s_deleted_from_ssh_config": {
		EN: "\n✓ Host '%s' deleted from ~/.ssh/config\n",
		ZH: "\n✓ 已从 ~/.ssh/config 删除主机 %s\n",
	},
	"shell.host_s_is_defined_in_s": {
		EN: "host %s is defined in %s; edit that file directly",
		ZH: "主机 %s 定义在 %s 中，请直接编辑该文件",
	},
	"shell.host_s_updated": {
		EN: "\n✓ Host '%s' updated\n",
		ZH: "\n✓ 已更新主机 %s\n",
	},
	"shell.hostname_or_ip": {
		EN: "Hostname or IP: ",
		ZH: "主机名或 IP: ",
	},
	"shell.hostname_s_no_hostname_ssh_connects": {
		EN: "Hostname: %s (no HostName, ssh connects to the host name itself)\n",
		ZH: "Hostname: %s（未设置 HostName，ssh 直接连接该名称）\n",
	},
	"shell.identityfile_path": {
		EN: "IdentityFile path: ",
		ZH: "IdentityFile 路径: ",
	},
	"shell.imported_keys": {
		EN: "\nImported keys:",
		ZH: "\n已导入的密钥:",
	},
	"shell.info_id_alias_hostname_ip_show": {
		EN: "  info <id|alias|hostname|ip> - Show host info by any identifier",
		ZH: "  info <编号|别名|主机名|IP> - 按任意标识查看主机详情",
	},
	"shell.ip_hidden_proxy_fake_ip_address": {
		EN: "IP: (hidden: proxy fake-ip address)",
		ZH: "IP: （已隐藏：代理返回的 fake-ip 地址）",
	},
	"shell.jump_host_user_host_or_just": {
		EN: "Jump host (user@host or just host): ",
		ZH: "跳板机（user@host 或 host）: ",
	},
	"shell.key_for_this_host_number_or": {
		EN: "Key for this host (number or alias, Enter = any key in the agent): ",
		ZH: "该主机使用的密钥（编号或别名，回车表示可用 agent 中任意密钥）: ",
	},
	"shell.list_r_list_all_ssh_hosts": {
		EN: "  list [-r]         - List all SSH hosts (-r: resolve IP addresses)",
		ZH: "  list [-r]         - 列出所有主机（-r：解析 IP 地址）",
	},
	"shell.no_host_block_found_in_ssh": {
		EN: "\nNo Host * block found in ~/.ssh/config",
		ZH: "\n~/.ssh/config 中没有 Host * 配置块",
	},
	"shell.port_22": {
		EN: "Port [22]: ",
		ZH: "端口 [22]: ",
	},
	"shell.port_22_default": {
		EN: "Port: 22 (default)\n",
		ZH: "Port: 22（默认）\n",
	},
	"shell.press_enter_to_keep_current_value": {
		EN: "Press Enter to keep current value, or type new value",
		ZH: "回车保留当前值，或输入新值",
	},
	"shell.press_enter_to_keep_current_value_2": {
		EN: "Press Enter to keep current value, type new value to change, or '-' to clear",
		ZH: "回车保留当前值，输入新值修改，输入 - 清除",
	},
	"shell.private_key_configuration": {
		EN: "\nPrivate Key Configuration:",
		ZH: "\n私钥配置:",
	},
	"shell.proxy_configuration": {
		EN: "\nProxy Configuration:",
		ZH: "\n代理配置:",
	},
	"shell.save_changes_y_n": {
		EN: "\nSave changes? [Y/n]: ",
		ZH: "\n保存修改？[Y/n]: ",
	},
	"shell.save_global_configuration_y_n": {
		EN: "Save global configuration? [Y/n]: ",
		ZH: "保存全局配置？[Y/n]: ",
	},
	"shell.save_this_configuration_y_n": {
		EN: "\nSave this configuration? [Y/n]: ",
		ZH: "\n保存该配置？[Y/n]: ",
	},
	"shell.search_term_search_hosts_by_name": {
		EN: "  search <term>     - Search hosts by name/alias/hostname",
		ZH: "  search <关键词>   - 按名称/别名/主机名搜索",
	},
	"shell.set_s_s": {
		EN: "\n✓ Set %s = %s\n",
		ZH: "\n✓ 已设置 %s = %s\n",
	},
	"shell.shortcuts_type_host_name_directly_to": {
		EN: "Shortcuts: Type host name directly to connect",
		ZH: "快捷方式：直接输入主机名即可连接",
	},
	"shell.show_host_show_host_details": {
		EN: "  show <host>       - Show host details",
		ZH: "  show <主机>       - 查看主机详情",
	},
	"shell.socks5_proxy_host": {
		EN: "SOCKS5 proxy host: ",
		ZH: "SOCKS5 代理主机: ",
	},
	"shell.socks5_proxy_port_1080": {
		EN: "SOCKS5 proxy port [1080]: ",
		ZH: "SOCKS5 代理端口 [1080]: ",
	},
	"shell.summary": {
		EN: "\n=== Summary ===",
		ZH: "\n=== 汇总 ===",
	},
	"shell.supported_options": {
		EN: "\nSupported options:",
		ZH: "\n支持的选项:",
	},
	"shell.suspend_suspend_fssh_use_fg_to": {
		EN: "  suspend           - Suspend fssh (use 'fg' to resume)",
		ZH: "  suspend           - 挂起 fssh（用 fg 恢复）",
	},
	"shell.tip_use_global_edit_for_interactive": {
		EN: "\nTip: Use 'global edit' for interactive editing with help",
		ZH: "\n提示：用 global edit 可以交互式编辑并查看说明",
	},
	"shell.tool_a": {
		EN: "Tool [a]: ",
		ZH: "工具 [a]: ",
	},
	"shell.type_to_see_detailed_help_for": {
		EN: "Type '?' to see detailed help for an option",
		ZH: "输入 ? 查看该选项的详细说明",
	},
	"shell.type_yes_to_confirm_deletion": {
		EN: "\nType 'yes' to confirm deletion: ",
		ZH: "\n输入 yes 确认删除: ",
	},
	"shell.unknown_global_subcommand_usage": {
		EN: "Unknown global subcommand. Usage:",
		ZH: "未知的 global 子命令。用法:",
	},
	"shell.unknown_key_try_again": {
		EN: "Unknown key, try again.",
		ZH: "没有这个密钥，请重试。",
	},
	"shell.unset_s": {
		EN: "\n✓ Unset %s\n",
		ZH: "\n✓ 已删除 %s\n",
	},
	"shell.unterminated_quote_or_escape": {
		EN: "unterminated quote or escape",
		ZH: "引号或转义符未闭合",
	},
	"shell.usage_delete_host": {
		EN: "Usage: delete <host>",
		ZH: "用法: delete <主机>",
	},
	"shell.usage_edit_host": {
		EN: "Usage: edit <host>",
		ZH: "用法: edit <主机>",
	},
	"shell.usage_global_set_key_value": {
		EN: "Usage: global set <key> <value>",
		ZH: "用法: global set <选项> <值>",
	},
	"shell.usage_global_unset_key": {
		EN: "Usage: global unset <key>",
		ZH: "用法: global unset <选项>",
	},
	"shell.usage_info_id_alias_hostname_ip": {
		EN: "Usage: info <id|alias|hostname|ip>",
		ZH: "用法: info <编号|别名|主机名|IP>",
	},
	"shell.usage_show_host": {
		EN: "Usage: show <host>",
		ZH: "用法: show <主机>",
	},
	"shell.username_press_enter_to_skip": {
		EN: "Username [press Enter to skip]: ",
		ZH: "用户名 [回车跳过]: ",
	},
	"shell.using_password_authentication": {
		EN: "Using password authentication",
		ZH: "将使用密码登录",
	},
	"shell.valid_values_s": {
		EN: "Valid values: %s\n",
		ZH: "可选值: %s\n",
	},
	"shell.warning_failed_to_reload_hosts_v": {
		EN: "Warning: Failed to reload hosts: %v\n",
		ZH: "警告：重新加载主机列表失败: %v\n",
	},
	"shell.warning_host_s_already_exists_use": {
		EN: "Warning: Host '%s' already exists. Use 'edit %s' to modify.\n",
		ZH: "警告：主机 %s 已存在，请用 edit %s 修改。\n",
	},
	"shell.warning_no_keys_imported_yet_run": {
		EN: "Warning: No keys imported yet. Run 'fssh import' or 'fssh keygen' first.",
		ZH: "警告：还没有密钥，请先运行 fssh import 或 fssh keygen。",
	},
	"shell.you_can_create_one_with_global": {
		EN: "\nYou can create one with: global edit",
		ZH: "\n可以用 global edit 创建",
	},
	"shell.you_can_now_connect_with_ssh": {
		EN: "\nYou can now connect with: ssh %s\n",
		ZH: "\n现在可以连接: ssh %s\n",
	},

	// ---- errors & misc ----
	"keychain.canceled": {
		EN: "Keychain access was canceled",
		ZH: "已取消钥匙串授权",
	},
	"keychain.store_failed": {
		EN: "could not store the master key in the Keychain (%d attempts): %w",
		ZH: "无法将主密钥存入钥匙串（已尝试 %d 次）: %w",
	},
	"keychain.not_initialized": {
		EN: "no master key in the Keychain; run `fssh init`",
		ZH: "钥匙串中没有主密钥，请运行 `fssh init`",
	},
	"otpcfg.read": {
		EN: "cannot read the OTP config: %w",
		ZH: "读取 OTP 配置失败: %w",
	},
	"otpcfg.parse": {
		EN: "the OTP config is damaged: %w",
		ZH: "OTP 配置已损坏: %w",
	},
	"otpcfg.version": {
		EN: "unsupported OTP config version: %s",
		ZH: "不支持的 OTP 配置版本: %s",
	},
	"otpcfg.incomplete": {
		EN: "the OTP config is damaged: required fields are missing",
		ZH: "OTP 配置已损坏：缺少必要字段",
	},
	"otpcfg.write": {
		EN: "cannot write the OTP config: %w",
		ZH: "写入 OTP 配置失败: %w",
	},
	"auth.unknown_mode": {
		EN: "unknown auth mode %q in ~/.fssh/auth_mode.json",
		ZH: "~/.fssh/auth_mode.json 中的认证模式 %q 无效",
	},
	"auth.mode_read": {
		EN: "cannot read ~/.fssh/auth_mode.json: %w",
		ZH: "读取 ~/.fssh/auth_mode.json 失败: %w",
	},
	"auth.mode_parse": {
		EN: "~/.fssh/auth_mode.json is damaged: %w",
		ZH: "~/.fssh/auth_mode.json 已损坏: %w",
	},
	"agent.started": {
		EN: "Agent started: %s",
		ZH: "Agent 已启动: %s",
	},
	"agent.started_hint": {
		EN: "Press Ctrl-C to stop. Run `fssh doctor` if ssh does not use it.",
		ZH: "按 Ctrl-C 停止。如果 ssh 没有使用它，请运行 `fssh doctor`。",
	},
	"cli.config_invalid": {
		EN: "~/.fssh/config.json is invalid: %w",
		ZH: "~/.fssh/config.json 格式错误: %w",
	},
	"cli.one_passphrase_source": {
		EN: "use only one of --passphrase, --ask-passphrase, --passphrase-file and --passphrase-stdin",
		ZH: "--passphrase、--ask-passphrase、--passphrase-file、--passphrase-stdin 只能使用一个",
	},
	"configgen.usage": {
		EN: "usage: fssh config-gen --host <name> [--user u] [--port p] [--write]",
		ZH: "用法: fssh config-gen --host <名称> [--user 用户] [--port 端口] [--write]",
	},
	"configgen.wrote": {
		EN: "Updated %s",
		ZH: "已更新 %s",
	},
}
