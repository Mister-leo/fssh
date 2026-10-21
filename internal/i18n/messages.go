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
}
