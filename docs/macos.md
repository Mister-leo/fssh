# macOS 安装与开机自启 fssh agent

## 系统要求
- macOS 12+（Monterey/Ventura/Sonoma）
- 终端使用 zsh 或 bash

## 安装 fssh
- 构建并安装：
  - 在项目目录执行：`go build ./cmd/fssh`
  - 将生成的二进制复制到可执行路径：`/usr/local/bin/fssh`

## 初始化与导入密钥
- 初始化主密钥（受 Touch ID 保护）：`fssh init`
- 导入私钥：`fssh import --alias default --file ~/.ssh/id_ed25519 --ask-passphrase`
- 查看密钥列表：`fssh list`

## 配置环境变量（终端会话）
- 在 `~/.zshrc` 或 `~/.bash_profile` 添加：
```
export SSH_AUTH_SOCK=/Users/leo/.fssh/agent.sock
```
- 重新加载：`source ~/.zshrc`

## 开机（登录）自启配置
- 将示例文件 `contrib/com.fssh.agent.plist` 复制到：`~/Library/LaunchAgents/com.fssh.agent.plist`
- 启用（任选其一）：
  - 旧语法：`launchctl load -w ~/Library/LaunchAgents/com.fssh.agent.plist`
  - 新语法：`launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.fssh.agent.plist`
- 验证：
  - `launchctl list | grep com.fssh.agent`
  - `lsof -U ~/.fssh/agent.sock`
  - `ssh-add -l`

## 使用
- 普通 ssh：`ssh user@host`
- 交互式 shell：`fssh`，使用 `list/search/connect` 和 Tab 补全

## 常见问题
- GUI 程序（VSCode 等）不继承终端环境：可执行 `launchctl setenv SSH_AUTH_SOCK ~/.fssh/agent.sock`，或在应用启动器中显式设置。
- 每次签名触发 Touch ID：保持 `--require-touch-id-per-sign=true`；如希望一次性解锁，可设为 `false`。

## 卸载
- `launchctl unload -w ~/Library/LaunchAgents/com.fssh.agent.plist`
- 删除 `~/Library/LaunchAgents/com.fssh.agent.plist`
- 从 `~/.zshrc`/`~/.bash_profile` 移除 `SSH_AUTH_SOCK` 配置
## 配置文件
- 路径：`~/.fssh/config.json`
- 示例：
```
{
  "socket": "~/.fssh/agent.sock",
  "require_touch_id_per_sign": true,
  "log_out": "/var/tmp/fssh-agent.out.log",
  "log_err": "/var/tmp/fssh-agent.err.log"
}
```
- 优先级：命令行参数 > 配置文件 > 默认值
- 说明：日志路径如在配置文件设置，程序会将标准输出/错误重定向到对应文件；如不设置，日志由系统接管或输出到控制台。