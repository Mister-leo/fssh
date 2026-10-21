package otp

import (
	"bufio"
	"errors"
	"fmt"
	"fssh/internal/i18n"
	"os"
	"strings"

	"golang.org/x/term"
)

// PromptPassword 安全地提示输入密码（不回显）
func PromptPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	// 检查是否是终端
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// 不是终端，从标准输入读取
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		// 对于密码，只清理 ANSI 转义序列，保留其他字符
		return cleanInput(scanner.Text()), scanner.Err()
	}

	// 终端环境，使用不回显的密码输入
	password, err := term.ReadPassword(fd)
	fmt.Println() // 换行
	if err != nil {
		return "", fmt.Errorf("读取密码失败: %w", err)
	}

	return string(password), nil
}

// PromptConfirm 提示用户确认（y/n）
func PromptConfirm(prompt string) bool {
	fmt.Printf("%s (y/n): ", prompt)

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	answer := scanner.Text()

	// 清理输入：移除空白和控制字符
	answer = cleanInput(answer)
	answer = strings.ToLower(answer)

	return answer == "y" || answer == "yes"
}

// cleanInput 清理用户输入，移除控制序列和多余空白
func cleanInput(input string) string {
	// 移除前后空白
	input = strings.TrimSpace(input)

	// 移除 ANSI 转义序列和其他控制字符
	var cleaned strings.Builder
	inEscape := false
	for _, r := range input {
		// 检测 ANSI 转义序列开始
		if r == '\x1b' || r == '\033' {
			inEscape = true
			continue
		}

		// 如果在转义序列中，跳过直到遇到字母
		if inEscape {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}

		// 过滤其他控制字符（除了换行和制表符，虽然我们也不需要它们）
		if r < 32 || r == 127 {
			continue
		}

		// 过滤 Unicode 空白字符
		if r == '\u3000' || r == '\u00A0' {
			continue
		}

		cleaned.WriteRune(r)
	}

	return strings.TrimSpace(cleaned.String())
}

// PromptInput 提示输入普通文本（可见回显）
func PromptInput(prompt string) (string, error) {
	fmt.Print(prompt)

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("读取输入失败: %w", err)
		}
		return "", nil // EOF
	}

	// 使用 cleanInput 清理控制字符
	return cleanInput(scanner.Text()), nil
}

// ValidatePasswordStrength 验证密码强度
func ValidatePasswordStrength(password string) error {
	// 最小长度检查
	if len(password) < 12 {
		return errors.New(i18n.T("otp.err_password_weak"))
	}

	// 可选：添加更多密码强度检查
	// 例如：大小写字母、数字、特殊字符等

	return nil
}
