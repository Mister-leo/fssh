package main

import (
	"crypto/rand"
	"fmt"
	"io"

	"fssh/internal/auth"
	"fssh/internal/keychain"
	"fssh/internal/otp"
)

// initOTPMode 初始化 OTP 认证模式
func initOTPMode(force bool, seedTTL int, algorithm string, digits int) {
	// 检查是否已存在 OTP 配置
	if otp.ConfigExists() && !force {
		fmt.Println("OTP 配置已存在，使用 --force 覆盖")
		return
	}

	// 提示设置密码
	fmt.Println("初始化 OTP 认证模式")
	fmt.Println()

	password, err := otp.PromptPasswordWithConfirm(
		"请设置 OTP 密码（至少12位）: ",
		"确认密码: ",
	)
	if err != nil {
		fatal(err)
	}

	// 初始化选项
	opts := &otp.InitOptions{
		Password:         password,
		SeedUnlockTTL:    seedTTL,
		Algorithm:        algorithm,
		Digits:           digits,
		Period:           30,
		GenerateRecovery: true,
	}

	// 执行初始化
	seed, recoveryCodes, err := otp.Initialize(opts)
	if err != nil {
		fatal(err)
	}

	// master key 每次由 seed 派生，不写入 Keychain：写入后只凭开机密码就能绕过 OTP
	// 显示结果
	if err := otp.DisplayInitResult(seed, recoveryCodes, algorithm, digits, 30); err != nil {
		fatal(err)
	}

	// 保存认证模式
	if err := auth.SaveMode(auth.ModeOTP); err != nil {
		fatal(fmt.Errorf("保存认证模式失败: %w", err))
	}
}

// initTouchIDMode 初始化 Touch ID 认证模式
func initTouchIDMode(force bool) {
	exists, err := keychain.MasterKeyExists()
	if err != nil {
		fatal(err)
	}
	if exists && !force {
		fmt.Println("master key already exists")
		return
	}

	// 如果是重新初始化，给用户一个提示
	if exists && force {
		fmt.Println("正在重新初始化 master key...")
	} else {
		fmt.Println("正在初始化 master key...")
		fmt.Println()
		fmt.Println("⚠️  macOS 可能会弹出对话框:")
		fmt.Println("   「fssh 想要使用您存储在钥匙串中的机密信息」")
		fmt.Println()
		fmt.Println("   这是正常的安全提示，请:")
		fmt.Println("   1. 点击「允许」或输入您的 macOS 用户密码")
		fmt.Println("   2. 首次授权后，后续不会再提示")
		fmt.Println()
	}

	mk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, mk); err != nil {
		fatal(err)
	}

	fmt.Println("正在保存到 Keychain...")
	if err := keychain.StoreMasterKey(mk, force); err != nil {
		fmt.Println()
		fmt.Println("❌ Keychain 操作失败")
		fmt.Println()
		fmt.Println("可能的原因:")
		fmt.Println("  • 您点击了「拒绝」而不是「允许」")
		fmt.Println("  • macOS 安全设置阻止了访问")
		fmt.Println("  • Keychain 服务异常")
		fmt.Println()
		fmt.Println("解决方法:")
		fmt.Println("  1. 重新运行: fssh init")
		fmt.Println("  2. 这次请点击「允许」")
		fmt.Println("  3. 如果仍失败，请检查系统「安全性与隐私」设置")
		fmt.Println()
		fatal(err)
	}

	// 保存认证模式
	if err := auth.SaveMode(auth.ModeTouchID); err != nil {
		fmt.Printf("警告: 保存认证模式失败: %v\n", err)
	}

	fmt.Println("✓ 已成功初始化 master key (Touch ID 保护)")
}
