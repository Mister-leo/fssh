package main

import (
	"errors"
	"fmt"
	"fssh/internal/i18n"
	"net"
	"os"
	"time"
)

// startAgent starts the fssh agent and verifies it's running
func startAgent() error {
	socketPath := agentSocket()

	// Check if agent is already running
	if _, err := os.Stat(socketPath); err == nil {
		// Try to connect
		if conn, err := net.Dial("unix", socketPath); err == nil {
			conn.Close()
			fmt.Println("✓ " + i18n.T("agentstart.running"))
			return nil
		}

		// Socket exists but not responding, remove it
		_ = os.Remove(socketPath)
	}

	// Agent will be started by LaunchAgent automatically
	// We just need to wait for it to start
	fmt.Println(i18n.T("agentstart.waiting"))

	// Wait up to 10 seconds for socket to appear and be ready
	maxAttempts := 20
	for i := 0; i < maxAttempts; i++ {
		time.Sleep(500 * time.Millisecond)

		if _, err := os.Stat(socketPath); err == nil {
			// Socket exists, try to connect
			if conn, err := net.Dial("unix", socketPath); err == nil {
				conn.Close()
				fmt.Println("✓ " + i18n.T("agentstart.running"))
				return nil
			}
		}

		// Show progress
		if (i+1)%4 == 0 {
			fmt.Print(".")
		}
	}

	fmt.Println()
	return errors.New(i18n.T("agentstart.timeout"))
}
