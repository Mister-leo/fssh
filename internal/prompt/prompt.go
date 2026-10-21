// Package prompt asks the user for secrets either on the terminal or, for the
// agent running in the background, through native macOS dialogs.
package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"fssh/internal/i18n"

	"golang.org/x/term"
)

// ErrCanceled is returned when the user dismisses the prompt.
var ErrCanceled = errors.New("canceled by user")

// Prompter collects input from the user.
type Prompter interface {
	// Password reads a secret without echo.
	Password(msg string) (string, error)
	// Text reads visible input, e.g. a TOTP code.
	Text(msg string) (string, error)
	// Notify shows a non-blocking message.
	Notify(title, msg string)
}

// Default returns a terminal prompter when stdin is a terminal, otherwise a
// GUI prompter (e.g. when started by launchd).
func Default() Prompter {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return TTY{}
	}
	return GUI{}
}

// ---- terminal ----

// TTY prompts on the controlling terminal.
type TTY struct{}

var (
	stdinOnce   sync.Once
	stdinReader *bufio.Reader
)

// sharedStdin avoids losing buffered input between successive prompts.
func sharedStdin() *bufio.Reader {
	stdinOnce.Do(func() { stdinReader = bufio.NewReader(os.Stdin) })
	return stdinReader
}

func (TTY) Password(msg string) (string, error) {
	fmt.Fprint(os.Stderr, msg)
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return readLine()
	}
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (TTY) Text(msg string) (string, error) {
	fmt.Fprint(os.Stderr, msg)
	s, err := readLine()
	return strings.TrimSpace(s), err
}

func (TTY) Notify(title, msg string) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", title, msg)
}

// readLine returns the next line without its line ending. EOF with no input
// counts as cancellation.
func readLine() (string, error) {
	s, err := sharedStdin().ReadString('\n')
	if err != nil {
		if !errors.Is(err, io.EOF) {
			return "", err
		}
		if s == "" {
			return "", ErrCanceled
		}
	}
	return strings.TrimRight(s, "\r\n"), nil
}

// ---- macOS dialogs ----

// GUI shows native dialogs via osascript. Text is passed as script
// arguments, never interpolated into the script, so it needs no escaping.
type GUI struct {
	// Timeout closes an unanswered dialog; zero means 120 seconds.
	Timeout time.Duration
}

func (g GUI) Password(msg string) (string, error) { return g.dialog(msg, true) }
func (g GUI) Text(msg string) (string, error)     { return g.dialog(msg, false) }

func (g GUI) Notify(title, msg string) {
	_ = exec.Command("osascript", notifyArgs(title, msg)...).Run()
}

func (g GUI) dialog(msg string, hidden bool) (string, error) {
	timeout := g.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	out, err := exec.Command("osascript", dialogArgs(msg, hidden, timeout)...).Output()
	if err != nil {
		var ee *exec.ExitError
		// -128 is AppleScript's "User canceled"; the script also raises it on timeout
		if errors.As(err, &ee) && strings.Contains(string(ee.Stderr), "-128") {
			return "", ErrCanceled
		}
		return "", fmt.Errorf("osascript: %w", err)
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}

func dialogArgs(msg string, hidden bool, timeout time.Duration) []string {
	hiddenClause := ""
	if hidden {
		hiddenClause = " with hidden answer"
	}
	script := []string{
		"on run argv",
		"set r to display dialog (item 1 of argv) with title (item 2 of argv) default answer \"\"" + hiddenClause +
			" buttons {(item 3 of argv), (item 4 of argv)} default button 2 cancel button 1 with icon caution" +
			fmt.Sprintf(" giving up after %d", int(timeout/time.Second)),
		"if gave up of r then error number -128",
		"return text returned of r",
		"end run",
	}
	return withArgs(script, msg, "fssh", i18n.T("prompt.cancel"), i18n.T("prompt.ok"))
}

func notifyArgs(title, msg string) []string {
	script := []string{
		"on run argv",
		"display notification (item 2 of argv) with title (item 1 of argv)",
		"end run",
	}
	return withArgs(script, title, msg)
}

func withArgs(script []string, argv ...string) []string {
	var args []string
	for _, line := range script {
		args = append(args, "-e", line)
	}
	return append(args, argv...)
}
