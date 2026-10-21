package prompt

import (
	"strings"
	"testing"
	"time"
)

// User-controlled text (process names, hosts) must travel as osascript
// arguments, never inside the script, so it cannot inject AppleScript.
func TestDialogArgsKeepMessageOutOfScript(t *testing.T) {
	msg := `evil" & (do shell script "id") & "`
	args := dialogArgs(msg, true, 30*time.Second)

	var script []string
	for i := 0; i+1 < len(args) && args[i] == "-e"; i += 2 {
		script = append(script, args[i+1])
	}
	joined := strings.Join(script, "\n")
	if strings.Contains(joined, "do shell script") {
		t.Fatal("message leaked into the AppleScript source")
	}
	if !strings.Contains(joined, "with hidden answer") || !strings.Contains(joined, "giving up after 30") {
		t.Fatalf("unexpected script: %s", joined)
	}
	if args[2*len(script)] != msg {
		t.Fatalf("message must be the first script argument, got %q", args[2*len(script)])
	}
	if strings.Contains(strings.Join(dialogArgs("x", false, time.Minute), " "), "hidden answer") {
		t.Fatal("visible prompt must not hide input")
	}
}
