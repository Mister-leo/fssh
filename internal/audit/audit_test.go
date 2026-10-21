package audit

import (
	"fmt"
	"os"
	"testing"
)

func TestAppendTail(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if es, err := Tail(10); err != nil || len(es) != 0 {
		t.Fatalf("empty log: %v, %v", es, err)
	}
	for i := 0; i < 5; i++ {
		if err := Append(Entry{Alias: fmt.Sprintf("k%d", i), Result: ResultOK}); err != nil {
			t.Fatal(err)
		}
	}
	if fi, err := os.Stat(Path()); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("audit log mode = %v, %v; want 0600", fi.Mode().Perm(), err)
	}
	es, err := Tail(2)
	if err != nil || len(es) != 2 || es[0].Alias != "k3" || es[1].Alias != "k4" {
		t.Fatalf("Tail(2) = %+v, %v", es, err)
	}
}
