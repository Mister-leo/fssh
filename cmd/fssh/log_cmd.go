package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"fssh/internal/audit"
	"fssh/internal/i18n"
)

// cmdLog shows recent signature requests from the audit log.
func cmdLog() {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	n := fs.Int("n", 20, "number of entries to show")
	fs.Parse(os.Args[2:])

	entries, err := audit.Tail(*n)
	if err != nil {
		fatal(err)
	}
	if len(entries) == 0 {
		fmt.Println(i18n.T("log.empty"))
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, i18n.T("log.header"))
	for _, e := range entries {
		ts := e.Time
		if t, err := time.Parse(time.RFC3339, e.Time); err == nil {
			ts = t.Local().Format("01-02 15:04:05")
		}
		host := e.Host
		if host == "" {
			host = "-"
		}
		if e.Forwarded {
			host += " " + i18n.T("log.forwarded")
		}
		alias := e.Alias
		if alias == "" {
			alias = "-"
		}
		result := i18n.T("log.result_" + e.Result)
		if e.Error != "" && e.Result != audit.ResultOK {
			result += " (" + e.Error + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", ts, alias, e.Process, host, result)
	}
	w.Flush()
}
