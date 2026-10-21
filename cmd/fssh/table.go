package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/mattn/go-runewidth"
)

// printTable prints rows with columns padded by display width. tabwriter
// counts runes, so Chinese headers (two columns per character) misalign.
func printTable(w io.Writer, rows [][]string) {
	var widths []int
	for _, r := range rows {
		for i, c := range r {
			if i >= len(widths) {
				widths = append(widths, 0)
			}
			if n := runewidth.StringWidth(c); n > widths[i] {
				widths[i] = n
			}
		}
	}
	for _, r := range rows {
		var b strings.Builder
		for i, c := range r {
			b.WriteString(c)
			if i < len(r)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-runewidth.StringWidth(c)+2))
			}
		}
		fmt.Fprintln(w, b.String())
	}
}
