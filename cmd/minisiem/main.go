// Command minisiem reads a log file and prints the parsed events.
package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/Apoo007/mini-siem/internal/parser"
)

func main() {
	file := flag.String("file", "testdata/auth.log", "path to auth.log")
	year := flag.Int("year", time.Now().Year(), "year of the log (auth.log has no year)")
	flag.Parse()

	events, skipped, err := parser.ParseFile(*file, *year)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tPROGRAM\tACTION\tUSER\tSOURCE IP\tDETAIL")
	for _, ev := range events {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			ev.Timestamp.Format("2006-01-02 15:04:05"),
			ev.Program, ev.Action, ev.User, ev.SourceIP, ev.Detail)
	}
	w.Flush()

	fmt.Printf("\n%d events parsed, %d lines skipped\n", len(events), skipped)
}