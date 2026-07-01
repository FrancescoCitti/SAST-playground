// Command sarifgate merges the SARIF output of several SAST scanners into one
// deduplicated report and acts as a CI gate: it exits non-zero when any active
// finding reaches a configurable severity threshold (default HIGH).
//
// Usage:
//
//	sarifgate [flags] <input.sarif> [<input.sarif> ...]
//
// Flags:
//
//	-threshold   Minimum severity that fails the build: CRITICAL|HIGH|MEDIUM|LOW|NONE (default HIGH)
//	-output      Path to write the merged SARIF document (default: none)
//	-summary     Path to write a GitHub-flavoured Markdown summary (e.g. $GITHUB_STEP_SUMMARY)
//	-glob        Treat positional args as globs and expand them (default: literal paths)
//	-no-fail     Always exit 0; only report. Useful for dry runs.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sastgate/internal/sarif"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sarifgate: "+err.Error())
		// A threshold breach is a gate failure (exit 1); anything else is a
		// usage or I/O error (exit 2).
		if _, ok := err.(*failError); ok {
			os.Exit(1)
		}
		os.Exit(2)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("sarifgate", flag.ContinueOnError)
	thresholdStr := fs.String("threshold", "HIGH", "severity that fails the build: CRITICAL|HIGH|MEDIUM|LOW|NONE")
	output := fs.String("output", "", "write the merged SARIF document to this path")
	summary := fs.String("summary", "", "write a Markdown summary to this path (append if it exists)")
	useGlob := fs.Bool("glob", false, "expand positional arguments as globs")
	noFail := fs.Bool("no-fail", false, "report only; always exit 0")
	if err := fs.Parse(args); err != nil {
		return err
	}

	threshold, err := sarif.ParseSeverity(*thresholdStr)
	if err != nil {
		return err
	}

	inputs, err := collectInputs(fs.Args(), *useGlob)
	if err != nil {
		return err
	}
	if len(inputs) == 0 {
		return fmt.Errorf("no SARIF input files given")
	}

	logs := make([]*sarif.Log, 0, len(inputs))
	for _, in := range inputs {
		log, err := sarif.Load(in)
		if err != nil {
			return err
		}
		logs = append(logs, log)
	}

	report := sarif.Merge(logs)

	if *output != "" {
		if err := writeSARIF(*output, report.ToLog()); err != nil {
			return err
		}
	}

	text := renderReport(report, threshold, inputs)
	fmt.Print(text)
	if *summary != "" {
		if err := appendFile(*summary, text); err != nil {
			return err
		}
	}

	breaches := report.CountAtOrAbove(threshold)
	if breaches > 0 && !*noFail {
		return failf("%d active finding(s) at or above %s threshold", breaches, threshold)
	}
	return nil
}

// failError is returned for a threshold breach so main can exit 1 (a gate
// failure) rather than 2 (a usage/IO error).
type failError struct{ msg string }

func (e *failError) Error() string { return e.msg }

func failf(format string, a ...any) error { return &failError{fmt.Sprintf(format, a...)} }

func collectInputs(args []string, useGlob bool) ([]string, error) {
	if !useGlob {
		return args, nil
	}
	var out []string
	for _, pattern := range args {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("glob %q: %w", pattern, err)
		}
		out = append(out, matches...)
	}
	sort.Strings(out)
	return out, nil
}

func writeSARIF(path string, log *sarif.Log) error {
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("encode merged SARIF: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func appendFile(path, text string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open summary %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		return fmt.Errorf("write summary %s: %w", path, err)
	}
	return nil
}

// renderReport produces a Markdown report that reads cleanly both on a terminal
// and in the GitHub Actions step summary.
func renderReport(report *sarif.Report, threshold sarif.Severity, inputs []string) string {
	var b strings.Builder
	b.WriteString("## SAST gate report\n\n")
	fmt.Fprintf(&b, "Merged %d SARIF file(s) from: %s\n\n", len(inputs), strings.Join(report.Tools, ", "))
	fmt.Fprintf(&b, "Threshold: **%s** (build fails when an active finding is at or above this severity)\n\n", threshold)

	b.WriteString("| Severity | Active findings |\n|---|---|\n")
	for _, sc := range report.SeverityCounts() {
		fmt.Fprintf(&b, "| %s | %d |\n", sc.Severity, sc.Count)
	}
	b.WriteString("\n")

	breaches := report.CountAtOrAbove(threshold)
	if breaches > 0 {
		fmt.Fprintf(&b, "❌ **Gate FAILED** — %d active finding(s) at or above %s.\n\n", breaches, threshold)
	} else {
		fmt.Fprintf(&b, "✅ **Gate PASSED** — no active findings at or above %s.\n\n", threshold)
	}

	b.WriteString("<details><summary>All deduplicated findings</summary>\n\n")
	b.WriteString("| Severity | Tool | Rule | Location | Active |\n|---|---|---|---|---|\n")
	for _, f := range report.Findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		active := "yes"
		if !f.Active {
			active = "suppressed"
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s |\n",
			f.Severity, f.Tool, f.RuleID, loc, active)
	}
	b.WriteString("\n</details>\n")
	return b.String()
}
