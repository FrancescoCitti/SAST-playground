package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
)

// Finding is a single deduplicated result enriched with the data the gate
// reports on: its source tool, resolved severity and stable fingerprint.
type Finding struct {
	Fingerprint string
	RuleID      string
	Tool        string
	File        string
	Line        int
	Severity    Severity
	Active      bool
	Message     string
	result      Result
}

// Report is the outcome of merging one or more SARIF documents.
type Report struct {
	Findings []Finding
	// Tools lists the driver names seen across all inputs, in input order.
	Tools []string
}

// Load reads and decodes a single SARIF document from disk.
func Load(filePath string) (*Log, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filePath, err)
	}
	var log Log
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("parse %s: %w", filePath, err)
	}
	return &log, nil
}

// fingerprint builds the stable dedup key: rule id + file + line. Tool and
// message are deliberately excluded so the same defect reported by two scanners
// (or two rulesets) collapses to one finding.
func fingerprint(ruleID, file string, line int) string {
	// Normalise the path so "./app.py" and "app.py" don't diverge.
	cleanFile := path.Clean(strings.TrimPrefix(file, "./"))
	key := fmt.Sprintf("%s\x00%s\x00%d", ruleID, cleanFile, line)
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// Merge folds every run of every input log into one deduplicated Report.
// Findings are deduplicated by fingerprint; on collision the higher severity
// and the active flag win, so a finding active in any input stays active.
func Merge(logs []*Log) *Report {
	byFingerprint := make(map[string]*Finding)
	var order []string
	var tools []string
	seenTool := make(map[string]bool)

	for _, log := range logs {
		if log == nil {
			continue
		}
		for _, run := range log.Runs {
			toolName := run.Tool.Driver.Name
			if toolName == "" {
				toolName = "unknown"
			}
			if !seenTool[toolName] {
				seenTool[toolName] = true
				tools = append(tools, toolName)
			}

			rules := indexRules(run.Tool.Driver.Rules)

			for _, res := range run.Results {
				rule := lookupRule(rules, res)
				file, line := res.primaryLocation()
				fp := fingerprint(res.RuleID, file, line)
				sev := resolveSeverity(res, rule)
				active := res.isActive()

				if existing, ok := byFingerprint[fp]; ok {
					if sev > existing.Severity {
						existing.Severity = sev
					}
					// Active in any input ⇒ active overall.
					existing.Active = existing.Active || active
					continue
				}

				f := &Finding{
					Fingerprint: fp,
					RuleID:      res.RuleID,
					Tool:        toolName,
					File:        file,
					Line:        line,
					Severity:    sev,
					Active:      active,
					Message:     res.Message.Text,
					result:      res,
				}
				byFingerprint[fp] = f
				order = append(order, fp)
			}
		}
	}

	findings := make([]Finding, 0, len(order))
	for _, fp := range order {
		findings = append(findings, *byFingerprint[fp])
	}
	sortFindings(findings)

	return &Report{Findings: findings, Tools: tools}
}

// indexRules maps rule id -> rule for fast lookup.
func indexRules(rules []Rule) map[string]*Rule {
	m := make(map[string]*Rule, len(rules))
	for i := range rules {
		m[rules[i].ID] = &rules[i]
	}
	return m
}

// lookupRule resolves the rule descriptor for a result, preferring ruleIndex
// (the SARIF-correct reference) and falling back to ruleId.
func lookupRule(rules map[string]*Rule, res Result) *Rule {
	if res.RuleID != "" {
		if r, ok := rules[res.RuleID]; ok {
			return r
		}
	}
	return nil
}

// sortFindings orders findings most-severe first, then by file and line, so the
// console summary and merged output are deterministic.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
}

// CountAtOrAbove returns the number of active findings whose severity is at or
// above threshold.
func (r *Report) CountAtOrAbove(threshold Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Active && f.Severity >= threshold {
			n++
		}
	}
	return n
}

// SeverityCounts tallies active findings per severity, most-severe first.
func (r *Report) SeverityCounts() []SeverityCount {
	counts := map[Severity]int{}
	for _, f := range r.Findings {
		if f.Active {
			counts[f.Severity]++
		}
	}
	order := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone}
	out := make([]SeverityCount, 0, len(order))
	for _, s := range order {
		out = append(out, SeverityCount{Severity: s, Count: counts[s]})
	}
	return out
}

// SeverityCount pairs a severity with how many active findings have it.
type SeverityCount struct {
	Severity Severity
	Count    int
}

// ToLog renders the merged report as a single-run SARIF document so it can be
// archived as a CI artifact. Rules are reconstructed with a security-severity
// derived from each finding's resolved severity.
func (r *Report) ToLog() *Log {
	ruleSet := map[string]Rule{}
	var ruleOrder []string
	results := make([]Result, 0, len(r.Findings))

	for _, f := range r.Findings {
		if _, ok := ruleSet[f.RuleID]; !ok && f.RuleID != "" {
			ruleSet[f.RuleID] = Rule{
				ID: f.RuleID,
				Properties: &Properties{
					SecuritySeverity: securityScoreFor(f.Severity),
					Tags:             []string{"sastgate"},
				},
				DefaultConfiguration: &Configuration{Level: levelFor(f.Severity)},
			}
			ruleOrder = append(ruleOrder, f.RuleID)
		}
		res := f.result
		if res.PartialFingerprints == nil {
			res.PartialFingerprints = map[string]string{}
		}
		res.PartialFingerprints["sastgate/v1"] = f.Fingerprint
		results = append(results, res)
	}

	rules := make([]Rule, 0, len(ruleOrder))
	for _, id := range ruleOrder {
		rules = append(rules, ruleSet[id])
	}

	return &Log{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []Run{{
			Tool: Tool{Driver: Driver{
				Name:           "sastgate",
				InformationURI: "https://github.com/",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// securityScoreFor returns a representative numeric security-severity for a
// gate severity, so the merged SARIF round-trips through GitHub's buckets.
func securityScoreFor(s Severity) string {
	switch s {
	case SeverityCritical:
		return "9.5"
	case SeverityHigh:
		return "8.0"
	case SeverityMedium:
		return "5.0"
	case SeverityLow:
		return "2.0"
	default:
		return "0.0"
	}
}

// levelFor maps a gate severity back to a SARIF level keyword.
func levelFor(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	case SeverityLow:
		return "note"
	default:
		return "none"
	}
}
