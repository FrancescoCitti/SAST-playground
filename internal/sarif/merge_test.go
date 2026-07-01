package sarif

import (
	"encoding/json"
	"testing"
)

// mustLog decodes a SARIF document from a literal for use in tests.
func mustLog(t *testing.T, doc string) *Log {
	t.Helper()
	var log Log
	if err := json.Unmarshal([]byte(doc), &log); err != nil {
		t.Fatalf("decode test SARIF: %v", err)
	}
	return &log
}

// semgrepLog reports a high-severity SQL injection via security-severity.
const semgrepLog = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "Semgrep", "rules": [
      {"id": "sql-injection", "properties": {"security-severity": "8.5"}}
    ]}},
    "results": [{
      "ruleId": "sql-injection",
      "level": "error",
      "message": {"text": "tainted SQL"},
      "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "app.py"},
        "region": {"startLine": 10}
      }}]
    }]
  }]
}`

// codeqlLog reports the *same* defect (same rule id, file, line) so it must
// dedup against the Semgrep finding.
const codeqlLog = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "CodeQL", "rules": [
      {"id": "sql-injection", "properties": {"security-severity": "9.8"}}
    ]}},
    "results": [{
      "ruleId": "sql-injection",
      "message": {"text": "dataflow to query"},
      "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "./app.py"},
        "region": {"startLine": 10}
      }}]
    }]
  }]
}`

// gitleaksLog reports a hardcoded secret at a different location.
const gitleaksLog = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "Gitleaks", "rules": [
      {"id": "generic-api-key", "properties": {"security-severity": "7.5"}}
    ]}},
    "results": [{
      "ruleId": "generic-api-key",
      "level": "error",
      "message": {"text": "hardcoded secret"},
      "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "config.py"},
        "region": {"startLine": 3}
      }}]
    }]
  }]
}`

func TestMergeDeduplicates(t *testing.T) {
	report := Merge([]*Log{
		mustLog(t, semgrepLog),
		mustLog(t, codeqlLog),
		mustLog(t, gitleaksLog),
	})

	// sql-injection appears twice (Semgrep + CodeQL) but at the same
	// rule/file/line, so it collapses to one finding; plus the secret = 2.
	if got := len(report.Findings); got != 2 {
		t.Fatalf("expected 2 deduplicated findings, got %d: %+v", got, report.Findings)
	}

	// The deduped SQL finding must take the *higher* severity. CodeQL's 9.8
	// is CRITICAL and beats Semgrep's 8.5 (HIGH).
	var sql *Finding
	for i := range report.Findings {
		if report.Findings[i].RuleID == "sql-injection" {
			sql = &report.Findings[i]
		}
	}
	if sql == nil {
		t.Fatal("sql-injection finding missing")
	}
	if sql.Severity != SeverityCritical {
		t.Fatalf("expected CRITICAL after merge, got %s", sql.Severity)
	}
}

func TestThresholdGating(t *testing.T) {
	report := Merge([]*Log{mustLog(t, gitleaksLog)})

	// generic-api-key is 7.5 → HIGH.
	if n := report.CountAtOrAbove(SeverityHigh); n != 1 {
		t.Fatalf("expected 1 finding at/above HIGH, got %d", n)
	}
	if n := report.CountAtOrAbove(SeverityCritical); n != 0 {
		t.Fatalf("expected 0 findings at/above CRITICAL, got %d", n)
	}
	if n := report.CountAtOrAbove(SeverityLow); n != 1 {
		t.Fatalf("expected 1 finding at/above LOW, got %d", n)
	}
}

func TestSuppressedFindingIsInactive(t *testing.T) {
	const suppressed = `{
      "version": "2.1.0",
      "runs": [{
        "tool": {"driver": {"name": "Semgrep", "rules": [
          {"id": "x", "properties": {"security-severity": "9.0"}}
        ]}},
        "results": [{
          "ruleId": "x",
          "message": {"text": "m"},
          "suppressions": [{"kind": "inSource", "status": "accepted"}],
          "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}
          }}]
        }]
      }]
    }`
	report := Merge([]*Log{mustLog(t, suppressed)})
	if len(report.Findings) != 1 {
		t.Fatalf("expected the finding to be present, got %d", len(report.Findings))
	}
	if report.Findings[0].Active {
		t.Fatal("suppressed finding must be inactive")
	}
	if n := report.CountAtOrAbove(SeverityNone); n != 0 {
		t.Fatalf("suppressed finding must not count toward the gate, got %d", n)
	}
}

func TestFingerprintStability(t *testing.T) {
	// "./app.py" and "app.py" must normalise to the same fingerprint.
	if fingerprint("r", "./app.py", 5) != fingerprint("r", "app.py", 5) {
		t.Fatal("path normalisation failed: fingerprints differ")
	}
	// Different line ⇒ different fingerprint.
	if fingerprint("r", "app.py", 5) == fingerprint("r", "app.py", 6) {
		t.Fatal("different lines must produce different fingerprints")
	}
}

func TestMergedLogRoundTrips(t *testing.T) {
	report := Merge([]*Log{mustLog(t, semgrepLog), mustLog(t, gitleaksLog)})
	out := report.ToLog()
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal merged log: %v", err)
	}
	var back Log
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("merged log does not round-trip: %v", err)
	}
	if len(back.Runs) != 1 {
		t.Fatalf("merged log should have exactly one run, got %d", len(back.Runs))
	}
	if got := len(back.Runs[0].Results); got != 2 {
		t.Fatalf("merged run should carry 2 results, got %d", got)
	}
}
