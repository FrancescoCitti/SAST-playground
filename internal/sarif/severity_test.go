package sarif

import "testing"

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"critical": SeverityCritical,
		"HIGH":     SeverityHigh,
		" medium ": SeverityMedium,
		"Low":      SeverityLow,
		"none":     SeverityNone,
	}
	for in, want := range cases {
		got, err := ParseSeverity(in)
		if err != nil {
			t.Fatalf("ParseSeverity(%q) error: %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseSeverity(%q) = %s, want %s", in, got, want)
		}
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Fatal("expected error for unknown severity")
	}
}

func TestSeverityFromSecurityScore(t *testing.T) {
	cases := []struct {
		score float64
		want  Severity
	}{
		{9.0, SeverityCritical},
		{8.9, SeverityHigh},
		{7.0, SeverityHigh},
		{6.9, SeverityMedium},
		{4.0, SeverityMedium},
		{3.9, SeverityLow},
		{0.1, SeverityLow},
		{0.0, SeverityNone},
	}
	for _, c := range cases {
		if got := severityFromSecurityScore(c.score); got != c.want {
			t.Fatalf("severityFromSecurityScore(%.1f) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestResolveSeverityFallbacks(t *testing.T) {
	// security-severity wins over level.
	rule := &Rule{Properties: &Properties{SecuritySeverity: "9.5"}}
	r := Result{Level: "note"}
	if got := resolveSeverity(r, rule, true); got != SeverityCritical {
		t.Fatalf("security-severity should win, got %s", got)
	}

	// No security-severity, but the tool DOES score elsewhere ⇒ level maps
	// straight through (error → HIGH).
	if got := resolveSeverity(Result{Level: "error"}, nil, true); got != SeverityHigh {
		t.Fatalf("level fallback failed, got %s", got)
	}

	// No level on the result ⇒ fall back to the rule's default config.
	ruleOnly := &Rule{DefaultConfiguration: &Configuration{Level: "warning"}}
	if got := resolveSeverity(Result{}, ruleOnly, true); got != SeverityMedium {
		t.Fatalf("default-config fallback failed, got %s", got)
	}
}

func TestResolveSeverityCapsUnscoredTools(t *testing.T) {
	// A tool that provides NO security-severity anywhere: an "error" level is a
	// policy signal and must be capped at MEDIUM, not promoted to HIGH.
	if got := resolveSeverity(Result{Level: "error"}, nil, false); got != SeverityMedium {
		t.Fatalf("unscored error should cap at MEDIUM, got %s", got)
	}
	// note stays LOW; the cap only lowers, never raises.
	if got := resolveSeverity(Result{Level: "note"}, nil, false); got != SeverityLow {
		t.Fatalf("unscored note should stay LOW, got %s", got)
	}
}

func TestDriverHasSecuritySeverity(t *testing.T) {
	with := []Rule{{ID: "a"}, {ID: "b", Properties: &Properties{SecuritySeverity: "7.0"}}}
	if !driverHasSecuritySeverity(with) {
		t.Fatal("expected true when a rule carries security-severity")
	}
	without := []Rule{{ID: "a"}, {ID: "b", Properties: &Properties{Tags: []string{"x"}}}}
	if driverHasSecuritySeverity(without) {
		t.Fatal("expected false when no rule carries security-severity")
	}
}
