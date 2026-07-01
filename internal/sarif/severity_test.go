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
	if got := resolveSeverity(r, rule); got != SeverityCritical {
		t.Fatalf("security-severity should win, got %s", got)
	}

	// No security-severity ⇒ fall back to the result level.
	if got := resolveSeverity(Result{Level: "error"}, nil); got != SeverityHigh {
		t.Fatalf("level fallback failed, got %s", got)
	}

	// No level on the result ⇒ fall back to the rule's default config.
	ruleOnly := &Rule{DefaultConfiguration: &Configuration{Level: "warning"}}
	if got := resolveSeverity(Result{}, ruleOnly); got != SeverityMedium {
		t.Fatalf("default-config fallback failed, got %s", got)
	}
}
