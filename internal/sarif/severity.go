package sarif

import (
	"fmt"
	"strconv"
	"strings"
)

// Severity is the gate's normalised severity scale. Ordering matters: higher
// values are more severe, and the gate fails when a finding's severity is at or
// above the configured threshold.
type Severity int

const (
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String renders the canonical upper-case name.
func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "NONE"
	}
}

// ParseSeverity converts a user-supplied threshold name into a Severity.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical, nil
	case "HIGH":
		return SeverityHigh, nil
	case "MEDIUM", "MED":
		return SeverityMedium, nil
	case "LOW":
		return SeverityLow, nil
	case "NONE":
		return SeverityNone, nil
	default:
		return SeverityNone, fmt.Errorf("unknown severity %q (want CRITICAL, HIGH, MEDIUM, LOW or NONE)", s)
	}
}

// severityFromSecurityScore maps a GitHub security-severity score (0.0–10.0)
// onto the gate scale using GitHub's own bucket boundaries.
func severityFromSecurityScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0.0:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// severityFromLevel maps a SARIF level keyword onto the gate scale. This is the
// fallback used when a rule carries no numeric security-severity.
func severityFromLevel(level string) Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return SeverityHigh
	case "warning":
		return SeverityMedium
	case "note":
		return SeverityLow
	default:
		// "none" or unspecified.
		return SeverityNone
	}
}

// resolveSeverity determines the severity of a single result. It prefers the
// numeric security-severity attached to the matching rule (this is what GitHub
// itself uses), then the result's own level, then the rule's default level.
//
// toolHasSeverity reports whether the result's tool provides a numeric
// security-severity on *any* of its rules. When it does not, a level of "error"
// is a policy/style signal (as emitted by IaC and workflow linters), not a
// scored vulnerability, so it is capped at MEDIUM: the finding stays visible but
// does not on its own trip a HIGH gate.
func resolveSeverity(r Result, rule *Rule, toolHasSeverity bool) Severity {
	if rule != nil && rule.Properties != nil && rule.Properties.SecuritySeverity != "" {
		if score, err := strconv.ParseFloat(strings.TrimSpace(rule.Properties.SecuritySeverity), 64); err == nil {
			if sev := severityFromSecurityScore(score); sev != SeverityNone {
				return sev
			}
		}
	}

	var sev Severity
	switch {
	case r.Level != "":
		sev = severityFromLevel(r.Level)
	case rule != nil && rule.DefaultConfiguration != nil && rule.DefaultConfiguration.Level != "":
		sev = severityFromLevel(rule.DefaultConfiguration.Level)
	default:
		// SARIF's default level when nothing is specified is "warning".
		sev = SeverityMedium
	}

	if !toolHasSeverity && sev > SeverityMedium {
		sev = SeverityMedium
	}
	return sev
}

// driverHasSecuritySeverity reports whether any rule in a driver carries a
// numeric security-severity property.
func driverHasSecuritySeverity(rules []Rule) bool {
	for i := range rules {
		if rules[i].Properties != nil && strings.TrimSpace(rules[i].Properties.SecuritySeverity) != "" {
			return true
		}
	}
	return false
}
