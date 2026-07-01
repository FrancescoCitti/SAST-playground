// Package sarif implements a minimal SARIF v2.1.0 model plus the merge,
// deduplication and severity-gating logic used by the sarifgate CI tool.
//
// Only the fields the gate actually needs are modelled. Unknown fields in the
// input documents are ignored on decode and dropped on re-encode, which is
// fine because the per-tool SARIF files are uploaded to GitHub directly; the
// merged document this package produces is a gate/audit artifact, not the copy
// GitHub ingests.
package sarif

// Log is the top-level SARIF document.
type Log struct {
	Schema  string `json:"$schema,omitempty"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is a single tool invocation's worth of results.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the analysis tool that produced a run.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver is the tool component that holds the rule metadata.
type Driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri,omitempty"`
	Version        string `json:"version,omitempty"`
	Rules          []Rule `json:"rules,omitempty"`
}

// Rule is a reporting descriptor. security-severity lives in Properties.
type Rule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     *Message       `json:"shortDescription,omitempty"`
	DefaultConfiguration *Configuration `json:"defaultConfiguration,omitempty"`
	Properties           *Properties    `json:"properties,omitempty"`
}

// Configuration carries a rule's default SARIF level.
type Configuration struct {
	Level string `json:"level,omitempty"`
}

// Properties holds the GitHub-recognised security-severity score and tags.
type Properties struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

// Result is a single finding.
type Result struct {
	RuleID              string            `json:"ruleId,omitempty"`
	RuleIndex           *int              `json:"ruleIndex,omitempty"`
	Level               string            `json:"level,omitempty"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Suppressions        []Suppression     `json:"suppressions,omitempty"`
}

// Message is SARIF's text container.
type Message struct {
	Text string `json:"text,omitempty"`
}

// Location wraps a physical location.
type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
}

// PhysicalLocation points at a file and region.
type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *Region           `json:"region,omitempty"`
}

// ArtifactLocation is the file URI of a finding.
type ArtifactLocation struct {
	URI string `json:"uri,omitempty"`
}

// Region is the line/column span of a finding.
type Region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// Suppression marks a result as suppressed (e.g. dismissed or a baseline).
type Suppression struct {
	Kind   string `json:"kind,omitempty"`
	Status string `json:"status,omitempty"`
}

// primaryLocation returns the file URI and start line of the result's first
// physical location, or ("", 0) when none is present.
func (r Result) primaryLocation() (string, int) {
	for _, loc := range r.Locations {
		if loc.PhysicalLocation == nil {
			continue
		}
		uri := ""
		if loc.PhysicalLocation.ArtifactLocation != nil {
			uri = loc.PhysicalLocation.ArtifactLocation.URI
		}
		line := 0
		if loc.PhysicalLocation.Region != nil {
			line = loc.PhysicalLocation.Region.StartLine
		}
		return uri, line
	}
	return "", 0
}

// isActive reports whether a result counts toward the gate. A result with any
// suppression (dismissed in the UI, baselined, etc.) is treated as inactive.
func (r Result) isActive() bool {
	for _, s := range r.Suppressions {
		// An accepted/underReview suppression of any kind means the finding
		// has been handled; it should not fail the build.
		if s.Status == "" || s.Status == "accepted" || s.Status == "underReview" {
			return false
		}
	}
	return true
}
