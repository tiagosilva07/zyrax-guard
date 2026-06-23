package agentsec

import (
	"encoding/json"
	"io"
)

// sarifLevel maps a finding severity to a SARIF result level.
func sarifLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

// SARIF writes findings as a SARIF 2.1.0 document to w. Each finding carries a
// physical location (file, plus line when known) so GitHub Code Scanning can
// annotate the pull-request diff inline.
func SARIF(w io.Writer, findings []Finding) error {
	type artifactLocation struct {
		URI string `json:"uri"`
	}
	type region struct {
		StartLine int `json:"startLine"`
	}
	type physicalLocation struct {
		ArtifactLocation artifactLocation `json:"artifactLocation"`
		Region           *region          `json:"region,omitempty"`
	}
	type location struct {
		PhysicalLocation physicalLocation `json:"physicalLocation"`
	}
	type message struct {
		Text string `json:"text"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   message    `json:"message"`
		Locations []location `json:"locations"`
	}

	results := make([]result, 0, len(findings))
	for _, f := range findings {
		phys := physicalLocation{ArtifactLocation: artifactLocation{URI: f.FilePath}}
		if f.Line > 0 {
			phys.Region = &region{StartLine: f.Line}
		}
		results = append(results, result{
			RuleID:    f.RuleID,
			Level:     sarifLevel(f.Severity),
			Message:   message{Text: f.Message},
			Locations: []location{{PhysicalLocation: phys}},
		})
	}

	doc := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool":    map[string]any{"driver": map[string]any{"name": "zyrax-guard"}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
