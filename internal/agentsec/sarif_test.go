package agentsec

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSARIFLevelMapping(t *testing.T) {
	cases := []struct{ sev, want string }{
		{"CRITICAL", "error"},
		{"HIGH", "error"},
		{"MEDIUM", "warning"},
		{"LOW", "note"},
		{"", "note"},
	}
	for _, c := range cases {
		if got := sarifLevel(c.sev); got != c.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", c.sev, got, c.want)
		}
	}
}

func TestSARIFDocument(t *testing.T) {
	findings := []Finding{
		{RuleID: "prompt-injection", Severity: "CRITICAL", FilePath: "CLAUDE.md", Line: 3, Message: "injection"},
		{RuleID: "mcp-non-https", Severity: "HIGH", FilePath: ".mcp.json", Line: 0, Message: "non-https"},
	}
	var buf bytes.Buffer
	if err := SARIF(&buf, findings); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct{ Name string } `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string                `json:"ruleId"`
				Level     string                `json:"level"`
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }     `json:"artifactLocation"`
						Region           *struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != "zyrax-guard" {
		t.Fatalf("unexpected runs/tool: %+v", doc.Runs)
	}
	res := doc.Runs[0].Results
	if len(res) != 2 {
		t.Fatalf("results len = %d, want 2", len(res))
	}
	if res[0].Locations[0].PhysicalLocation.Region == nil ||
		res[0].Locations[0].PhysicalLocation.Region.StartLine != 3 {
		t.Errorf("first finding region = %+v, want startLine 3", res[0].Locations[0].PhysicalLocation.Region)
	}
	if res[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "CLAUDE.md" {
		t.Errorf("first finding uri = %q", res[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if res[1].Locations[0].PhysicalLocation.Region != nil {
		t.Errorf("whole-file finding should omit region, got %+v", res[1].Locations[0].PhysicalLocation.Region)
	}
	if res[1].Locations[0].PhysicalLocation.ArtifactLocation.URI != ".mcp.json" {
		t.Errorf("second finding uri = %q", res[1].Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
}

func TestSARIFEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, nil); err != nil {
		t.Fatalf("SARIF(nil): %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 0 {
		t.Errorf("empty findings should produce empty results, got %+v", doc.Runs)
	}
}
