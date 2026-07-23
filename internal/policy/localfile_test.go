package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/seam"
)

func TestLocalPolicyAllow(t *testing.T) {
	dir := t.TempDir()
	p, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Decide("foo") != seam.Defer {
		t.Fatal("unknown package should Defer")
	}
	if err := p.Allow("foo", ""); err != nil {
		t.Fatal(err)
	}
	// reload from disk
	p2, _ := Load(dir)
	if p2.Decide("foo") != seam.ForceAllow {
		t.Fatal("allowed package should ForceAllow after reload")
	}
	if _, err := filepath.Rel(dir, p.path); err != nil {
		t.Fatal("policy file must live under the project dir")
	}
}

func TestLocalPolicyAllowReasonAndLegacyFormat(t *testing.T) {
	dir := t.TempDir()
	p, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Allow("with-reason", "reviewed setup.py, tree-sitter-bash FP"); err != nil {
		t.Fatal(err)
	}
	if err := p.Allow("no-reason", ""); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p.path)
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild as a mix of the new object-form entry and a bare-string legacy
	// entry — someone's already-committed policy.json from before Reason/At
	// existed must keep loading exactly as before.
	mixed := `{"allow":[` + entryJSON(t, raw, "with-reason") + `,"legacy-pkg"],"deny":[]}`
	if err := os.WriteFile(p.path, []byte(mixed), 0o644); err != nil {
		t.Fatal(err)
	}

	p2, err := Load(dir)
	if err != nil {
		t.Fatalf("legacy+new mixed policy.json must still load: %v", err)
	}
	if p2.Decide("with-reason") != seam.ForceAllow {
		t.Fatal("object-form entry should ForceAllow")
	}
	if p2.Decide("legacy-pkg") != seam.ForceAllow {
		t.Fatal("legacy bare-string entry should still ForceAllow")
	}
	if e := p2.allow["with-reason"]; e.Reason != "reviewed setup.py, tree-sitter-bash FP" || e.At.IsZero() {
		t.Errorf("reason/timestamp not preserved: %+v", e)
	}
	if e := p2.allow["legacy-pkg"]; e.Reason != "" || !e.At.IsZero() {
		t.Errorf("legacy entry should have no reason/timestamp: %+v", e)
	}
}

// entryJSON extracts the marshaled JSON for a single allow entry by name, so
// the test can hand-assemble a policy.json mixing object-form and legacy
// bare-string entries without depending on map iteration order.
func entryJSON(t *testing.T, raw []byte, name string) string {
	t.Helper()
	var f struct {
		Allow []json.RawMessage `json:"allow"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, e := range f.Allow {
		if strings.Contains(string(e), name) {
			return string(e)
		}
	}
	t.Fatalf("entry %q not found in %s", name, raw)
	return ""
}
