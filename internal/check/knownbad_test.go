package check

import (
	"strings"
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/seam"
	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

// BLOCK means "we think this is an attack" — reserved for known-malicious
// packages. A vulnerability in a legitimate package (any severity) is WARN:
// nearly every popular package carries a high-severity advisory at some point,
// and false-BLOCKing `next` or `vite` teaches users to bypass the gate.
func TestKnownBad(t *testing.T) {
	if s := KnownBad([]seam.Advisory{{Malware: true, Summary: "malware"}}); s.Level != verdict.LevelBlock {
		t.Errorf("malware should BLOCK, got %v", s.Level)
	}
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		s := KnownBad([]seam.Advisory{{ID: "GHSA-x", Severity: sev, Summary: "vuln"}})
		if s.Level != verdict.LevelWarn {
			t.Errorf("%s severity non-malware should WARN, got %v", sev, s.Level)
		}
		if !strings.Contains(s.Message, "GHSA-x") {
			t.Errorf("%s: advisory must be visible in the message, got %q", sev, s.Message)
		}
	}
	// Severity must be shown so the user sees what they are accepting.
	if s := KnownBad([]seam.Advisory{{ID: "GHSA-x", Severity: "high", Summary: "DoS"}}); !strings.Contains(s.Message, "high") {
		t.Errorf("severity should appear in the WARN message, got %q", s.Message)
	}
	// Malware dominates: mixed advisories still BLOCK.
	mixed := []seam.Advisory{{ID: "GHSA-x", Severity: "low"}, {ID: "MAL-1", Malware: true}}
	if s := KnownBad(mixed); s.Level != verdict.LevelBlock {
		t.Errorf("mixed advisories with malware should BLOCK, got %v", s.Level)
	}
	if s := KnownBad(nil); s.Level != verdict.LevelInfo {
		t.Errorf("no advisories should be info, got %v", s.Level)
	}
}
