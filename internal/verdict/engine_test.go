package verdict

import "testing"

func TestDecide(t *testing.T) {
	tests := []struct {
		name    string
		signals []Signal
		want    Verdict
		suggest string
	}{
		{"no signals is safe", nil, Safe, ""},
		{"info only is safe", []Signal{{Check: RuleNewAndUnused, Level: LevelInfo, Message: "new"}}, Safe, ""},
		{"a warn signal warns", []Signal{{Check: RuleNewAndUnused, Level: LevelWarn, Message: "new+unused"}}, Warn, ""},
		{"a block signal blocks", []Signal{{Check: RuleNonexistent, Level: LevelBlock, Message: "404"}}, Block, ""},
		{"block beats warn", []Signal{{Check: RuleNewAndUnused, Level: LevelWarn}, {Check: RuleKnownMalware, Level: LevelBlock}}, Block, ""},
		{"suggestion surfaces", []Signal{{Check: RuleTyposquat, Level: LevelBlock, Message: "typo", Suggest: "request"}}, Block, "request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide("npm", "pkg", "1.0.0", tc.signals)
			if got.Verdict != tc.want {
				t.Errorf("verdict = %v, want %v", got.Verdict, tc.want)
			}
			if got.Suggestion != tc.suggest {
				t.Errorf("suggestion = %q, want %q", got.Suggestion, tc.suggest)
			}
		})
	}
}

func TestVerdictString(t *testing.T) {
	if Block.String() != "BLOCK" || Warn.String() != "WARN" || Safe.String() != "SAFE" {
		t.Fatal("verdict strings wrong")
	}
}

func TestDecideErrorVerdict(t *testing.T) {
	// A LevelError signal yields the ERROR verdict...
	r := Decide("npm", "x", "", []Signal{{Check: "check-error", Level: LevelError, Message: "registry unreachable"}})
	if r.VerdictStr != "ERROR" || r.Verdict != Error {
		t.Fatalf("got %q/%d, want ERROR", r.VerdictStr, r.Verdict)
	}
	// ...but a concrete BLOCK still dominates ERROR.
	r2 := Decide("npm", "x", "", []Signal{
		{Check: "check-error", Level: LevelError, Message: "osv down"},
		{Check: "known-malware", Level: LevelBlock, Message: "malware"},
	})
	if r2.Verdict != Block {
		t.Fatalf("BLOCK must dominate ERROR, got %s", r2.VerdictStr)
	}
	// ERROR outranks WARN.
	r3 := Decide("npm", "x", "", []Signal{
		{Check: "new-and-unused", Level: LevelWarn, Message: "new"},
		{Check: "check-error", Level: LevelError, Message: "osv down"},
	})
	if r3.Verdict != Error {
		t.Fatalf("ERROR must outrank WARN, got %s", r3.VerdictStr)
	}
}
