// Package verdict is the pure, ecosystem-agnostic core: it turns Signals into a
// SAFE/WARN/BLOCK Result. It has no I/O and no dependencies outside the stdlib.
package verdict

// Level is the severity a single check contributes.
type Level int

const (
	LevelInfo  Level = iota // contributes context, never escalates past SAFE
	LevelWarn               // escalates to WARN
	LevelBlock              // escalates to BLOCK
	LevelError              // could-not-determine — escalates to ERROR (fail closed)
)

// Verdict is the overall decision for a package.
type Verdict int

const (
	Safe  Verdict = iota
	Warn          // suspicious
	Error         // could not verify — fails closed (exits non-zero)
	Block         // strong malicious/hallucinated signal
)

func (v Verdict) String() string {
	switch v {
	case Block:
		return "BLOCK"
	case Error:
		return "ERROR"
	case Warn:
		return "WARN"
	default:
		return "SAFE"
	}
}

// Rule IDs — these are the canonical check identifiers and double as SARIF ruleIds.
const (
	RuleNonexistent       = "nonexistent"
	RuleTyposquat         = "typosquat"
	RuleKnownMalware      = "known-malware"
	RuleNewAndUnused      = "new-and-unused"
	RuleLockfileIntegrity = "lockfile-integrity"
	RuleMaintainerChange  = "maintainer-change"
	RuleCheckError        = "check-error"
	RuleSuspiciousInstall = "suspicious-install"
)

// Signal is one check's contribution to the verdict.
type Signal struct {
	Check   string `json:"check"`
	Level   Level  `json:"level"`
	Message string `json:"message"`
	Suggest string `json:"suggest,omitempty"`
}

// Result is the full decision for one package.
type Result struct {
	Ecosystem  string   `json:"ecosystem"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Verdict    Verdict  `json:"-"`
	VerdictStr string   `json:"verdict"`
	Score      int      `json:"score"`
	Signals    []Signal `json:"signals"`
	Suggestion string   `json:"suggestion,omitempty"`
}
