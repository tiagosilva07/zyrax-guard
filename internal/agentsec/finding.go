package agentsec

// Finding is an agent-security finding.
type Finding struct {
	RuleID      string  `json:"rule_id"`
	Severity    string  `json:"severity"`
	FilePath    string  `json:"file_path"`
	Line        int     `json:"line,omitempty"`
	Message     string  `json:"message"`
	Description string  `json:"description"`
	Remediation string  `json:"remediation"`
	Confidence  float64 `json:"confidence"`
}
