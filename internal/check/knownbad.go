package check

import (
	"github.com/tiagosilva07/zyrax-guard/internal/seam"
	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

// KnownBad turns advisories into a signal. BLOCK is reserved for known-malicious
// packages ("we think this is an attack"); a vulnerability in a legitimate
// package WARNs at any severity — the severity is shown so the user sees what
// they are accepting, and --strict turns the WARN into a failure. Blocking
// popular packages on ordinary CVEs (e.g. a DoS advisory on next/vite) teaches
// users to bypass the gate; vulnerability management belongs to audit tooling.
func KnownBad(advs []seam.Advisory) verdict.Signal {
	worst := verdict.LevelInfo
	msg := ""
	for _, a := range advs {
		if a.Malware {
			return verdict.Signal{Check: verdict.RuleKnownMalware, Level: verdict.LevelBlock, Message: advMsg(a)}
		}
		if worst < verdict.LevelWarn {
			worst, msg = verdict.LevelWarn, advMsg(a)
		}
	}
	return verdict.Signal{Check: verdict.RuleKnownMalware, Level: worst, Message: msg}
}

func advMsg(a seam.Advisory) string {
	msg := a.ID
	if a.Severity != "" {
		msg += " (" + a.Severity + " severity)"
	}
	if a.Summary != "" {
		msg += ": " + a.Summary
	}
	return msg
}
