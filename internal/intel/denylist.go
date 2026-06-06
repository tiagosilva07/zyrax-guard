// Package intel implements seam.ThreatIntel using public OSV data plus a small
// bundled denylist of known-malicious package names (seed; grow via PRs).
package intel

// denylist maps ecosystem -> set of known-malicious names. Seeded small; a
// public-knowledge list of confirmed-malicious package names (grow via PRs).
var denylist = map[string]map[string]bool{
	"npm": {
		// Examples of historically malicious typo/confusion names. Extend via PR.
		"crossenv":     true,
		"cross-env.js": true,
	},
}

// InDenylist reports whether name is a known-malicious package in ecosystem.
func InDenylist(ecosystem, name string) bool {
	return denylist[ecosystem][name]
}
