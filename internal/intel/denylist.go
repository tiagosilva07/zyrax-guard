// Package intel implements seam.ThreatIntel using public OSV data plus a small
// bundled denylist of known-malicious package names (seed; grow via PRs).
package intel

// denylist maps ecosystem -> set of known-malicious names. Seeded small; this is
// the OSS, public-knowledge list (the paid curated feed is a separate provider).
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
