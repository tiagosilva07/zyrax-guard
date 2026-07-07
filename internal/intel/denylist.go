// Package intel implements seam.ThreatIntel using public OSV data plus a small
// bundled denylist of known-malicious package names (seed; grow via PRs).
package intel

import (
	"sync"

	"github.com/tiagosilva07/zyrax-guard/internal/data"
)

// denylist maps ecosystem -> set of known-malicious names, loaded once from
// the embedded data file (internal/data/denylist.json — grow via data-only PRs).
var denylist = sync.OnceValue(func() map[string]map[string]bool {
	sets := map[string]map[string]bool{}
	for eco, names := range data.Denylist() {
		set := make(map[string]bool, len(names))
		for _, n := range names {
			set[n] = true
		}
		sets[eco] = set
	}
	return sets
})

// InDenylist reports whether name is a known-malicious package in ecosystem.
func InDenylist(ecosystem, name string) bool {
	return denylist()[ecosystem][name]
}
