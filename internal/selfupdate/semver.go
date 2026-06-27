// Package selfupdate handles Guard's own update notice and verified upgrade.
package selfupdate

import (
	"strconv"
	"strings"
)

// compareSemver returns -1, 0, or 1 comparing a to b. A leading "v" is ignored and
// any pre-release/build suffix (after "-" or "+") is dropped, so 1.2.3-rc1 == 1.2.3.
// An unparsable version sorts as the oldest possible (so we never nag on garbage).
func compareSemver(a, b string) int {
	pa, oka := parseVer(a)
	pb, okb := parseVer(b)
	switch {
	case !oka && !okb:
		return 0
	case !oka:
		return -1
	case !okb:
		return 1
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVer(s string) ([3]int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	var out [3]int
	if len(parts) == 0 || len(parts) > 3 {
		return out, false
	}
	for i := 0; i < 3; i++ {
		if i >= len(parts) {
			continue // missing minor/patch defaults to 0
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
