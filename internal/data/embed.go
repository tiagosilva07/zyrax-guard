// Package data embeds the bundled popular-package lists so the binary is fully
// self-contained (no runtime file dependency).
package data

import (
	_ "embed"
	"encoding/json"
)

//go:embed popular-npm.json
var popularNPMRaw []byte

// PopularNPM returns the bundled top-npm names.
func PopularNPM() []string {
	var out []string
	_ = json.Unmarshal(popularNPMRaw, &out)
	return out
}

//go:embed popular-pypi.json
var popularPyPIRaw []byte

//go:embed popular-crates.json
var popularCratesRaw []byte

// PopularPyPI returns the bundled top-PyPI names (normalized).
func PopularPyPI() []string {
	var out []string
	_ = json.Unmarshal(popularPyPIRaw, &out)
	return out
}

// PopularCrates returns the bundled top-crates names.
func PopularCrates() []string {
	var out []string
	_ = json.Unmarshal(popularCratesRaw, &out)
	return out
}

//go:embed popular-gomod.json
var popularGoModRaw []byte

// PopularGoModules returns the bundled well-known Go module paths. Unlike
// npm/PyPI/crates.io, the Go module proxy exposes no download-count API to
// rank by — this list is manually curated (see scripts/refresh-popular-gomod.sh)
// rather than machine-generated from a popularity endpoint.
func PopularGoModules() []string {
	var out []string
	_ = json.Unmarshal(popularGoModRaw, &out)
	return out
}

//go:embed denylist.json
var denylistRaw []byte

// Denylist returns the bundled known-malicious names per ecosystem. Kept as a
// data file (not Go source) so the list can grow via data-only PRs.
func Denylist() map[string][]string {
	var out map[string][]string
	_ = json.Unmarshal(denylistRaw, &out)
	return out
}
