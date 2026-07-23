// Package policy implements seam.Policy backed by a project-local committed file
// .zyrax/policy.json — the OSS allow/deny source. (Org policy is a paid drop-in.)
package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/tiagosilva07/zyrax-guard/internal/seam"
)

// AllowEntry is one allowlisted package, with an optional audit trail of why
// and when it was trusted. It marshals as a bare string when it carries
// neither — so every policy.json written before Reason/At existed round-trips
// byte-for-byte unchanged — and as an object once a reason is recorded.
type AllowEntry struct {
	Name   string    `json:"name"`
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at,omitempty"`
}

func (e *AllowEntry) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err == nil {
		e.Name, e.Reason, e.At = name, "", time.Time{}
		return nil
	}
	type alias AllowEntry
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*e = AllowEntry(a)
	return nil
}

func (e AllowEntry) MarshalJSON() ([]byte, error) {
	if e.Reason == "" && e.At.IsZero() {
		return json.Marshal(e.Name)
	}
	type alias AllowEntry
	return json.Marshal(alias(e))
}

type file struct {
	Allow []AllowEntry `json:"allow,omitempty"`
	Deny  []string     `json:"deny,omitempty"`
}

type Local struct {
	path  string
	allow map[string]AllowEntry
	deny  map[string]bool
}

// Load reads .zyrax/policy.json under projectDir (creating neither dir nor file
// until Allow is called). projectDir bounds all writes (no traversal).
func Load(projectDir string) (*Local, error) {
	p := &Local{
		path:  filepath.Join(projectDir, ".zyrax", "policy.json"),
		allow: map[string]AllowEntry{},
		deny:  map[string]bool{},
	}
	b, err := os.ReadFile(p.path)
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	for _, e := range f.Allow {
		p.allow[e.Name] = e
	}
	for _, n := range f.Deny {
		p.deny[n] = true
	}
	return p, nil
}

func (p *Local) Decide(name string) seam.Decision {
	if p.deny[name] {
		return seam.ForceDeny
	}
	if _, ok := p.allow[name]; ok {
		return seam.ForceAllow
	}
	return seam.Defer
}

// Allow adds name to the allowlist (with an optional reason, timestamped in
// UTC) and persists the file (creating .zyrax/). Existing entries — including
// ones with no reason recorded — are preserved as-is; only the named entry is
// touched.
func (p *Local) Allow(name, reason string) error {
	p.allow[name] = AllowEntry{Name: name, Reason: reason, At: time.Now().UTC()}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o755); err != nil {
		return err
	}
	var f file
	for _, e := range p.allow {
		f.Allow = append(f.Allow, e)
	}
	for n := range p.deny {
		f.Deny = append(f.Deny, n)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.path, b, 0o644)
}
