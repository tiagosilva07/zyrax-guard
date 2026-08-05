package check

import (
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

func TestParseTOMLPackages(t *testing.T) {
	cargo := `# Cargo.lock
[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "rand"
version = "0.8.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "def456"

[metadata]
ignored = "yes"
`
	entries := parseTOMLPackages([]byte(cargo))
	if len(entries) != 2 || entries[0].Name != "serde" || entries[0].Version != "1.0.197" || entries[0].Integrity != "abc123" {
		t.Fatalf("cargo parse wrong: %+v", entries)
	}
}

func TestParseRequirements(t *testing.T) {
	req := `# comment
requests==2.31.0
Flask[async]==3.0.0
-e ./local
urllib3 >= 1.26
`
	m := parseRequirements([]byte(req))
	if m["requests"].Version != "2.31.0" {
		t.Fatalf("requests: %+v", m["requests"])
	}
	if _, ok := m["flask"]; !ok { // normalized lowercase, extras stripped
		t.Fatalf("flask missing: %+v", m)
	}
}

func TestParseLockDispatch(t *testing.T) {
	cargo := "[[package]]\nname = \"serde\"\nversion = \"1.0\"\n"
	m, err := ParseLock("crates", []byte(cargo))
	if err != nil || m["serde"].Version != "1.0" {
		t.Fatalf("dispatch crates: %+v err=%v", m, err)
	}
}

func TestParseLockAdded(t *testing.T) {
	base := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://r/a","integrity":"sha-A"}}}`
	head := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://r/a","integrity":"sha-A"},"node_modules/b":{"version":"2.0.0","resolved":"https://r/b","integrity":"sha-B"}}}`
	added, changed, err := DiffLockfilesEco("npm", []byte(base), []byte(head))
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0].Name != "b" {
		t.Fatalf("added = %+v", added)
	}
	if len(changed) != 0 {
		t.Fatalf("changed = %+v", changed)
	}
}

func TestParseLockWorkspaceEntries(t *testing.T) {
	// npm workspace lockfiles (lockfileVersion 2/3) contain entries whose path has
	// no "node_modules/" prefix — the local workspace packages themselves, e.g.
	// "apps/web". These are not registry dependencies: they must be skipped, not
	// mis-sliced (short paths used to panic; longer ones produced garbage names).
	lock := `{"packages":{
		"": {"version":"0.0.1"},
		"a": {"version":"1.0.0"},
		"apps/web": {"version":"0.1.0"},
		"node_modules/lodash": {"version":"4.17.21","resolved":"https://r/lodash","integrity":"sha-L"},
		"apps/web/node_modules/left-pad": {"version":"1.3.0","resolved":"https://r/left-pad","integrity":"sha-P"}
	}}`
	m, err := parseLock([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("want 2 registry deps, got %d: %+v", len(m), m)
	}
	if m["lodash"].Version != "4.17.21" {
		t.Errorf("lodash: %+v", m["lodash"])
	}
	if m["left-pad"].Version != "1.3.0" {
		t.Errorf("left-pad (nested workspace dep): %+v", m["left-pad"])
	}
}

func TestLockIntegrityChanged(t *testing.T) {
	base := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://r/a","integrity":"sha-A"}}}`
	head := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://EVIL/a","integrity":"sha-X"}}}`
	_, changed, _ := DiffLockfilesEco("npm", []byte(base), []byte(head))
	if len(changed) != 1 {
		t.Fatalf("expected 1 integrity change, got %+v", changed)
	}
	if s := LockfileIntegrity(changed[0]); s.Level != verdict.LevelBlock {
		t.Errorf("integrity change should BLOCK, got %v", s.Level)
	}
}

func TestParseGoSum(t *testing.T) {
	sum := `github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
`
	m := parseGoSum([]byte(sum))
	if len(m) != 1 {
		t.Fatalf("want 1 module (the /go.mod line must be skipped), got %d: %+v", len(m), m)
	}
	e := m["github.com/pkg/errors"]
	if e.Version != "v0.9.1" || e.Integrity != "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=" {
		t.Fatalf("parsed entry wrong: %+v", e)
	}
}

func TestParseLockDispatchGoMod(t *testing.T) {
	sum := "example.com/mod v1.0.0 h1:abc=\nexample.com/mod v1.0.0/go.mod h1:def=\n"
	m, err := ParseLock("gomod", []byte(sum))
	if err != nil || m["example.com/mod"].Version != "v1.0.0" {
		t.Fatalf("dispatch gomod: %+v err=%v", m, err)
	}
}

func TestGoSumIntegrityChanged(t *testing.T) {
	base := "example.com/mod v1.0.0 h1:abc=\n"
	head := "example.com/mod v1.0.0 h1:TAMPERED=\n"
	_, changed, err := DiffLockfilesEco("gomod", []byte(base), []byte(head))
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 {
		t.Fatalf("expected 1 integrity change, got %+v", changed)
	}
	if s := LockfileIntegrity(changed[0]); s.Level != verdict.LevelBlock {
		t.Errorf("integrity change should BLOCK, got %v", s.Level)
	}
}

func TestDiffLockfilesEco_EmptyBaseAllAdded(t *testing.T) {
	// A missing/empty base lockfile must parse to no packages (all head deps "added"),
	// for every ecosystem — npm's JSON parser must tolerate empty input too.
	heads := map[string][]byte{
		"npm":    []byte(`{"packages":{"node_modules/a":{"version":"1.0.0"}}}`),
		"crates": []byte("[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n"),
		"pypi":   []byte("a==1.0.0\n"),
		"gomod":  []byte("a v1.0.0 h1:abc=\n"),
	}
	for eco, head := range heads {
		added, _, err := DiffLockfilesEco(eco, nil, head)
		if err != nil {
			t.Fatalf("%s: empty base errored: %v", eco, err)
		}
		if len(added) != 1 || added[0].Name != "a" {
			t.Fatalf("%s: want 1 added 'a', got %+v", eco, added)
		}
	}
}
