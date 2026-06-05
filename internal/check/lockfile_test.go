package check

import (
	"testing"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

func TestParseLockAdded(t *testing.T) {
	base := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://r/a","integrity":"sha-A"}}}`
	head := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://r/a","integrity":"sha-A"},"node_modules/b":{"version":"2.0.0","resolved":"https://r/b","integrity":"sha-B"}}}`
	added, changed, err := DiffLockfiles([]byte(base), []byte(head))
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

func TestLockIntegrityChanged(t *testing.T) {
	base := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://r/a","integrity":"sha-A"}}}`
	head := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://EVIL/a","integrity":"sha-X"}}}`
	_, changed, _ := DiffLockfiles([]byte(base), []byte(head))
	if len(changed) != 1 {
		t.Fatalf("expected 1 integrity change, got %+v", changed)
	}
	if s := LockfileIntegrity(changed[0]); s.Level != verdict.LevelBlock {
		t.Errorf("integrity change should BLOCK, got %v", s.Level)
	}
}

func TestMaintainerChange(t *testing.T) {
	if s := MaintainerChange([]string{"alice"}, []string{"bob"}); s.Level != verdict.LevelWarn {
		t.Errorf("new maintainer should WARN, got %v", s.Level)
	}
	if s := MaintainerChange([]string{"alice"}, []string{"alice"}); s.Level != verdict.LevelInfo {
		t.Errorf("same maintainer should be info, got %v", s.Level)
	}
}
