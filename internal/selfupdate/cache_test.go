package selfupdate

import (
	"testing"
	"time"
)

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	if err := writeCache(dir, cacheState{LastCheck: now.Unix(), Latest: "0.9.0"}); err != nil {
		t.Fatalf("writeCache: %v", err)
	}
	got, err := readCache(dir)
	if err != nil {
		t.Fatalf("readCache: %v", err)
	}
	if got.Latest != "0.9.0" || got.LastCheck != now.Unix() {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestReadCacheMissingIsZeroNoError(t *testing.T) {
	got, err := readCache(t.TempDir())
	if err != nil {
		t.Fatalf("missing cache should not error, got %v", err)
	}
	if got.Latest != "" || got.LastCheck != 0 {
		t.Fatalf("missing cache should be zero value, got %+v", got)
	}
}
