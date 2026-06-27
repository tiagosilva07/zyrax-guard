package selfupdate

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func fixedClock(t time.Time) Clock { return func() time.Time { return t } }

func TestCheckAndNotify(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fetch := func(context.Context) (string, error) { return "0.9.0", nil }

	t.Run("notifies when newer and refreshes stale cache", func(t *testing.T) {
		var buf bytes.Buffer
		opts := Options{CacheDir: t.TempDir(), Now: fixedClock(now), Fetch: fetch}
		CheckAndNotify(&buf, "0.8.2", opts)
		if !strings.Contains(buf.String(), "0.9.0") {
			t.Fatalf("expected upgrade notice, got %q", buf.String())
		}
	})

	t.Run("no-op on dev build", func(t *testing.T) {
		var buf bytes.Buffer
		opts := Options{CacheDir: t.TempDir(), Now: fixedClock(now), Fetch: fetch}
		CheckAndNotify(&buf, "dev", opts)
		if buf.Len() != 0 {
			t.Fatalf("dev build must not notify, got %q", buf.String())
		}
	})

	t.Run("no-op when quiet", func(t *testing.T) {
		var buf bytes.Buffer
		opts := Options{CacheDir: t.TempDir(), Now: fixedClock(now), Fetch: fetch, Quiet: true}
		CheckAndNotify(&buf, "0.8.2", opts)
		if buf.Len() != 0 {
			t.Fatalf("quiet must not notify, got %q", buf.String())
		}
	})

	t.Run("no-op when opted out", func(t *testing.T) {
		t.Setenv("ZYRAX_NO_UPDATE_CHECK", "1")
		var buf bytes.Buffer
		opts := Options{CacheDir: t.TempDir(), Now: fixedClock(now), Fetch: fetch}
		CheckAndNotify(&buf, "0.8.2", opts)
		if buf.Len() != 0 {
			t.Fatalf("opt-out must not notify, got %q", buf.String())
		}
	})

	t.Run("fresh cache: no fetch, notify from cache", func(t *testing.T) {
		dir := t.TempDir()
		writeCache(dir, cacheState{LastCheck: now.Unix(), Latest: "0.9.0"})
		var calls int
		opts := Options{CacheDir: dir, Now: fixedClock(now), Fetch: func(context.Context) (string, error) {
			calls++
			return "0.9.0", nil
		}}
		CheckAndNotify(&bytes.Buffer{}, "0.8.2", opts)
		if calls != 0 {
			t.Fatalf("fresh cache must not fetch, fetched %d times", calls)
		}
	})

	t.Run("fetch error is silent", func(t *testing.T) {
		var buf bytes.Buffer
		opts := Options{CacheDir: t.TempDir(), Now: fixedClock(now),
			Fetch: func(context.Context) (string, error) { return "", context.DeadlineExceeded }}
		CheckAndNotify(&buf, "0.8.2", opts)
		if buf.Len() != 0 {
			t.Fatalf("fetch error must be silent, got %q", buf.String())
		}
	})
}
