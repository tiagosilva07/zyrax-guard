package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
)

// Fetcher returns the latest published version string, or an error.
type Fetcher func(ctx context.Context) (string, error)

// NPMRegistryURL is the canonical source for Guard's own latest version. Its host is
// already in the SSRF allowlist and already disclosed in the privacy promise.
const NPMRegistryURL = "https://registry.npmjs.org/zyrax-guard/latest"

// npmFetcher builds a Fetcher that GETs url (the npm "latest" doc) and reads .version.
func npmFetcher(c *httpx.Client, url string) Fetcher {
	return func(ctx context.Context) (string, error) {
		var doc struct {
			Version string `json:"version"`
		}
		code, err := c.GetJSON(ctx, url, &doc)
		if err != nil {
			return "", err
		}
		if code != 200 || doc.Version == "" {
			return "", fmt.Errorf("npm latest: status %d", code)
		}
		return doc.Version, nil
	}
}

type cacheState struct {
	LastCheck int64  `json:"last_check"`
	Latest    string `json:"latest"`
}

const cacheFileName = "update-check.json"

// readCache loads the cache from dir. A missing or unreadable file yields the zero
// value with no error — the check is best-effort and must never fail a command.
func readCache(dir string) (cacheState, error) {
	b, err := os.ReadFile(filepath.Join(dir, cacheFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return cacheState{}, nil
		}
		return cacheState{}, nil // unreadable: treat as empty, don't propagate
	}
	var s cacheState
	if err := json.Unmarshal(b, &s); err != nil {
		return cacheState{}, nil // corrupt: treat as empty
	}
	return s, nil
}

// writeCache persists s into dir, creating dir if needed. Errors are returned for
// tests but callers ignore them (persistence is best-effort).
func writeCache(dir string, s cacheState) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, cacheFileName), b, 0o644)
}

// cacheDir returns the per-user cache directory for Guard, or "" if unavailable.
func cacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "zyrax-guard")
}

// Clock returns the current time (injectable for tests).
type Clock func() time.Time

// Options configures CheckAndNotify. Zero values pick production defaults.
type Options struct {
	CacheDir string  // defaults to cacheDir()
	Now      Clock   // defaults to time.Now
	Fetch    Fetcher // defaults to the npm-registry fetcher
	Quiet    bool    // true for --json/--sarif and the mcp command
	Force    bool    // true for `version --check`: ignore the 24h gate
}

const checkInterval = 24 * time.Hour
const fetchTimeout = 1500 * time.Millisecond

// CheckAndNotify prints a one-line stderr notice (to w) when a newer release exists.
// It is best-effort: it never returns an error, never alters exit codes, and never
// writes to stdout. It refreshes the cached "latest" at most once per checkInterval.
func CheckAndNotify(w io.Writer, current string, opts Options) {
	if current == "dev" || opts.Quiet || os.Getenv("ZYRAX_NO_UPDATE_CHECK") != "" {
		return
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.CacheDir == "" {
		opts.CacheDir = cacheDir()
	}
	if opts.CacheDir == "" {
		return // no place to cache: skip rather than hammer the registry every run
	}
	if opts.Fetch == nil {
		opts.Fetch = npmFetcher(httpx.New([]string{"registry.npmjs.org"}), NPMRegistryURL)
	}

	state, _ := readCache(opts.CacheDir)
	now := opts.Now()
	stale := opts.Force || now.Sub(time.Unix(state.LastCheck, 0)) >= checkInterval
	if stale {
		ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
		defer cancel()
		if latest, err := opts.Fetch(ctx); err == nil && latest != "" {
			state.Latest = latest
			state.LastCheck = now.Unix()
			_ = writeCache(opts.CacheDir, state)
		}
	}
	if state.Latest != "" && compareSemver(state.Latest, current) > 0 {
		fmt.Fprintf(w, "zyrax-guard %s available (you have %s) — run 'zyrax-guard upgrade' or see https://github.com/tiagosilva07/zyrax-guard/releases\n", state.Latest, current)
	}
}
