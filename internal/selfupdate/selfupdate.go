package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
