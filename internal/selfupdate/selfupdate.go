package selfupdate

import (
	"encoding/json"
	"os"
	"path/filepath"
)

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
