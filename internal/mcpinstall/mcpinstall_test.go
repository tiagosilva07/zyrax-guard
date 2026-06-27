package mcpinstall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveCommandAutoDetect(t *testing.T) {
	npxForm := []string{"npx", "-y", "zyrax-guard", "mcp"}

	// Absolute paths that should look like a real installation vary by OS because
	// filepath.IsAbs is OS-dependent (/usr/... is not absolute on Windows).
	var (
		realBinPath1  string // e.g. /usr/local/bin/zyrax-guard
		realBinPath2  string // e.g. /home/u/.local/bin/zyrax-guard
		npmCachePath  string // an npx-cache path containing /_npx/
		wrongBasePath string // an absolute path with the wrong binary name
	)
	if runtime.GOOS == "windows" {
		realBinPath1 = `C:\Program Files\zyrax-guard\zyrax-guard.exe`
		realBinPath2 = `C:\Users\u\bin\zyrax-guard.exe`
		npmCachePath = `C:\Users\u\.npm\_npx\abc\node_modules\.bin\zyrax-guard.exe`
		wrongBasePath = `C:\Program Files\other\other.exe`
	} else {
		realBinPath1 = "/usr/local/bin/zyrax-guard"
		realBinPath2 = "/home/u/.local/bin/zyrax-guard"
		npmCachePath = "/home/u/.npm/_npx/abc/node_modules/.bin/zyrax-guard"
		wrongBasePath = "/usr/local/bin/other"
	}

	cases := []struct {
		name    string
		path    string
		wantNpx bool
	}{
		{
			name:    "abs path real install",
			path:    realBinPath1,
			wantNpx: false,
		},
		{
			name:    "abs path home local bin",
			path:    realBinPath2,
			wantNpx: false,
		},
		{
			name:    "relative path",
			path:    "zyrax-guard",
			wantNpx: true,
		},
		{
			name:    "wrong basename",
			path:    wrongBasePath,
			wantNpx: true,
		},
		{
			name:    "npx cache path",
			path:    npmCachePath,
			wantNpx: true,
		},
		{
			// Windows temp path — capital T in Temp must still be caught (case-insensitive fix).
			// This path is absolute on all OSes (drive letter present), so filepath.IsAbs
			// returns true on Windows; on non-Windows it falls through as non-absolute and also
			// returns npx — making the assertion wantNpx=true hold on every platform.
			name:    "windows temp path",
			path:    `C:\Users\me\AppData\Local\Temp\zyrax-guard.exe`,
			wantNpx: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveCommand("", tc.path)
			isNpx := len(got) == len(npxForm) && got[0] == "npx"
			if isNpx != tc.wantNpx {
				t.Errorf("ResolveCommand(%q): got %v, wantNpx=%v", tc.path, got, tc.wantNpx)
			}
		})
	}
}

func TestResolveCommandOverride(t *testing.T) {
	if got := ResolveCommand("npx", "/any/zyrax-guard"); got[0] != "npx" {
		t.Fatalf("npx override: got %v", got)
	}
	bin := ResolveCommand("binary", "/usr/local/bin/zyrax-guard")
	if bin[0] != "/usr/local/bin/zyrax-guard" || bin[1] != "mcp" {
		t.Fatalf("binary override: got %v", bin)
	}
}

func TestWriteProjectConfigMergesPreservingExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".mcp.json")
	existing := `{"mcpServers":{"other":{"command":"foo","args":["bar"]}}}`
	os.WriteFile(path, []byte(existing), 0o644)

	if err := WriteProjectConfig(path, []string{"npx", "-y", "zyrax-guard", "mcp"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var got map[string]map[string]any
	b, _ := os.ReadFile(path)
	json.Unmarshal(b, &got)
	if _, ok := got["mcpServers"]["other"]; !ok {
		t.Fatal("existing server 'other' was dropped")
	}
	if _, ok := got["mcpServers"]["zyrax-guard"]; !ok {
		t.Fatal("zyrax-guard entry not added")
	}
}

func TestWriteProjectConfigCreatesAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".mcp.json")
	cmd := []string{"zyrax-guard", "mcp"}
	if err := WriteProjectConfig(path, cmd); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(path)
	if err := WriteProjectConfig(path, cmd); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if string(first) != string(second) {
		t.Fatalf("re-run not idempotent:\n%s\n%s", first, second)
	}
}
