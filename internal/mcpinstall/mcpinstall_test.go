package mcpinstall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
