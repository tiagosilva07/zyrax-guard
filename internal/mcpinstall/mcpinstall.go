// Package mcpinstall registers Guard as an MCP server for AI coding agents, either by
// merging a generic project .mcp.json or by delegating to a client's official CLI.
package mcpinstall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// ResolveCommand returns the argv to register. override is "", "npx", or "binary".
// With "" it auto-detects: if execPath looks like a real installed binary use it,
// otherwise fall back to npx.
func ResolveCommand(override, execPath string) []string {
	switch override {
	case "npx":
		return []string{"npx", "-y", "zyrax-guard", "mcp"}
	case "binary":
		return []string{execPath, "mcp"}
	}
	if looksInstalled(execPath) {
		return []string{execPath, "mcp"}
	}
	return []string{"npx", "-y", "zyrax-guard", "mcp"}
}

// looksInstalled is true when execPath is an absolute path to a zyrax-guard binary that
// is not in a temp dir (npx caches run from temp/cache locations).
func looksInstalled(execPath string) bool {
	if execPath == "" || !filepath.IsAbs(execPath) {
		return false
	}
	base := strings.TrimSuffix(filepath.Base(execPath), ".exe")
	if base != "zyrax-guard" {
		return false
	}
	p := filepath.ToSlash(execPath)
	for _, frag := range []string{"/tmp/", "/_npx/", "/.npm/", "/npm-cache/", "/temp/"} {
		if strings.Contains(p, frag) {
			return false
		}
	}
	return true
}

// WriteProjectConfig merges a zyrax-guard entry into the .mcp.json at path, preserving
// every other key and server, and writes it back with stable 2-space indentation.
func WriteProjectConfig(path string, command []string) error {
	root := map[string]any{}
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		if err := json.Unmarshal(b, &root); err != nil {
			return err
		}
	}
	servers, _ := root["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	servers["zyrax-guard"] = map[string]any{
		"command": command[0],
		"args":    command[1:],
	}
	root["mcpServers"] = servers

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0o644)
}
