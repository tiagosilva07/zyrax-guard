// Package agentsec scans AI agent configuration files for security threats:
// prompt injection, malicious MCP hosts, excessive permissions, and supply-chain risks.
package agentsec

import (
	"os"
	"path/filepath"
	"strings"
)

// minConfidence is the lowest confidence score that gets reported.
const minConfidence = 0.50

var agentConfigNames = map[string]bool{
	"CLAUDE.md":                  true,
	"AGENTS.md":                  true,
	"GEMINI.md":                  true,
	".mcp.json":                  true,
	"claude_desktop_config.json": true,
}

// ScanDir scans root for agent config files and returns all findings above
// the minimum confidence threshold.
func ScanDir(root string) ([]Finding, []string, error) {
	files := discoverAgentFiles(root)
	var all []Finding
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(root, f)
		for _, finding := range evaluateFile(root, rel, string(content)) {
			if finding.Confidence >= minConfidence {
				all = append(all, finding)
			}
		}
	}
	rel := make([]string, len(files))
	for i, f := range files {
		r, _ := filepath.Rel(root, f)
		rel[i] = r
	}
	return all, rel, nil
}

func discoverAgentFiles(root string) []string {
	var found []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		rel, _ := filepath.Rel(root, path)
		parts := strings.Split(filepath.ToSlash(rel), "/")

		if len(parts) == 1 && agentConfigNames[name] {
			found = append(found, path)
			return nil
		}
		if name == "SKILL.md" {
			for _, p := range parts {
				if p == "skills" {
					found = append(found, path)
					return nil
				}
			}
		}
		if name == "settings.json" && len(parts) >= 2 && parts[0] == ".claude" {
			found = append(found, path)
			return nil
		}
		if name == ".mcp.json" && len(parts) > 1 {
			found = append(found, path)
			return nil
		}
		if name == "rules" {
			for i := 1; i < len(parts); i++ {
				if parts[i] == "rules" && parts[i-1] == ".cursor" {
					found = append(found, path)
					return nil
				}
			}
		}
		if filepath.Ext(name) == ".mdc" {
			for i := 2; i < len(parts); i++ {
				if parts[i-1] == "rules" && parts[i-2] == ".cursor" {
					found = append(found, path)
					return nil
				}
			}
		}
		return nil
	})
	return found
}

func evaluateFile(root, relPath, content string) []Finding {
	var findings []Finding
	for _, f := range rulePromptInjection(content, relPath) {
		findings = append(findings, f)
	}
	for _, f := range ruleHiddenUnicode(content, relPath) {
		findings = append(findings, f)
	}
	for _, f := range ruleEncodedInstructions(content, relPath) {
		findings = append(findings, f)
	}
	for _, f := range ruleConditionalTriggers(content, relPath) {
		findings = append(findings, f)
	}
	for _, f := range rulePersonaOverride(content, relPath) {
		findings = append(findings, f)
	}
	for _, f := range ruleMCPHosts(content, relPath) {
		findings = append(findings, f)
	}
	for _, f := range ruleExcessivePermissions(content, relPath) {
		findings = append(findings, f)
	}
	for _, f := range ruleSupplyChain(content, relPath, root) {
		findings = append(findings, f)
	}
	return findings
}
