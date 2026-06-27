// Package agentsec scans AI agent configuration files for security threats:
// prompt injection, malicious MCP hosts, excessive permissions, and supply-chain risks.
package agentsec

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// minConfidence is the lowest confidence score that gets reported.
const minConfidence = 0.50

// maxFileSizeBytes is the largest file ScanDir will read. Files above this
// limit are silently skipped to prevent memory exhaustion on crafted inputs.
const maxFileSizeBytes int64 = 5 * 1024 * 1024 // 5 MB

var agentConfigNames = map[string]bool{
	"CLAUDE.md":                  true,
	"AGENTS.md":                  true,
	"GEMINI.md":                  true,
	".mcp.json":                  true,
	"claude_desktop_config.json": true,
	".cursorrules":               true, // legacy Cursor single-file format
	".windsurfrules":             true, // Windsurf agent instructions
}

// ScanDir scans root for agent config files and returns all findings above
// the minimum confidence threshold.
func ScanDir(root string) ([]Finding, []string, error) {
	files, err := discoverAgentFiles(root)
	if err != nil {
		return nil, nil, err
	}
	var all []Finding
	rel := make([]string, len(files))
	for i, f := range files {
		rel[i], _ = filepath.Rel(root, f)
		fi, err := os.Stat(f)
		if err != nil || fi.Size() > maxFileSizeBytes {
			continue
		}
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, finding := range evaluateFile(root, rel[i], string(content)) {
			if finding.Confidence >= minConfidence {
				all = append(all, finding)
			}
		}
	}
	all = append(all, findSymlinkedConfigs(root)...)
	return all, rel, nil
}

// SeverityOrder lists severities from most to least critical.
var SeverityOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}

// CountBySeverity returns a map of severity label to occurrence count.
func CountBySeverity(findings []Finding) map[string]int {
	counts := make(map[string]int, len(SeverityOrder))
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

// SummaryLine returns "N finding(s) — X CRITICAL, Y HIGH, …" in severity order.
func SummaryLine(findings []Finding) string {
	counts := CountBySeverity(findings)
	summary := fmt.Sprintf("%d finding(s)", len(findings))
	var parts []string
	for _, sev := range SeverityOrder {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) > 0 {
		summary += " — " + strings.Join(parts, ", ")
	}
	return summary
}

// skipDirs are directories never scanned — they contain third-party or VCS
// content, not agent configs authored by the repo owner.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
}

func discoverAgentFiles(root string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil // symlinks reported separately by findSymlinkedConfigs
		}
		name := d.Name()
		rel, _ := filepath.Rel(root, path)
		parts := strings.Split(filepath.ToSlash(rel), "/")

		// Known agent config names — scanned at any depth (nested CLAUDE.md etc.)
		if agentConfigNames[name] {
			found = append(found, path)
			return nil
		}
		if name == "SKILL.md" && slices.Contains(parts, "skills") {
			found = append(found, path)
			return nil
		}
		if name == "settings.json" && len(parts) >= 2 && parts[0] == ".claude" {
			found = append(found, path)
			return nil
		}
		// .claude/commands/*.md — custom slash commands run by Claude Code
		if filepath.Ext(name) == ".md" && len(parts) >= 3 && parts[0] == ".claude" && parts[1] == "commands" {
			found = append(found, path)
			return nil
		}
		// .github/copilot-instructions.md — GitHub Copilot agent instructions
		if name == "copilot-instructions.md" && len(parts) >= 2 && parts[0] == ".github" {
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
	return found, err
}

// findSymlinkedConfigs emits a MEDIUM finding for any known agent config file
// that is a symlink — these are skipped during scanning and may hide malicious
// content in the symlink target.
func findSymlinkedConfigs(root string) []Finding {
	var findings []Finding
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink == 0 || !agentConfigNames[d.Name()] {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		findings = append(findings, Finding{
			RuleID:      "agent-config/symlink",
			Severity:    "MEDIUM",
			FilePath:    rel,
			Message:     "Agent config '" + sanitizeExcerpt(d.Name()) + "' is a symlink — target was not scanned",
			Description: "Symlinked agent config files are skipped by the scanner. The target may contain malicious instructions.",
			Remediation: "Inspect the symlink target and replace with the actual file, or verify the target is trusted.",
			Confidence:  0.90,
		})
		return nil
	})
	return findings
}

func evaluateFile(root, relPath, content string) []Finding {
	var findings []Finding
	findings = append(findings, rulePromptInjection(content, relPath)...)
	findings = append(findings, ruleHiddenUnicode(content, relPath)...)
	findings = append(findings, ruleEncodedInstructions(content, relPath)...)
	findings = append(findings, ruleConditionalTriggers(content, relPath)...)
	findings = append(findings, rulePersonaOverride(content, relPath)...)
	findings = append(findings, ruleCredentialAccess(content, relPath)...)
	findings = append(findings, ruleExfiltrationSink(content, relPath)...)
	findings = append(findings, ruleMCPHosts(content, relPath)...)
	findings = append(findings, ruleMCPCommands(content, relPath)...)
	findings = append(findings, ruleMCPToolDescription(content, relPath)...)
	findings = append(findings, ruleExcessivePermissions(content, relPath)...)
	findings = append(findings, ruleHooks(content, relPath)...)
	findings = append(findings, ruleSupplyChain(content, relPath, root)...)
	return applyAllowDirectives(content, findings)
}

// applyAllowDirectives drops findings suppressed by an inline `zyrax-allow[: prefix]`
// on the finding's line, or a file-level `zyrax-allow-file[: prefix]` anywhere in the
// file. A bare directive suppresses any rule; with ": prefix" it suppresses only rules
// whose RuleID begins with that prefix.
// Findings with Line == 0 (whole-file findings) are only suppressible by file directives.
func applyAllowDirectives(content string, findings []Finding) []Finding {
	lines := strings.Split(content, "\n")
	fileDirectives := collectAllowPrefixes(content, "zyrax-allow-file")
	kept := findings[:0]
	for _, f := range findings {
		if suppressed(fileDirectives, f.RuleID) {
			continue
		}
		if f.Line >= 1 && f.Line <= len(lines) {
			lineDirectives := collectAllowPrefixes(lines[f.Line-1], "zyrax-allow")
			if suppressed(lineDirectives, f.RuleID) {
				continue
			}
		}
		kept = append(kept, f)
	}
	return kept
}

// collectAllowPrefixes finds every occurrence of directive in s and returns the
// rule-prefix arguments that follow each one. A bare occurrence yields "" (matches
// any rule). An occurrence followed by ": prefix" yields "prefix".
// When directive == "zyrax-allow", occurrences of "zyrax-allow-file" are skipped so
// that a file-scope directive is never misread as a line-scope one.
func collectAllowPrefixes(s, directive string) []string {
	var out []string
	search := s
	for {
		idx := strings.Index(search, directive)
		if idx < 0 {
			break
		}
		rest := search[idx+len(directive):]

		// Guard: when scanning for the line-scoped "zyrax-allow" directive, skip any
		// occurrence that is actually "zyrax-allow-file".
		if directive == "zyrax-allow" && strings.HasPrefix(rest, "-file") {
			search = rest
			continue
		}

		// Skip leading spaces/tabs (newline terminates the directive).
		rest = strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(rest, ":") {
			// "directive: prefix" — extract the first whitespace-delimited token.
			tail := strings.TrimLeft(rest[1:], " \t")
			end := strings.IndexAny(tail, " \t\n\r")
			var arg string
			if end < 0 {
				arg = strings.TrimRight(tail, "\r\n")
			} else {
				arg = tail[:end]
			}
			out = append(out, arg)
		} else {
			// Bare directive — suppresses any rule.
			out = append(out, "")
		}
		search = rest
	}
	return out
}

// suppressed reports whether ruleID is covered by any of the collected prefixes.
// An empty prefix matches any rule ID.
func suppressed(prefixes []string, ruleID string) bool {
	for _, p := range prefixes {
		if p == "" || strings.HasPrefix(ruleID, p) {
			return true
		}
	}
	return false
}
