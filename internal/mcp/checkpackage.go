package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tiagosilva07/zyrax-guard/internal/agentsec"
	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

func checkPackageTool() map[string]any {
	return map[string]any{
		"name":        "check_package",
		"description": "Vet a package for typosquats, known-malware, hallucinated names, and supply-chain risk BEFORE installing it. Returns SAFE, WARN, or BLOCK with reasons. Call this before running any package install. Set deep=true to also download the artifact and statically analyze install/build scripts (slower).",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name":      map[string]any{"type": "string", "description": "package name to check"},
				"version":   map[string]any{"type": "string", "description": "optional; defaults to the latest published version"},
				"ecosystem": map[string]any{"type": "string", "enum": []string{"npm", "pypi", "crates"}, "default": "npm"},
				"deep":      map[string]any{"type": "boolean", "description": "download the artifact and statically analyze install/build scripts (slower)"},
			},
			"required": []string{"name"},
		},
	}
}

func scanAgentsTool() map[string]any {
	return map[string]any{
		"name":        "scan_agents",
		"description": "Audit a directory for AI agent security risks: prompt injection in CLAUDE.md/AGENTS.md/GEMINI.md, malicious or unencrypted MCP server URLs, excessive permissions in settings.json, and supply-chain risks from unpinned npx MCP packages. Call this before running an agent in an unfamiliar repo, or in CI to gate agent config changes.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"dir": map[string]any{"type": "string", "description": "directory to scan (default: current working directory)"},
			},
		},
	}
}

func (s *Server) toolsCall(params json.RawMessage) map[string]any {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return toolError("bad arguments")
	}
	switch p.Name {
	case "check_package":
		return s.callCheckPackage(p.Arguments)
	case "scan_agents":
		return s.callScanAgents(p.Arguments)
	default:
		return toolError("unknown tool: " + p.Name)
	}
}

func (s *Server) callCheckPackage(raw json.RawMessage) map[string]any {
	var args struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
		Deep      bool   `json:"deep"`
	}
	if err := json.Unmarshal(raw, &args); err != nil || strings.TrimSpace(args.Name) == "" {
		return toolError("missing required argument: name")
	}
	eco := args.Ecosystem
	if eco == "" {
		eco = "npm"
	}
	checker, err := s.Resolve(eco)
	if err != nil {
		return toolError(err.Error())
	}
	res := checker.CheckWith(context.Background(), args.Name, args.Version, args.Deep)
	structured, _ := json.Marshal(res)
	text := renderForAgent(res) + "\n\n" + string(structured)
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": text}},
		"isError": false,
	}
}

func (s *Server) callScanAgents(raw json.RawMessage) map[string]any {
	var args struct {
		Dir string `json:"dir"`
	}
	_ = json.Unmarshal(raw, &args)
	dir := args.Dir
	if dir == "" {
		dir = "."
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return toolError("invalid dir: " + err.Error())
	}
	fi, err := os.Stat(absDir)
	if err != nil {
		return toolError("cannot access dir: " + err.Error())
	}
	if !fi.IsDir() {
		return toolError("dir is not a directory: " + absDir)
	}
	findings, files, err := agentsec.ScanDir(absDir)
	if err != nil {
		return toolError("scan-agents: " + err.Error())
	}
	type out struct {
		Dir      string             `json:"dir"`
		Files    []string           `json:"files_scanned"`
		Findings []agentsec.Finding `json:"findings"`
	}
	result, _ := json.MarshalIndent(out{Dir: dir, Files: files, Findings: findings}, "", "  ")
	var summary string
	if len(findings) == 0 {
		summary = fmt.Sprintf("No issues found in %d file(s). Agent configs look clean.", len(files))
	} else {
		counts := agentsec.CountBySeverity(findings)
		summary = fmt.Sprintf("%d finding(s) in %d file(s) — review and remediate before running agents in this repo.", len(findings), len(files))
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM"} {
			if n := counts[sev]; n > 0 {
				summary += fmt.Sprintf(" %d %s.", n, sev)
			}
		}
	}
	text := summary + "\n\n" + string(result)
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": text}},
		"isError": false,
	}
}

func toolError(msg string) map[string]any {
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": "error: " + msg}},
		"isError": true,
	}
}

// renderForAgent produces a plain-language summary an agent can act on.
func renderForAgent(r verdict.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s — %s@%s", r.VerdictStr, r.Name, r.Version)
	for _, s := range r.Signals {
		if s.Level == verdict.LevelInfo || s.Message == "" {
			continue
		}
		fmt.Fprintf(&b, "\n  - %s", s.Message)
	}
	if r.Suggestion != "" {
		fmt.Fprintf(&b, "\n  did you mean: %s", r.Suggestion)
	}
	switch r.Verdict {
	case verdict.Block:
		b.WriteString("\n\nRECOMMENDATION: do NOT install this package.")
	case verdict.Warn:
		b.WriteString("\n\nRECOMMENDATION: review carefully before installing.")
	default:
		b.WriteString("\n\nRECOMMENDATION: safe to install.")
	}
	return b.String()
}
