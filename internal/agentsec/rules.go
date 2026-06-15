package agentsec

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// ── Prompt injection ──────────────────────────────────────────────────────────

var injectionKeywords = []string{
	"ignore previous instructions",
	"disregard all prior",
	"forget all previous",
	"new objective:",
	"system prompt:",
	"you are now",
	"override your instructions",
	"ignore your training",
}

func rulePromptInjection(content, filePath string) []Finding {
	lower := strings.ToLower(content)
	lines := strings.Split(content, "\n")
	var findings []Finding
	for _, kw := range injectionKeywords {
		if !strings.Contains(lower, kw) {
			continue
		}
		line := 0
		for i, l := range lines {
			if strings.Contains(strings.ToLower(l), kw) {
				line = i + 1
				break
			}
		}
		findings = append(findings, Finding{
			RuleID:      "prompt-injection/keyword",
			Severity:    "CRITICAL",
			FilePath:    filePath,
			Line:        line,
			Message:     "Prompt injection keyword detected: '" + kw + "'",
			Description: "The file contains an instruction that could hijack an AI agent's behaviour.",
			Remediation: "Remove or review this instruction. Triage as false positive if intentional.",
			Confidence:  0.88,
		})
	}
	return findings
}

// ── Hidden unicode ────────────────────────────────────────────────────────────

var hiddenUnicodeRanges = []*unicode.RangeTable{
	{R16: []unicode.Range16{{Lo: 0x200B, Hi: 0x200F, Stride: 1}}}, // zero-width chars
	{R16: []unicode.Range16{{Lo: 0x202A, Hi: 0x202E, Stride: 1}}}, // bidi overrides
	{R16: []unicode.Range16{{Lo: 0xFEFF, Hi: 0xFEFF, Stride: 1}}}, // BOM
}

func ruleHiddenUnicode(content, filePath string) []Finding {
	lines := strings.Split(content, "\n")
	var findings []Finding
	for i, line := range lines {
		for _, r := range line {
			for _, table := range hiddenUnicodeRanges {
				if unicode.Is(table, r) {
					findings = append(findings, Finding{
						RuleID:      "prompt-injection/hidden-unicode",
						Severity:    "CRITICAL",
						FilePath:    filePath,
						Line:        i + 1,
						Message:     "Hidden unicode character detected (possible prompt injection)",
						Description: "Zero-width or bidi-override unicode characters can hide instructions from human reviewers.",
						Remediation: "Remove the hidden characters. Use a hex editor or 'cat -A' to inspect.",
						Confidence:  0.95,
					})
					goto nextLine
				}
			}
		}
	nextLine:
	}
	return findings
}

// ── MCP host checks ───────────────────────────────────────────────────────────

type mcpConfig struct {
	MCPServers map[string]struct {
		URL     string   `json:"url"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
	} `json:"mcpServers"`
}

var tunnelPatterns = regexp.MustCompile(`ngrok\.io|localtunnel\.me|serveo\.net|localhost\.run|trycloudflare\.com`)

func ruleMCPHosts(content, filePath string) []Finding {
	if !strings.HasSuffix(filePath, ".json") {
		return nil
	}
	var cfg mcpConfig
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		return nil
	}
	var findings []Finding
	for name, srv := range cfg.MCPServers {
		rawURL := srv.URL
		if rawURL == "" {
			continue
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			continue
		}
		if u.Scheme == "http" {
			findings = append(findings, Finding{
				RuleID:      "mcp-host/non-https",
				Severity:    "HIGH",
				FilePath:    filePath,
				Message:     "MCP server '" + name + "' uses non-HTTPS URL: " + rawURL,
				Description: "Unencrypted MCP connections expose tool calls and responses to interception.",
				Remediation: "Use HTTPS for all external MCP server URLs.",
				Confidence:  1.0,
			})
		}
		if net.ParseIP(host) != nil {
			findings = append(findings, Finding{
				RuleID:      "mcp-host/raw-ip",
				Severity:    "HIGH",
				FilePath:    filePath,
				Message:     "MCP server '" + name + "' uses a raw IP address: " + host,
				Description: "Raw IP MCP servers bypass hostname verification and may indicate C2 infrastructure.",
				Remediation: "Use a hostname with a valid TLS certificate instead of a raw IP.",
				Confidence:  0.92,
			})
		}
		if tunnelPatterns.MatchString(rawURL) {
			findings = append(findings, Finding{
				RuleID:      "mcp-host/tunnel",
				Severity:    "HIGH",
				FilePath:    filePath,
				Message:     "MCP server '" + name + "' uses a tunnel service: " + rawURL,
				Description: "Tunnel services expose local ports to the internet and are commonly used in attacks.",
				Remediation: "Replace with a stable, verified MCP server URL.",
				Confidence:  0.95,
			})
		}
	}
	return findings
}

// ── Excessive permissions ─────────────────────────────────────────────────────

var dangerousTools = []string{"Bash", "Computer", "Shell"}

var wildcardPatterns = regexp.MustCompile(`^\*$|^[A-Za-z]+\(\s*\*`)

func isHighRiskUnqualified(entry string) bool {
	highRisk := []string{"Bash", "Write", "Edit", "Computer", "Shell"}
	for _, t := range highRisk {
		if strings.EqualFold(entry, t) {
			return true
		}
	}
	return false
}

type permissionsSchema struct {
	Permissions struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	} `json:"permissions"`
	Tools []string `json:"tools"`
}

func ruleExcessivePermissions(content, filePath string) []Finding {
	if !strings.HasSuffix(filePath, ".json") {
		return nil
	}
	var cfg permissionsSchema
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		return nil
	}
	var findings []Finding
	for _, entry := range cfg.Permissions.Allow {
		if wildcardPatterns.MatchString(entry) {
			findings = append(findings, Finding{
				RuleID:      "permissions/wildcard-allow",
				Severity:    "HIGH",
				FilePath:    filePath,
				Message:     "permissions.allow contains a wildcard entry: '" + entry + "'",
				Description: "A wildcard allow rule grants the agent unrestricted tool access, enabling arbitrary command execution.",
				Remediation: "Replace the wildcard with specific, scoped tool entries (e.g. 'Bash(npm run build)').",
				Confidence:  0.95,
			})
			continue
		}
		if isHighRiskUnqualified(entry) && len(cfg.Permissions.Deny) == 0 {
			findings = append(findings, Finding{
				RuleID:      "permissions/unrestricted-shell",
				Severity:    "MEDIUM",
				FilePath:    filePath,
				Message:     "permissions.allow grants unqualified '" + entry + "' with no deny rules",
				Description: "Unrestricted shell/write tool access with an empty deny list allows agents to execute arbitrary commands.",
				Remediation: "Add argument restrictions (e.g. 'Bash(npm run build)') or add deny rules to limit scope.",
				Confidence:  0.88,
			})
		}
	}
	for _, tool := range cfg.Tools {
		for _, danger := range dangerousTools {
			if strings.EqualFold(tool, danger) {
				findings = append(findings, Finding{
					RuleID:      "permissions/unrestricted-shell",
					Severity:    "MEDIUM",
					FilePath:    filePath,
					Message:     "Settings grant unrestricted '" + tool + "' tool access",
					Description: "Unrestricted shell/computer tool access allows agents to execute arbitrary commands.",
					Remediation: "Restrict allowed commands via an allowlist in settings.",
					Confidence:  0.88,
				})
			}
		}
	}
	return findings
}

// ── Supply chain ──────────────────────────────────────────────────────────────

var npxPattern = regexp.MustCompile(`"command"\s*:\s*"npx"`)

func ruleSupplyChain(content, filePath, root string) []Finding {
	if !strings.HasSuffix(filePath, ".json") {
		return nil
	}
	if !npxPattern.MatchString(content) {
		return nil
	}
	dir := filepath.Join(root, filepath.Dir(filePath))
	lockFiles := []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}
	for _, lf := range lockFiles {
		if _, err := os.Stat(filepath.Join(dir, lf)); err == nil {
			return nil
		}
	}
	return []Finding{{
		RuleID:      "supply-chain/npx-no-lockfile",
		Severity:    "MEDIUM",
		FilePath:    filePath,
		Message:     "MCP server uses npx without a lock file",
		Description: "Running npx without a lock file allows dependency version drift and supply-chain substitution attacks.",
		Remediation: "Add package-lock.json or npm-shrinkwrap.json and pin exact MCP package versions.",
		Confidence:  0.90,
	}}
}

// ── Encoded instructions ──────────────────────────────────────────────────────

var reBase64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{60,}={0,2}`)

func encodedInstructionsSuspect(filePath string) bool {
	base := strings.ToLower(filepath.Base(filePath))
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".md" || base == ".mcp.json"
}

func ruleEncodedInstructions(content, filePath string) []Finding {
	if !encodedInstructionsSuspect(filePath) {
		return nil
	}
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if reBase64Blob.MatchString(line) {
			return []Finding{{
				RuleID:      "prompt-injection/encoded-instructions",
				Severity:    "CRITICAL",
				FilePath:    filePath,
				Line:        i + 1,
				Message:     "Possible base64-encoded instructions detected",
				Description: "Base64-encoded content in agent config files is a known vector for hiding prompt injection.",
				Remediation: "Review and remove the encoded content. If legitimate, document why base64 is needed here.",
				Confidence:  0.65,
			}}
		}
	}
	return nil
}

// ── Conditional triggers ──────────────────────────────────────────────────────

var conditionalTriggerPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)when\s+.*user\s+.*ask`),
	regexp.MustCompile(`(?i)if\s+.*user\s+.*mention`),
	regexp.MustCompile(`(?i)when\s+.*conversation\s+.*contain`),
	regexp.MustCompile(`(?i)only\s+if\b`),
	regexp.MustCompile(`(?i)unless\s+told\b`),
	regexp.MustCompile(`(?i)except\s+when\b`),
	regexp.MustCompile(`(?i)^trigger:`),
	regexp.MustCompile(`(?i)activate\s+when\b`),
	regexp.MustCompile(`(?i)^condition:`),
}

func ruleConditionalTriggers(content, filePath string) []Finding {
	lines := strings.Split(content, "\n")
	var findings []Finding
	for i, line := range lines {
		for _, re := range conditionalTriggerPatterns {
			if re.MatchString(line) {
				findings = append(findings, Finding{
					RuleID:      "prompt-injection/conditional-trigger",
					Severity:    "CRITICAL",
					FilePath:    filePath,
					Line:        i + 1,
					Message:     "Conditional trigger pattern detected: '" + strings.TrimSpace(line) + "'",
					Description: "Sleeper instructions that activate only under specific conditions are a hallmark of targeted prompt-injection attacks.",
					Remediation: "Review this conditional carefully. Dismiss as false positive if it is a legitimate skill trigger phrase.",
					Confidence:  0.60,
				})
				break
			}
		}
	}
	return findings
}

// ── Persona override ──────────────────────────────────────────────────────────

var personaOverridePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\byou\s+are\s+now\b`),
	regexp.MustCompile(`(?i)\bact\s+as\s+\S`),
	regexp.MustCompile(`(?i)\byour\s+new\s+name\s+is\b`),
	regexp.MustCompile(`(?i)\byour\s+real\s+name\s+is\b`),
	regexp.MustCompile(`(?i)\bforget\s+you\s+are\b`),
	regexp.MustCompile(`(?i)\byou\s+are\s+not\s+claude\b`),
	regexp.MustCompile(`(?i)\byou\s+are\s+not\s+an\s+ai\b`),
	regexp.MustCompile(`(?i)\byour\s+true\s+purpose\b`),
	regexp.MustCompile(`(?i)\byour\s+actual\s+goal\b`),
}

func rulePersonaOverride(content, filePath string) []Finding {
	lines := strings.Split(content, "\n")
	var findings []Finding
	for i, line := range lines {
		for _, re := range personaOverridePatterns {
			if re.MatchString(line) {
				findings = append(findings, Finding{
					RuleID:      "prompt-injection/persona-override",
					Severity:    "HIGH",
					FilePath:    filePath,
					Line:        i + 1,
					Message:     "Persona override pattern detected: '" + strings.TrimSpace(line) + "'",
					Description: "Instructions that attempt to replace the agent's identity are a strong signal of prompt hijacking.",
					Remediation: "Review this instruction. Legitimate persona assignments in skills are usually false positives.",
					Confidence:  0.72,
				})
				break
			}
		}
	}
	return findings
}
