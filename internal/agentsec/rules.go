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

// ── Output sanitization ───────────────────────────────────────────────────────

const maxExcerptLen = 120

// sanitizeExcerpt strips hidden unicode and control characters from s and
// truncates to maxExcerptLen runes. Applied to all attacker-controlled content
// before it is embedded in Finding.Message to prevent second-order prompt
// injection via the scanner's own output.
func sanitizeExcerpt(s string) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count >= maxExcerptLen {
			b.WriteString("…")
			break
		}
		// Use the same broadened hidden-rune check as ruleHiddenUnicode so that
		// detected characters (unicode.Cf, variation selectors FE00–FE0F, etc.)
		// cannot leak into Finding.Message excerpts.
		if isHiddenRune(r) {
			continue
		}
		if r < 0x20 && r != '\t' { // drop control chars except tab
			continue
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

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
	folded := foldForMatch(content)
	origLines := strings.Split(strings.ToLower(content), "\n")
	var findings []Finding
	for _, kw := range injectionKeywords {
		// Fold the keyword with the same transform applied to content so that
		// keywords containing ":" (e.g. "system prompt:", "new objective:") still
		// match: foldForMatch collapses ":" to a space on both sides, making the
		// comparison symmetric. The original kw is preserved for the user message.
		fkw := foldForMatch(kw)
		if !strings.Contains(folded, fkw) {
			continue
		}
		line := lineOfFoldedKeyword(content, origLines, fkw)
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

// lineOfFoldedKeyword best-efforts a 1-based line number for a keyword that matched the
// folded view: first try a raw lowercased substring match per line; else fold each line and
// match; else 0 (whole-file). kw must be the pre-folded form (via foldForMatch) so that
// keywords with punctuation (e.g. "system prompt") align with the lowercased raw lines.
func lineOfFoldedKeyword(content string, lowerLines []string, kw string) int {
	for i, l := range lowerLines {
		if strings.Contains(l, kw) {
			return i + 1
		}
	}
	for i, l := range strings.Split(content, "\n") {
		if strings.Contains(foldForMatch(l), kw) {
			return i + 1
		}
	}
	return 0
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
			if isHiddenRune(r) {
				findings = append(findings, Finding{
					RuleID:      "prompt-injection/hidden-unicode",
					Severity:    "CRITICAL",
					FilePath:    filePath,
					Line:        i + 1,
					Message:     "Hidden unicode character detected (possible prompt injection)",
					Description: "Zero-width, bidi-override, or format unicode characters can hide instructions from human reviewers.",
					Remediation: "Remove the hidden characters. Use a hex editor or 'cat -A' to inspect.",
					Confidence:  0.95,
				})
				break
			}
		}
	}
	return findings
}

// isHiddenRune reports characters that smuggle/obscure instructions: the curated ranges plus
// any Unicode format char and word-joiner / variation-selector blocks.
func isHiddenRune(r rune) bool {
	for _, table := range hiddenUnicodeRanges {
		if unicode.Is(table, r) {
			return true
		}
	}
	if unicode.Is(unicode.Cf, r) {
		return true
	}
	// Word joiner / invisible operators U+2060–U+2064 (also in Cf, belt-and-suspenders).
	if r >= 0x2060 && r <= 0x2064 {
		return true
	}
	// Variation selectors U+FE00–U+FE0F.
	if r >= 0xFE00 && r <= 0xFE0F {
		return true
	}
	return false
}

// ── MCP host checks ───────────────────────────────────────────────────────────

type mcpConfig struct {
	MCPServers map[string]struct {
		URL     string            `json:"url"`
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
		Tools   []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
	} `json:"mcpServers"`
}

var tunnelPatterns = regexp.MustCompile(
	`ngrok\.io|ngrok-free\.app|ngrok\.app|localtunnel\.me|loca\.lt|serveo\.net|` +
		`localhost\.run|trycloudflare\.com|tunnelmole\.com|bore\.pub|pinggy\.io|lhr\.life|devtunnels\.ms`)

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
		sName := sanitizeExcerpt(name)
		sURL := sanitizeExcerpt(rawURL)
		sHost := sanitizeExcerpt(host)
		if strings.ToLower(u.Scheme) == "http" {
			findings = append(findings, Finding{
				RuleID:      "mcp-host/non-https",
				Severity:    "HIGH",
				FilePath:    filePath,
				Message:     "MCP server '" + sName + "' uses non-HTTPS URL: " + sURL,
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
				Message:     "MCP server '" + sName + "' uses a raw IP address: " + sHost,
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
				Message:     "MCP server '" + sName + "' uses a tunnel service: " + sURL,
				Description: "Tunnel services expose local ports to the internet and are commonly used in attacks.",
				Remediation: "Replace with a stable, verified MCP server URL.",
				Confidence:  0.95,
			})
		}
	}
	return findings
}

// ── Excessive permissions ─────────────────────────────────────────────────────

// dangerousTools covers execution tools that appear in the legacy cfg.Tools field
// (Claude Desktop format). Write/Edit are absent here because they don't appear
// in that schema — they are permissions.allow-only tools (see isHighRiskUnqualified).
var dangerousTools = []string{"Bash", "Computer", "Shell"}

var wildcardPatterns = regexp.MustCompile(`^\*$|^[A-Za-z]+\(\s*\*|\*\s*\)$|\([^)]*\*[^)]*\)`)

func isHighRiskUnqualified(entry string) bool {
	// Broader than dangerousTools: includes Write/Edit/WebFetch/Execute, which are Claude Code
	// permission tokens and risky when unqualified in permissions.allow.
	for _, t := range []string{"Bash", "Write", "Edit", "Computer", "Shell", "WebFetch", "Execute"} {
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
		sEntry := sanitizeExcerpt(entry)
		if wildcardPatterns.MatchString(entry) {
			findings = append(findings, Finding{
				RuleID:      "permissions/wildcard-allow",
				Severity:    "HIGH",
				FilePath:    filePath,
				Message:     "permissions.allow contains a wildcard entry: '" + sEntry + "'",
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
				Message:     "permissions.allow grants unqualified '" + sEntry + "' with no deny rules",
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
					Message:     "Settings grant unrestricted '" + sanitizeExcerpt(tool) + "' tool access",
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

// reBase64Line matches a single line that consists entirely of base64 characters
// (8+ chars, optional padding), used to detect line-wrapped base64 blobs.
var reBase64Line = regexp.MustCompile(`^[A-Za-z0-9+/]{8,}={0,2}$`)

// isBenignBase64 excludes data: URIs, inline base64 content blocks, and the
// canonical RFC-7519 example JWT header so that legitimate SVG/image data URIs
// and well-known JWT examples do not trigger a false positive.
func isBenignBase64(s string) bool {
	return strings.Contains(s, "data:") ||
		strings.Contains(s, "base64,") ||
		strings.Contains(s, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
}

func base64Finding(filePath string, line int) Finding {
	return Finding{
		RuleID:      "prompt-injection/encoded-instructions",
		Severity:    "CRITICAL",
		FilePath:    filePath,
		Line:        line,
		Message:     "Possible base64-encoded instructions detected",
		Description: "Base64-encoded content in agent config files is a known vector for hiding prompt injection.",
		Remediation: "Review and remove the encoded content. If legitimate, document why base64 is needed here.",
		Confidence:  0.65,
	}
}

// ruleEncodedInstructions detects base64-encoded payloads in any scanned file.
// It checks each line for an inline blob and also joins consecutive base64-ish
// lines to catch line-wrapped encodings. data: URIs and the RFC-7519 example
// JWT are excluded to avoid false positives on legitimate content.
func ruleEncodedInstructions(content, filePath string) []Finding {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if reBase64Blob.MatchString(line) && !isBenignBase64(line) {
			return []Finding{base64Finding(filePath, i+1)}
		}
	}
	// Line-wrapped base64: join consecutive base64-ish lines and test the blob.
	var run strings.Builder
	start := 0
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if reBase64Line.MatchString(t) {
			if run.Len() == 0 {
				start = i + 1
			}
			run.WriteString(t)
			if reBase64Blob.MatchString(run.String()) && !isBenignBase64(run.String()) {
				return []Finding{base64Finding(filePath, start)}
			}
		} else {
			run.Reset()
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

// scanLinePatterns scans content line-by-line against patterns, appending a
// finding for each match. tmpl.Message is used as a prefix; the matched line
// text is appended. FilePath and Line are filled in per match.
func scanLinePatterns(content, filePath string, patterns []*regexp.Regexp, tmpl Finding) []Finding {
	lines := strings.Split(content, "\n")
	var findings []Finding
	for i, line := range lines {
		folded := foldForMatch(line)
		for _, re := range patterns {
			if re.MatchString(line) || re.MatchString(folded) {
				f := tmpl
				f.FilePath = filePath
				f.Line = i + 1
				f.Message = tmpl.Message + sanitizeExcerpt(strings.TrimSpace(line)) + "'"
				findings = append(findings, f)
				break
			}
		}
	}
	return findings
}

func ruleConditionalTriggers(content, filePath string) []Finding {
	return scanLinePatterns(content, filePath, conditionalTriggerPatterns, Finding{
		RuleID:      "prompt-injection/conditional-trigger",
		Severity:    "CRITICAL",
		Message:     "Conditional trigger pattern detected: '",
		Description: "Sleeper instructions that activate only under specific conditions are a hallmark of targeted prompt-injection attacks.",
		Remediation: "Review this conditional carefully. Dismiss as false positive if it is a legitimate skill trigger phrase.",
		Confidence:  0.60,
	})
}

func rulePersonaOverride(content, filePath string) []Finding {
	return scanLinePatterns(content, filePath, personaOverridePatterns, Finding{
		RuleID:      "prompt-injection/persona-override",
		Severity:    "HIGH",
		Message:     "Persona override pattern detected: '",
		Description: "Instructions that attempt to replace the agent's identity are a strong signal of prompt hijacking.",
		Remediation: "Review this instruction. Legitimate persona assignments in skills are usually false positives.",
		Confidence:  0.72,
	})
}

// ── Lifecycle hooks ───────────────────────────────────────────────────────────

type hookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

type hookMatcher struct {
	Matcher string      `json:"matcher"`
	Hooks   []hookEntry `json:"hooks"`
}

type hooksConfig struct {
	Hooks map[string][]hookMatcher `json:"hooks"`
}

// hookDownloadExec matches download-pipe-execute and base64-decode-execute patterns.
var hookDownloadExec = regexp.MustCompile(
	`(?i)(curl|wget)\s+\S+\s*\|\s*(ba?sh|sh|zsh|fish)\b` +
		`|base64\b.*\|\s*(ba?sh|sh)\b`)

// hookShellFlag matches a shell interpreter invoked with an inline-code flag.
var hookShellFlag = regexp.MustCompile(`(?i)^(ba?sh|sh|zsh|fish|cmd(\.exe)?|powershell|pwsh)\s+(-c|-e|/c)\b`)

func ruleHooks(content, filePath string) []Finding {
	if !strings.HasSuffix(filePath, ".json") {
		return nil
	}
	var cfg hooksConfig
	if err := json.Unmarshal([]byte(content), &cfg); err != nil || len(cfg.Hooks) == 0 {
		return nil
	}
	var findings []Finding
	for event, matchers := range cfg.Hooks {
		sEvent := sanitizeExcerpt(event)
		for _, m := range matchers {
			for _, h := range m.Hooks {
				if h.Type != "command" || h.Command == "" {
					continue
				}
				cmd := sanitizeExcerpt(h.Command)
				sev, desc := "MEDIUM", "Hook commands run automatically during agent sessions without user confirmation."
				if hookDownloadExec.MatchString(h.Command) {
					sev = "CRITICAL"
					desc = "Hook command matches a download-execute pattern — likely malicious."
				} else if hookShellFlag.MatchString(h.Command) {
					sev = "HIGH"
					desc = "Hook runs a shell with an inline-execution flag (-c/-e), enabling arbitrary code execution."
				}
				findings = append(findings, Finding{
					RuleID:      "permissions/auto-run-hook",
					Severity:    sev,
					FilePath:    filePath,
					Message:     "Hook '" + sEvent + "' runs command: " + cmd,
					Description: desc,
					Remediation: "Review this hook. Auto-run hooks execute arbitrary commands — remove any not intentionally added.",
					Confidence:  0.92,
				})
			}
		}
	}
	return findings
}

// ── MCP command / args / env ──────────────────────────────────────────────────

var mcpDangerousShells = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "fish": true,
	"cmd": true, "cmd.exe": true, "powershell": true, "pwsh": true,
}

var mcpDangerousEnvKeys = []string{
	"LD_PRELOAD", "LD_LIBRARY_PATH", "NODE_OPTIONS", "PYTHONSTARTUP",
	"BASH_ENV", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
	"GIT_SSH_COMMAND", "PYTHONPATH", "ELECTRON_RUN_AS_NODE", "PERL5OPT", "RUBYOPT", "RUBYLIB",
}

var mcpTmpPath = regexp.MustCompile(`(?i)^(/tmp/|/var/tmp/|/dev/shm/|~?/downloads/|\\[Tt]emp\\|%[Tt][Ee][Mm][Pp]%)`)

func ruleMCPCommands(content, filePath string) []Finding {
	if !strings.HasSuffix(filePath, ".json") {
		return nil
	}
	var cfg mcpConfig
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		return nil
	}
	var findings []Finding
	for name, srv := range cfg.MCPServers {
		sName := sanitizeExcerpt(name)

		if srv.Command != "" {
			base := strings.ToLower(filepath.Base(srv.Command))
			if mcpDangerousShells[base] {
				// Shell + -c/-e in args = inline code execution
				inlineExec := false
				for _, arg := range srv.Args {
					if arg == "-c" || arg == "-e" || arg == "/c" {
						inlineExec = true
						break
					}
				}
				if inlineExec {
					findings = append(findings, Finding{
						RuleID:      "mcp-exec/shell-inline",
						Severity:    "CRITICAL",
						FilePath:    filePath,
						Message:     "MCP server '" + sName + "' runs a shell with inline execution flag",
						Description: "Shell with -c/-e executes arbitrary code at MCP server startup without user confirmation.",
						Remediation: "Remove inline shell execution. Use a dedicated script file with a fixed path instead.",
						Confidence:  0.95,
					})
				} else {
					findings = append(findings, Finding{
						RuleID:      "mcp-exec/dangerous-command",
						Severity:    "HIGH",
						FilePath:    filePath,
						Message:     "MCP server '" + sName + "' uses shell interpreter: " + sanitizeExcerpt(srv.Command),
						Description: "A shell interpreter as the MCP command allows arbitrary code execution on agent startup.",
						Remediation: "Replace with a specific script or binary rather than a shell interpreter.",
						Confidence:  0.88,
					})
				}
			} else if mcpTmpPath.MatchString(srv.Command) {
				findings = append(findings, Finding{
					RuleID:      "mcp-exec/temp-path",
					Severity:    "HIGH",
					FilePath:    filePath,
					Message:     "MCP server '" + sName + "' executes a binary from a temporary directory",
					Description: "Binaries in temp directories may be planted by attackers and are not version-controlled.",
					Remediation: "Use a path within the project or a system-installed binary.",
					Confidence:  0.90,
				})
			}
			// Interpreter + inline-eval (node -e, python -c/-m, deno, ruby/perl -e)
			evalFlags := map[string][]string{
				"node": {"-e", "--eval"}, "deno": {"eval"},
				"python": {"-c", "-m"}, "python3": {"-c", "-m"},
				"ruby": {"-e"}, "perl": {"-e"},
			}
			if flags, ok := evalFlags[base]; ok && hasAnyArg(srv.Args, flags) {
				findings = append(findings, Finding{
					RuleID:      "mcp-exec/interpreter-eval",
					Severity:    "HIGH",
					FilePath:    filePath,
					Message:     "MCP server '" + sName + "' runs an interpreter with an inline-eval flag",
					Description: "An interpreter with -e/-c/-m executes arbitrary code at MCP server startup.",
					Remediation: "Replace inline code with a committed, reviewed script file at a fixed path.",
					Confidence:  0.9,
				})
			}
			// `env <shell-or-interpreter> ...` wrapper hides the real command basename.
			if base == "env" && len(srv.Args) > 0 {
				inner := strings.ToLower(filepath.Base(srv.Args[0]))
				if mcpDangerousShells[inner] || evalFlags[inner] != nil {
					findings = append(findings, Finding{
						RuleID:      "mcp-exec/env-wrapper",
						Severity:    "HIGH",
						FilePath:    filePath,
						Message:     "MCP server '" + sName + "' uses 'env' to launch a shell/interpreter",
						Description: "Wrapping a shell or interpreter in 'env' obscures the executed command.",
						Remediation: "Invoke a specific reviewed binary directly instead of via 'env'.",
						Confidence:  0.85,
					})
				}
			}
		}

		for k := range srv.Env {
			for _, dangerous := range mcpDangerousEnvKeys {
				if strings.EqualFold(k, dangerous) {
					findings = append(findings, Finding{
						RuleID:      "mcp-exec/env-injection",
						Severity:    "HIGH",
						FilePath:    filePath,
						Message:     "MCP server '" + sName + "' sets dangerous env var: " + sanitizeExcerpt(k),
						Description: "Setting " + dangerous + " can hijack code execution within the MCP server process.",
						Remediation: "Remove this environment variable from the MCP server config.",
						Confidence:  0.92,
					})
				}
			}
		}
	}
	return findings
}

// hasAnyArg reports whether any element of args matches any element of want (exact string equality).
func hasAnyArg(args, want []string) bool {
	for _, a := range args {
		for _, w := range want {
			if a == w {
				return true
			}
		}
	}
	return false
}

// ── Credential access ─────────────────────────────────────────────────────────

// credentialPathPattern matches known credential file names/paths referenced in
// instruction prose. JSON files are excluded — they're config, not instructions.
var credentialPathPattern = regexp.MustCompile(
	`(?i)(^|[\s'"` + "`" + `/\\])` +
		`(\.env\b|id_rsa\b|id_ed25519\b|` +
		`\.aws[/\\]credentials\b|` +
		`\.npmrc\b|\.git-credentials\b|` +
		`\.netrc\b|` +
		`~[/\\]\.ssh[/\\])`)

func ruleCredentialAccess(content, filePath string) []Finding {
	if strings.HasSuffix(filePath, ".json") {
		return nil
	}
	lines := strings.Split(content, "\n")
	var findings []Finding
	for i, line := range lines {
		if credentialPathPattern.MatchString(line) {
			findings = append(findings, Finding{
				RuleID:      "exfil/credential-access",
				Severity:    "HIGH",
				FilePath:    filePath,
				Line:        i + 1,
				Message:     "Instruction references a credential file: '" + sanitizeExcerpt(strings.TrimSpace(line)) + "'",
				Description: "Referencing credential files in agent instructions is a common exfiltration payload pattern.",
				Remediation: "Remove this reference. If intentional, document why and add a zyrax-allow suppression.",
				Confidence:  0.65,
			})
		}
	}
	return findings
}

// ── Exfiltration sinks ────────────────────────────────────────────────────────

var exfilVerbPattern = regexp.MustCompile(
	`(?i)\b(send|post|upload|curl|wget|fetch|exfiltrate|transmit|forward|relay)\b`)

var anyURLPattern = regexp.MustCompile(`(?i)https?://[\w.\-]+`)

var localHosts = []string{"localhost", "127.0.0.1", "::1"}

func hasExternalURL(line string) bool {
	m := anyURLPattern.FindString(line)
	if m == "" {
		return false
	}
	lower := strings.ToLower(m)
	for _, h := range localHosts {
		if strings.Contains(lower, h) {
			return false
		}
	}
	return true
}

func ruleExfiltrationSink(content, filePath string) []Finding {
	if strings.HasSuffix(filePath, ".json") {
		return nil
	}
	lines := strings.Split(content, "\n")
	var findings []Finding
	for i, line := range lines {
		if exfilVerbPattern.MatchString(line) && hasExternalURL(line) {
			findings = append(findings, Finding{
				RuleID:      "exfil/external-sink",
				Severity:    "HIGH",
				FilePath:    filePath,
				Line:        i + 1,
				Message:     "Instruction combines exfiltration verb with external URL: '" + sanitizeExcerpt(strings.TrimSpace(line)) + "'",
				Description: "Instructions that send data to external URLs are a primary exfiltration mechanism in prompt-injection attacks.",
				Remediation: "Remove this instruction. If it is legitimate, add a zyrax-allow suppression with justification.",
				Confidence:  0.70,
			})
		}
	}
	return findings
}

// ── MCP tool description injection ───────────────────────────────────────────

func ruleMCPToolDescription(content, filePath string) []Finding {
	if !strings.HasSuffix(filePath, ".json") {
		return nil
	}
	var cfg mcpConfig
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		return nil
	}
	var findings []Finding
	for serverName, srv := range cfg.MCPServers {
		for _, tool := range srv.Tools {
			lower := strings.ToLower(tool.Description)
			for _, kw := range injectionKeywords {
				if strings.Contains(lower, kw) {
					findings = append(findings, Finding{
						RuleID:      "prompt-injection/tool-description",
						Severity:    "CRITICAL",
						FilePath:    filePath,
						Message:     "MCP server '" + sanitizeExcerpt(serverName) + "' tool '" + sanitizeExcerpt(tool.Name) + "' description contains injection keyword",
						Description: "Tool descriptions are read by the model as trusted context — injection keywords here bypass instruction-file scanning.",
						Remediation: "Remove the injection keyword from the tool description. If this MCP server is third-party, do not use it.",
						Confidence:  0.88,
					})
					break
				}
			}
		}
	}
	return findings
}
