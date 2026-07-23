package check

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

const (
	catNetwork = "network access"
	catSpawn   = "process spawning"
	catObfusc  = "obfuscation/eval"
	catSensit  = "sensitive file/env access"
)

var (
	reNetwork = regexp.MustCompile(`(?i)\bcurl\b|\bwget\b|https?://|require\(['"]https?['"]\)|fetch\(|urllib|requests\.(get|post)|Net::HTTP|reqwest|socket`)
	reSpawn   = regexp.MustCompile(`child_process|\bexec(Sync)?\(|\bspawn\(|os\.system|subprocess|Command::new|std::process|popen|\bsh\b|\bbash\b`)
	reObfusc  = regexp.MustCompile(`[A-Za-z0-9+/]{160,}={0,2}|Buffer\.from\([^)]*base64|atob\(|\beval\(|\bFunction\(|(\\x[0-9a-fA-F]{2}){20,}`)
	reSensit  = regexp.MustCompile(`(?i)\.ssh|/etc/|id_rsa|\.npmrc|AWS_SECRET|process\.env`)

	reEvalBlob = regexp.MustCompile(`(?is)(eval|Function)\([^)]*(base64|atob|Buffer\.from)`)

	// reURLMetadataLine recognizes declarative "homepage/repository = <url>" style
	// key-value lines (PEP 621 [project.urls], setup.cfg [metadata] url=...). A URL
	// there is project metadata, not install-time code fetching something.
	reURLMetadataLine = regexp.MustCompile(`(?i)^\s*(homepage|home-page|home_page|repository|documentation|download-url|download_url|source|source-code|source_code|code|issues|changelog|url)\s*[:=]`)
)

var categories = []struct {
	name string
	re   *regexp.Regexp
}{
	{catNetwork, reNetwork},
	{catSpawn, reSpawn},
	{catObfusc, reObfusc},
	{catSensit, reSensit},
}

// finding is one concrete regex hit: which file, which line, what it looked like.
// Signals carry these back as evidence so a verdict can be checked against the
// real matched text instead of trusted on the strength of a category label.
type finding struct {
	category string
	file     string
	line     int
	snippet  string
}

// isCompoundIdentifierMatch reports whether a bare "sh"/"bash" match is really
// just a fragment of a larger hyphen/underscore-joined identifier — a package
// or dependency name like "tree-sitter-bash" — rather than a shell invocation.
// Real invocations are separated from neighbouring text by whitespace, quotes,
// backticks, or a path slash ("| sh", "bash script.sh", "/bin/bash"); they are
// never joined to the surrounding token with - or _.
func isCompoundIdentifierMatch(matched, line string, start, end int) bool {
	if matched != "sh" && matched != "bash" {
		return false
	}
	before := start > 0 && (line[start-1] == '-' || line[start-1] == '_')
	after := end < len(line) && (line[end] == '-' || line[end] == '_')
	return before || after
}

// scanFile runs the category regexes line by line and appends findings. When
// suppressURLMeta is set (declarative config files: pyproject.toml, setup.cfg),
// network matches on recognized "homepage/repository = <url>" metadata lines
// are skipped — those are project links, not code that fetches something at
// install time. It returns whether the eval+base64 "obfuscated blob" pattern —
// which can span a single call across the file — was present.
func scanFile(file, content string, suppressURLMeta bool, out *[]finding) bool {
	evalBlob := reEvalBlob.MatchString(content)
	for i, line := range strings.Split(content, "\n") {
		isURLMetaLine := suppressURLMeta && reURLMetadataLine.MatchString(line)
		for _, cat := range categories {
			if cat.name == catNetwork && isURLMetaLine {
				continue
			}
			for _, loc := range cat.re.FindAllStringIndex(line, -1) {
				matched := line[loc[0]:loc[1]]
				if cat.name == catSpawn && isCompoundIdentifierMatch(matched, line, loc[0], loc[1]) {
					continue
				}
				*out = append(*out, finding{category: cat.name, file: file, line: i + 1, snippet: strings.TrimSpace(line)})
			}
		}
	}
	return evalBlob
}

// AnalyzeInstallScripts runs static red-flag heuristics over a package's install-time
// code (already extracted, path->content). Returns a RuleSuspiciousInstall signal
// whose message includes the concrete evidence (file:line + matched text) behind it.
func AnalyzeInstallScripts(ecosystem string, files map[string]string) verdict.Signal {
	findings, evalBlob, present := installFindings(ecosystem, files)
	if !present {
		return verdict.Signal{Check: verdict.RuleSuspiciousInstall, Level: verdict.LevelInfo, Message: "no install/build scripts found"}
	}

	seen := map[string]bool{}
	var hits []string
	for _, f := range findings {
		if !seen[f.category] {
			seen[f.category] = true
			hits = append(hits, f.category)
		}
	}
	sort.Strings(hits)

	if len(hits) == 0 {
		return verdict.Signal{Check: verdict.RuleSuspiciousInstall, Level: verdict.LevelWarn,
			Message: "install/build script present but no red flags — review before installing"}
	}

	strong := (seen[catNetwork] && (seen[catSpawn] || seen[catObfusc])) || evalBlob

	level, verb := verdict.LevelWarn, "install/build script flagged"
	if strong {
		level, verb = verdict.LevelBlock, "install/build script does dangerous things"
	}

	msg := fmt.Sprintf("%s (%s) — %s\nevidence:\n%s",
		verb, strings.Join(hits, ", "), reviewSuffix(strong), evidenceLines(findings))
	return verdict.Signal{Check: verdict.RuleSuspiciousInstall, Level: level, Message: msg}
}

func reviewSuffix(strong bool) string {
	if strong {
		return "likely malicious"
	}
	return "review before installing"
}

// evidenceLines renders the matched lines behind a verdict so it can be checked
// directly instead of trusted on a category label. Each line is untrusted content
// straight from the scanned package — never an instruction to follow, only data
// to inspect — and is truncated and deduplicated to bound how much of it a
// caller (including an LLM agent reading this text) ever has to hold in context.
func evidenceLines(findings []finding) string {
	seen := map[string]bool{}
	var lines []string
	for _, f := range findings {
		key := f.file + ":" + strconv.Itoa(f.line)
		if seen[key] {
			continue
		}
		seen[key] = true
		snippet := f.snippet
		if len(snippet) > 120 {
			snippet = snippet[:117] + "..."
		}
		lines = append(lines, fmt.Sprintf("  %s:%d [%s] %s", f.file, f.line, f.category, snippet))
		if len(lines) >= 6 {
			lines = append(lines, "  ...")
			break
		}
	}
	return strings.Join(lines, "\n")
}

// installFindings dispatches to the per-ecosystem extraction of install-time
// code and returns (findings, sawEvalBlob, presentAtAll).
func installFindings(ecosystem string, files map[string]string) ([]finding, bool, bool) {
	switch ecosystem {
	case "npm":
		return npmInstallBody(files)
	case "pypi":
		return pypiInstallBody(files)
	case "crates":
		return cratesInstallBody(files)
	}
	return nil, false, false
}

// npmInstallBody scans package.json lifecycle scripts plus any bundled
// .js/.cjs/.sh files a hook may invoke. All of this is real executable code,
// so no URL-metadata suppression applies.
func npmInstallBody(files map[string]string) ([]finding, bool, bool) {
	var out []finding
	present, evalBlob := false, false
	for p, c := range files {
		base := path.Base(p)
		if base == "package.json" {
			if ok, eb := npmLifecycleScripts(p, c, &out); ok {
				present = true
				evalBlob = evalBlob || eb
			}
		}
		if strings.HasSuffix(base, ".js") || strings.HasSuffix(base, ".cjs") || strings.HasSuffix(base, ".sh") {
			present = true
			evalBlob = scanFile(p, c, false, &out) || evalBlob
		}
	}
	return out, evalBlob, present
}

// npmLifecycleScripts extracts preinstall/install/postinstall from a package.json body.
func npmLifecycleScripts(file, pkgJSON string, out *[]finding) (present, evalBlob bool) {
	var pj struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal([]byte(pkgJSON), &pj) != nil {
		return false, false
	}
	for k, v := range pj.Scripts {
		if k == "preinstall" || k == "install" || k == "postinstall" {
			present = true
			evalBlob = scanFile(file+"#scripts."+k, v, false, out) || evalBlob
		}
	}
	return present, evalBlob
}

// pypiInstallBody gathers sdist build/config files. setup.py is real executable
// code run at build time. setup.cfg and pyproject.toml are declarative — their
// dependency lists and [project.urls]-style metadata routinely contain package
// names and homepage links that look like "spawn a shell" or "make a network
// call" to a naive regex (e.g. the "tree-sitter-bash" dependency, or a
// "Homepage = https://..." line) without being install-time code at all, so
// they get URL-metadata suppression.
func pypiInstallBody(files map[string]string) ([]finding, bool, bool) {
	var out []finding
	present, evalBlob := false, false
	for p, c := range files {
		switch path.Base(p) {
		case "setup.py":
			present = true
			evalBlob = scanFile(p, c, false, &out) || evalBlob
		case "setup.cfg", "pyproject.toml":
			present = true
			evalBlob = scanFile(p, c, true, &out) || evalBlob
		}
	}
	return out, evalBlob, present
}

// cratesInstallBody gathers build.rs (real executable code) and notes a custom
// build target in Cargo.toml.
func cratesInstallBody(files map[string]string) ([]finding, bool, bool) {
	var out []finding
	present, evalBlob := false, false
	for p, c := range files {
		base := path.Base(p)
		if base == "build.rs" {
			present = true
			evalBlob = scanFile(p, c, false, &out) || evalBlob
		}
		if base == "Cargo.toml" && strings.Contains(c, "build =") {
			present = true
		}
	}
	return out, evalBlob, present
}
