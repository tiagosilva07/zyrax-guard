package check

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

// GitHubAPIHost is the only host RepoContext ever talks to. It is passed to
// httpx.New's allowlist by the caller — RepoContext never constructs a request
// against an arbitrary host, even though the repo URL it parses comes from
// package-supplied (untrusted) registry metadata. See githubRepoRe.
const GitHubAPIHost = "api.github.com"

// githubRepoRe extracts owner/repo from a github.com URL. The input is
// untrusted — it's the "Repository"/"Homepage" field from a package's own
// registry metadata, so a malicious package could set it to anything. Only a
// plain https://github.com/<owner>/<repo>[.git][/...] shape is accepted; the
// owner/repo are re-assembled into our own GitHub API URL rather than the
// original string being reused, so this can never itself become an SSRF
// vector — a non-matching or non-github.com URL just yields no context.
var githubRepoRe = regexp.MustCompile(`^https://(?:www\.)?github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)/([A-Za-z0-9._-]+?)(?:\.git)?/?(?:[/?#].*)?$`)

type githubRepoJSON struct {
	StargazersCount int       `json:"stargazers_count"`
	CreatedAt       time.Time `json:"created_at"`
	PushedAt        time.Time `json:"pushed_at"`
	Archived        bool      `json:"archived"`
}

// GitHubClient fetches advisory-only repo context. apiBase is overridable so
// tests can point it at an httptest server, mirroring how ecosystem Providers
// expose registryBase/statsBase for the same reason.
type GitHubClient struct {
	http    *httpx.Client
	apiBase string
}

func NewGitHubClient(http *httpx.Client) *GitHubClient {
	return &GitHubClient{http: http, apiBase: "https://" + GitHubAPIHost}
}

// Context returns advisory-only context about the package's linked GitHub
// repo (age, stars, last push activity). This signal NEVER escalates or
// suppresses a verdict — it is always LevelInfo, deliberately, for two
// reasons: (1) stars/forks are cheap to buy or bot and easy to misrepresent —
// this tool has already seen a coordinated attempt to inflate a malicious
// package's perceived legitimacy via fabricated star counts; (2) real
// supply-chain attacks (event-stream, ua-parser-js, xz-utils) compromise
// already-trusted, reputable repos — a "trust score" that could downgrade a
// behavioral finding like suspicious-install would hand attackers exactly the
// blind spot they rely on. This exists purely to give a human more to look
// at alongside the verdict, never to decide the verdict.
func (g *GitHubClient) Context(ctx context.Context, repoURL string) verdict.Signal {
	m := githubRepoRe.FindStringSubmatch(strings.TrimSpace(repoURL))
	if m == nil {
		return verdict.Signal{Check: verdict.RuleRepoContext, Level: verdict.LevelInfo}
	}
	owner, repo := m[1], m[2]
	var gh githubRepoJSON
	code, err := g.http.GetJSON(ctx, g.apiBase+"/repos/"+owner+"/"+repo, &gh)
	if err != nil || code != 200 {
		// Best-effort: rate-limited, private, deleted, or unreachable — say
		// nothing rather than report a misleading absence of context.
		return verdict.Signal{Check: verdict.RuleRepoContext, Level: verdict.LevelInfo}
	}
	ageDays := int(time.Since(gh.CreatedAt).Hours() / 24)
	pushDays := int(time.Since(gh.PushedAt).Hours() / 24)
	status := "active"
	if gh.Archived {
		status = "archived"
	}
	msg := fmt.Sprintf("repo context (advisory only, not a trust decision): github.com/%s/%s — created %dd ago, %d stars, last push %dd ago, %s",
		owner, repo, ageDays, gh.StargazersCount, pushDays, status)
	return verdict.Signal{Check: verdict.RuleRepoContext, Level: verdict.LevelInfo, Message: msg}
}
