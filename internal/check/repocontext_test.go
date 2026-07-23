package check

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

func newTestGitHubClient(t *testing.T, h http.Handler) *GitHubClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	g := NewGitHubClient(httpx.New([]string{host}))
	g.apiBase = srv.URL
	return g
}

func TestGitHubRepoRe(t *testing.T) {
	cases := []struct {
		url       string
		wantOwner string
		wantRepo  string
		wantNoHit bool
	}{
		{"https://github.com/psf/requests", "psf", "requests", false},
		{"https://github.com/psf/requests.git", "psf", "requests", false},
		{"https://github.com/psf/requests/", "psf", "requests", false},
		{"https://github.com/psf/requests/tree/main", "psf", "requests", false},
		{"https://www.github.com/psf/requests", "psf", "requests", false},
		{"https://gitlab.com/psf/requests", "", "", true},
		{"not a url at all", "", "", true},
		{"https://github.com.evil.example/psf/requests", "", "", true},
		{"https://github.com/", "", "", true},
	}
	for _, c := range cases {
		m := githubRepoRe.FindStringSubmatch(c.url)
		if c.wantNoHit {
			if m != nil {
				t.Errorf("%q: expected no match, got %v", c.url, m)
			}
			continue
		}
		if m == nil {
			t.Fatalf("%q: expected a match, got none", c.url)
		}
		if m[1] != c.wantOwner || m[2] != c.wantRepo {
			t.Errorf("%q: got owner=%q repo=%q, want %q/%q", c.url, m[1], m[2], c.wantOwner, c.wantRepo)
		}
	}
}

func TestGitHubContextNeverEscalates(t *testing.T) {
	g := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"stargazers_count":99999,"created_at":"2015-01-01T00:00:00Z","pushed_at":"2026-07-01T00:00:00Z","archived":false}`))
	}))
	s := g.Context(context.Background(), "https://github.com/psf/requests")
	if s.Level != verdict.LevelInfo {
		t.Fatalf("repo-context must always be LevelInfo (advisory only), got %v", s.Level)
	}
	if s.Check != verdict.RuleRepoContext {
		t.Errorf("wrong check id: %s", s.Check)
	}
	if !strings.Contains(s.Message, "advisory only") {
		t.Errorf("message should self-label as advisory-only, got: %s", s.Message)
	}
	if !strings.Contains(s.Message, "psf/requests") {
		t.Errorf("message should identify the repo, got: %s", s.Message)
	}
}

func TestGitHubContextNoMatchIsQuiet(t *testing.T) {
	g := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not make a network call when the repo URL doesn't parse as github.com/<owner>/<repo>")
	}))
	s := g.Context(context.Background(), "https://gitlab.com/foo/bar")
	if s.Level != verdict.LevelInfo || s.Message != "" {
		t.Errorf("expected a silent Info signal, got level=%v message=%q", s.Level, s.Message)
	}
}

func TestGitHubContextFetchErrorIsQuiet(t *testing.T) {
	g := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	s := g.Context(context.Background(), "https://github.com/psf/requests")
	if s.Level != verdict.LevelInfo || s.Message != "" {
		t.Errorf("expected a silent Info signal on fetch failure, got level=%v message=%q", s.Level, s.Message)
	}
}
