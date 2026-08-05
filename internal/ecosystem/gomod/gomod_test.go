package gomod

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
	"github.com/tiagosilva07/zyrax-guard/internal/seam"
	"slices"
)

func newTestProvider(t *testing.T, h http.Handler) *Provider {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	p := New(httpx.New([]string{host}), []string{"github.com/pkg/errors"})
	p.base = srv.URL
	return p
}

func TestValidateName(t *testing.T) {
	p := New(nil, nil)
	for _, ok := range []string{
		"github.com/pkg/errors",
		"golang.org/x/sync",
		"gopkg.in/yaml.v2",
		"k8s.io/client-go",
	} {
		if err := p.ValidateName(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"foo;rm -rf",
		"../evil",
		"requests",      // no domain-like first segment
		"UPPER.com/pkg", // uppercase rejected (see nameRe comment)
		"",
		"github.com/../evil",
		strings.Repeat("a.b/", 200),
	} {
		if err := p.ValidateName(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestExistsAndMetadata(t *testing.T) {
	p := newTestProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/github.com/pkg/errors/@latest"):
			w.Write([]byte(`{"Version":"v0.9.1","Time":"2020-01-14T00:00:00Z"}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	ctx := context.Background()
	ok, err := p.Exists(ctx, "github.com/pkg/errors", "")
	if err != nil || !ok {
		t.Fatalf("github.com/pkg/errors should exist: ok=%v err=%v", ok, err)
	}
	md, err := p.Metadata(ctx, "github.com/pkg/errors")
	if err != nil {
		t.Fatal(err)
	}
	if md.Latest != "v0.9.1" {
		t.Errorf("md.Latest = %q, want v0.9.1", md.Latest)
	}
	if md.LoadsKnown {
		t.Error("LoadsKnown must be false — the module proxy has no download-count endpoint")
	}
	if md.RepoURL != "https://github.com/pkg/errors" {
		t.Errorf("md.RepoURL = %q, want https://github.com/pkg/errors", md.RepoURL)
	}
	miss, _ := p.Exists(ctx, "example.com/definitely-not-real-xyz", "")
	if miss {
		t.Fatal("nonexistent module reported as existing")
	}
}

func TestMetadataNonGitHubHasNoRepoURL(t *testing.T) {
	p := newTestProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"v1.0.0","Time":"2020-01-01T00:00:00Z"}`))
	}))
	md, err := p.Metadata(context.Background(), "golang.org/x/sync")
	if err != nil {
		t.Fatal(err)
	}
	if md.RepoURL != "" {
		t.Errorf("RepoURL should be empty for a non-github.com module path, got %q", md.RepoURL)
	}
}

func TestExistsDistinguishesAbsentFromUndetermined(t *testing.T) {
	var status int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	defer srv.Close()
	host := srv.Listener.Addr().String()
	p := New(httpx.New([]string{host}), nil)
	p.base = "http://" + host

	status = 404
	if ok, err := p.Exists(context.Background(), "example.com/ghost", ""); ok || err != nil {
		t.Fatalf("404 should be (false,nil), got (%v,%v)", ok, err)
	}
	status = 503
	if ok, err := p.Exists(context.Background(), "example.com/ghost", ""); ok || err == nil {
		t.Fatalf("503 should be (false,error), got (%v,%v)", ok, err)
	}
	status = 200
	if ok, err := p.Exists(context.Background(), "example.com/real", ""); !ok || err != nil {
		t.Fatalf("200 should be (true,nil), got (%v,%v)", ok, err)
	}
}

func TestInstallCodeNeverFetches(t *testing.T) {
	// Go's module-fetch step never executes code, so InstallCode must return
	// empty without even contacting the proxy — a request here is a bug.
	called := false
	p := newTestProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	files, err := p.InstallCode(context.Background(), "github.com/pkg/errors", "v0.9.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("expected no files, got %v", files)
	}
	if called {
		t.Error("InstallCode must not contact the proxy")
	}
}

func TestInstallCodeValidatesName(t *testing.T) {
	p := New(httpx.New(nil), nil)
	if _, err := p.InstallCode(context.Background(), "../evil", ""); err == nil {
		t.Error("illegal module path must be rejected")
	}
}

func TestInstallArgsPinsVettedVersion(t *testing.T) {
	p := New(nil, nil)
	args, err := p.installArgs([]seam.InstallRef{
		{Name: "github.com/pkg/errors", Version: "v0.9.1"},
		{Name: "golang.org/x/sync"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"get", "github.com/pkg/errors@v0.9.1", "golang.org/x/sync"}
	if !slices.Equal(args, want) {
		t.Errorf("args = %v, want %v", args, want)
	}
	if _, err := p.installArgs([]seam.InstallRef{{Name: "x.io/y", Version: "--evil"}}); err == nil {
		t.Error("flag-shaped version must be rejected before exec")
	}
	if _, err := p.installArgs([]seam.InstallRef{{Name: "not a name!"}}); err == nil {
		t.Error("illegal name must be rejected before exec")
	}
}

func TestInstallArgsRejectsUppercaseVersion(t *testing.T) {
	p := New(nil, nil)
	if _, err := p.installArgs([]seam.InstallRef{{Name: "x.io/y", Version: "v1.0.0-RC1"}}); err == nil {
		t.Error("uppercase version must be rejected (proxy-escaping not implemented)")
	}
}
