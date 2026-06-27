package selfupdate

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
)

// TestGithubDownloaderBase_404Asset checks that a 404 on the asset file produces a
// clear error that mentions the HTTP status code, rather than a confusing
// "no checksum for ..." message that would appear if the nil body silently fell
// through to verifySHA256.
func TestGithubDownloaderBase_404Asset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	host := srv.Listener.Addr().String() // "127.0.0.1:PORT"
	c := httpx.New([]string{host})
	dl := githubDownloaderBase(c, srv.URL+"/releases/download/")

	_, _, err := dl(context.Background(), "1.2.3", "zyrax-guard-linux-amd64")
	if err == nil {
		t.Fatal("expected error for 404 response, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected error to mention HTTP 404, got: %v", err)
	}
}

// TestGithubDownloaderBase_404Checksums checks that a 404 on checksums.txt (asset
// found but checksums not yet uploaded) produces a clear error mentioning HTTP 404.
func TestGithubDownloaderBase_404Checksums(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "checksums.txt") {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "asset-content")
	}))
	defer srv.Close()

	host := srv.Listener.Addr().String()
	c := httpx.New([]string{host})
	dl := githubDownloaderBase(c, srv.URL+"/releases/download/")

	_, _, err := dl(context.Background(), "1.2.3", "zyrax-guard-linux-amd64")
	if err == nil {
		t.Fatal("expected error for 404 checksums.txt, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected error to mention HTTP 404, got: %v", err)
	}
}
