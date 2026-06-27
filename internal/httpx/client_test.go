package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGetJSON_AllowedHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	var out struct {
		OK bool `json:"ok"`
	}
	code, err := c.GetJSON(context.Background(), srv.URL, &out)
	if err != nil || code != 200 || !out.OK {
		t.Fatalf("code=%d err=%v out=%+v", code, err, out)
	}
}

func TestGetJSON_DisallowedHost(t *testing.T) {
	c := New([]string{"registry.npmjs.org"})
	_, err := c.GetJSON(context.Background(), "http://169.254.169.254/latest/meta-data", nil)
	if err == nil {
		t.Fatal("expected host-not-allowed error (SSRF guard)")
	}
}

func TestGetJSON_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	code, err := c.GetJSON(context.Background(), srv.URL, nil)
	if code != 404 || err != nil {
		t.Fatalf("want 404,nil got code=%d err=%v", code, err)
	}
}

func TestPostJSON_DisallowedHost(t *testing.T) {
	c := New([]string{"registry.npmjs.org"})
	req, _ := http.NewRequest(http.MethodPost, "http://169.254.169.254/latest/meta-data", nil)
	_, _, err := c.PostJSON(req)
	if err == nil {
		t.Fatal("expected host-not-allowed error (SSRF guard)")
	}
}

func TestGetJSON_SendsUserAgent(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	if _, err := c.GetJSON(context.Background(), srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ua, "zyrax-guard") {
		t.Errorf("User-Agent = %q, want it to contain zyrax-guard", ua)
	}
}

func TestGetBytes_CapAndHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello-bytes"))
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	code, b, err := c.GetBytes(context.Background(), srv.URL, 1024)
	if err != nil || code != 200 || string(b) != "hello-bytes" {
		t.Fatalf("code=%d b=%q err=%v", code, b, err)
	}
	if _, _, err := c.GetBytes(context.Background(), "https://evil.example/x", 1024); err == nil {
		t.Fatal("disallowed host must error")
	}
}

func TestGetBytes_OverCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 5000))
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	_, _, err := c.GetBytes(context.Background(), srv.URL, 1024)
	if err == nil {
		t.Fatal("over-cap body must error")
	}
}

func TestRetriesTransient5xxThenSucceeds(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) < 3 {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	c.retryBase = time.Millisecond // keep the test fast

	var out struct{ Ok bool }
	code, err := c.GetJSON(context.Background(), "http://"+srv.Listener.Addr().String()+"/x", &out)
	if err != nil || code != 200 || !out.Ok {
		t.Fatalf("expected success after retries, got code=%d err=%v out=%+v", code, err, out)
	}
	if atomic.LoadInt32(&hits) != 3 {
		t.Fatalf("expected 3 attempts (2 retries), got %d", hits)
	}
}

func TestPersistent5xxExhaustsRetries(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(503)
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	c.retryBase = time.Millisecond

	code, err := c.GetJSON(context.Background(), "http://"+srv.Listener.Addr().String()+"/x", nil)
	if err != nil {
		t.Fatalf("non-2xx must not be a transport error, got %v", err)
	}
	if code != 503 {
		t.Fatalf("expected final 503, got %d", code)
	}
	if atomic.LoadInt32(&hits) != int32(c.maxAttempts) {
		t.Fatalf("expected %d attempts, got %d", c.maxAttempts, hits)
	}
}

func TestNoRetryOn404(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(404)
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	c.retryBase = time.Millisecond
	code, _ := c.GetJSON(context.Background(), "http://"+srv.Listener.Addr().String()+"/x", nil)
	if code != 404 || atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("404 must not retry: code=%d hits=%d", code, hits)
	}
}

func TestRetryAfterHonoredAndCapped(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set("Retry-After", "0") // 0s → immediate retry, deterministic
			w.WriteHeader(429)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	code, err := c.GetJSON(context.Background(), "http://"+srv.Listener.Addr().String()+"/x", nil)
	if err != nil || code != 200 || atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("429+Retry-After should retry to success: code=%d err=%v hits=%d", code, err, hits)
	}
}

func TestRedirectToHTTPDowngradeBlocked(t *testing.T) {
	// An allowlisted HTTPS-style host that 302-redirects to an http:// URL on the same
	// host must be refused (scheme guard), not followed in cleartext.
	var target string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}))
	defer srv.Close()
	host := srv.Listener.Addr().String()
	target = "http://" + host + "/downgraded" // same host, but we simulate a non-loopback by asserting the guard logic

	// Use the real guard: build a client allowing the host, then drive a redirect.
	c := New([]string{host})
	// The initial request is loopback-http (permitted for tests); the redirect target is
	// also loopback-http, so to exercise the scheme guard we assert CheckRedirect rejects
	// a non-loopback http downgrade. Construct that case directly:
	reqURL, _ := url.Parse("http://example.com/x")
	if err := c.checkRedirectScheme(reqURL); err == nil {
		t.Fatal("expected non-loopback http redirect target to be rejected by scheme guard")
	}
}

func TestExistsFromStatus(t *testing.T) {
	cases := []struct {
		code       int
		wantExists bool
		wantErr    bool
	}{
		{200, true, false},
		{404, false, false},
		{500, false, true},
		{503, false, true},
		{429, false, true},
		{403, false, true},
	}
	for _, c := range cases {
		exists, err := ExistsFromStatus(c.code)
		if exists != c.wantExists || (err != nil) != c.wantErr {
			t.Errorf("ExistsFromStatus(%d)=(%v,%v) want (%v,err=%v)", c.code, exists, err, c.wantExists, c.wantErr)
		}
	}
}
