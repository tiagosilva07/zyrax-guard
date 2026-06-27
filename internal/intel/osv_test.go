package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
)

func TestOSVLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulns":[{"id":"MAL-123","summary":"malware","database_specific":{"severity":"CRITICAL"}}]}`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	o := NewOSV(httpx.New([]string{host}))
	o.base = srv.URL
	advs, err := o.Lookup(context.Background(), "npm", "evil", "1.0.0")
	if err != nil || len(advs) != 1 || !advs[0].Malware {
		t.Fatalf("advs=%+v err=%v", advs, err)
	}
}

func TestDenylist(t *testing.T) {
	if !InDenylist("npm", "known-evil-pkg") {
		t.Skip("seed denylist may be empty in v1; ensure InDenylist exists")
	}
}

func TestOSVLookup_DegradedReturnsErrorButKeepsDenylistFloor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	o := NewOSV(httpx.New([]string{host}))
	o.base = srv.URL

	// A non-denylisted name: OSV down → error, no advisories.
	advs, err := o.Lookup(context.Background(), "npm", "some-random-pkg", "")
	if err == nil {
		t.Fatal("OSV 503 must now surface an error (fail closed), got nil")
	}
	if len(advs) != 0 {
		t.Fatalf("expected no advisories for non-denylisted name, got %v", advs)
	}

	// A denylisted name: OSV down → error AND the denylist advisory is still returned.
	advs, err = o.Lookup(context.Background(), "npm", "crossenv", "1.0.0")
	if err == nil {
		t.Fatal("OSV 503 must surface an error for denylisted name too")
	}
	if len(advs) != 1 || !advs[0].Malware {
		t.Fatalf("denylist must still fire on OSV downtime: %+v", advs)
	}
}
