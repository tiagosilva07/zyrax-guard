package selfupdate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
)

func TestNPMFetcherParsesVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"name":"zyrax-guard","version":"0.8.2"}`))
	}))
	defer srv.Close()

	host := srv.Listener.Addr().String()
	f := npmFetcher(httpx.New([]string{host}), "http://"+host+"/zyrax-guard/latest")
	got, err := f(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got != "0.8.2" {
		t.Fatalf("got %q want 0.8.2", got)
	}
}
