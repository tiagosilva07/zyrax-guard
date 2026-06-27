// Package httpx is a hardened read-only HTTP/JSON client: it only talks to an
// allowlist of registry hosts, never follows redirects to other hosts, and always
// times out. This is the SSRF guard for the whole tool.
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UserAgent identifies Guard to registries (crates.io rejects requests without one).
const UserAgent = "zyrax-guard (+https://github.com/tiagosilva07/zyrax-guard)"

type Client struct {
	allowed     map[string]bool
	hc          *http.Client
	maxAttempts int           // total tries (1 = no retry); default 3
	retryBase   time.Duration // base backoff; default 250ms
}

// New builds a client that will only contact hosts in allow (host or host:port).
func New(allow []string) *Client {
	m := make(map[string]bool, len(allow))
	for _, h := range allow {
		m[h] = true
	}
	c := &Client{allowed: m}
	c.hc = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !c.hostAllowed(req.URL) {
				return fmt.Errorf("redirect to disallowed host %q blocked", req.URL.Host)
			}
			return nil
		},
	}
	c.maxAttempts = 3
	c.retryBase = 250 * time.Millisecond
	return c
}

const maxBackoff = 5 * time.Second

var retryableStatus = map[int]bool{429: true, 500: true, 502: true, 503: true, 504: true}

// do executes req with bounded retries on transient failures (transport error or a
// retryable status). bodyBytes, when non-nil, rebuilds the single-use request body on
// each attempt. Backoff honors Retry-After (capped) and respects ctx cancellation.
func (c *Client) do(req *http.Request, bodyBytes []byte) (*http.Response, error) {
	attempts := c.maxAttempts
	if attempts < 1 {
		attempts = 1
	}
	var resp *http.Response
	var err error
	for i := 0; i < attempts; i++ {
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
		}
		resp, err = c.hc.Do(req)
		if err == nil && !retryableStatus[resp.StatusCode] {
			return resp, nil // success or a non-retryable status (e.g. 200/404/403)
		}
		if i == attempts-1 {
			return resp, err // out of attempts: return whatever we have
		}
		d := backoffDelay(c.retryBase, i, resp)
		if resp != nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			resp.Body.Close()
		}
		select {
		case <-time.After(d):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	return resp, err
}

// backoffDelay returns the wait before the next attempt: Retry-After (seconds, capped)
// if the server sent one, else exponential base<<attempt, capped at maxBackoff.
func backoffDelay(base time.Duration, attempt int, resp *http.Response) time.Duration {
	if resp != nil {
		if ra := strings.TrimSpace(resp.Header.Get("Retry-After")); ra != "" {
			if secs, e := strconv.Atoi(ra); e == nil && secs >= 0 {
				d := time.Duration(secs) * time.Second
				if d > maxBackoff {
					d = maxBackoff
				}
				return d
			}
		}
	}
	d := base << attempt
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

func (c *Client) hostAllowed(u *url.URL) bool {
	return c.allowed[u.Host] || c.allowed[u.Hostname()]
}

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

func schemeOK(u *url.URL) error {
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil // permit plaintext only to loopback (test servers)
	}
	return fmt.Errorf("only HTTPS is allowed (got scheme %q for host %q)", u.Scheme, u.Host)
}

// GetJSON GETs url and, on 200, decodes the body into out (may be nil to skip).
// Returns the HTTP status code. A non-2xx is not an error (callers branch on code);
// transport/SSRF problems are errors.
func (c *Client) GetJSON(ctx context.Context, rawurl string, out any) (int, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return 0, err
	}
	if err := schemeOK(u); err != nil {
		return 0, err
	}
	if !c.hostAllowed(u) {
		return 0, fmt.Errorf("host %q not in allowlist (SSRF guard)", u.Host)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.do(req, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return resp.StatusCode, nil
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// GetBytes downloads url's body (host-allowlisted, following allowed redirects)
// up to maxBytes; a body exceeding maxBytes is an error (tar-bomb / abuse guard).
func (c *Client) GetBytes(ctx context.Context, rawurl string, maxBytes int64) (int, []byte, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return 0, nil, err
	}
	if err := schemeOK(u); err != nil {
		return 0, nil, err
	}
	if !c.hostAllowed(u) {
		return 0, nil, fmt.Errorf("host %q not in allowlist (SSRF guard)", u.Host)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.do(req, nil)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if int64(len(b)) > maxBytes {
		return resp.StatusCode, nil, fmt.Errorf("response exceeds %d bytes", maxBytes)
	}
	return resp.StatusCode, b, nil
}

// ExistsFromStatus maps a registry GET status to package-existence semantics:
// 200 → exists, 404 → definitively absent, anything else (5xx/429/403/…) → an
// error, because the registry did not give us a determinate answer. Callers that
// cannot determine existence must fail closed rather than treat it as "absent".
func ExistsFromStatus(code int) (bool, error) {
	switch code {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("registry returned status %d (could not determine existence)", code)
	}
}

// PostJSON sends an already-built POST request, enforcing the same host allowlist,
// and returns the status code + raw body (capped). For the few APIs (OSV) that
// require POST. Body must already be set on req.
func (c *Client) PostJSON(req *http.Request) (int, []byte, error) {
	if err := schemeOK(req.URL); err != nil {
		return 0, nil, err
	}
	if !c.hostAllowed(req.URL) {
		return 0, nil, fmt.Errorf("host %q not in allowlist (SSRF guard)", req.URL.Host)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UserAgent)
	}
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}
	resp, err := c.do(req, bodyBytes)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, raw, nil
}
