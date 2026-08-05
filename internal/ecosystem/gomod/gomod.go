// Package gomod implements seam.Ecosystem for the public Go module proxy
// (proxy.golang.org). All registry access is read-only metadata via the proxy
// protocol (https://go.dev/ref/mod#goproxy-protocol); installs use an
// argument-array exec (never a shell string) so a hostile module path can
// never inject a command.
package gomod

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
	"github.com/tiagosilva07/zyrax-guard/internal/seam"
)

// Host is the standard, publicly-run Go module proxy. No auth, no client
// library — the proxy protocol is a handful of plain GETs over stdlib net/http.
const Host = "proxy.golang.org"

const maxNameLen = 512

// nameRe matches the real-world shape of a published Go module path: a
// domain-like first segment (containing a dot, e.g. "github.com", "golang.org",
// "gopkg.in") followed by lowercase path segments. Go module paths CAN contain
// uppercase letters (the proxy protocol escapes them as "!<lower>"), but every
// module worth vetting in practice uses an all-lowercase path — restricting to
// lowercase here means we never have to implement that escaping, and it stays
// conservative in the same spirit as the npm/PyPI/crates name grammars: reject
// anything unexpected before it reaches a URL or an exec arg.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*\.[a-z0-9][a-z0-9.-]*(/[a-z0-9][a-z0-9._-]*)*$`)

// safeVersion gates a version before it goes into a proxy URL path. Real Go
// versions ("v1.2.3", "v0.0.0-20210101000000-abcdef123456", "v2.0.0+incompatible")
// are lowercase; anything else (notably '/' or uppercase, which the proxy would
// otherwise expect escaped) is rejected so it cannot inject path segments.
var safeVersion = regexp.MustCompile(`^[0-9a-z][0-9a-z.+_-]*$`)

type Provider struct {
	http    *httpx.Client
	popular []string
	base    string
}

func New(client *httpx.Client, popular []string) *Provider {
	return &Provider{http: client, popular: popular, base: "https://" + Host}
}

func (p *Provider) Name() string          { return "gomod" }
func (p *Provider) PopularList() []string { return p.popular }

// ValidateName enforces the module-path grammar and a length bound.
func (p *Provider) ValidateName(name string) error {
	if len(name) == 0 || len(name) > maxNameLen {
		return fmt.Errorf("invalid Go module path length")
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("%q is not a legal Go module path", name)
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("%q is not a legal Go module path", name)
	}
	return nil
}

// Exists queries the proxy's @latest endpoint, which resolves for any module
// with at least one fetchable commit (tagged or not) and 404s for a module
// path with no such module. version is ignored — like the other ecosystems,
// existence is about the module path, not a specific release.
func (p *Provider) Exists(ctx context.Context, name, _ string) (bool, error) {
	if err := p.ValidateName(name); err != nil {
		return false, err
	}
	code, err := p.http.GetJSON(ctx, p.base+"/"+name+"/@latest", nil)
	if err != nil {
		return false, err
	}
	return httpx.ExistsFromStatus(code)
}

type latestJSON struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// Metadata fetches the module's latest version info. Unlike npm/PyPI/crates.io,
// the module proxy protocol has no download-count or maintainer field, so
// WeeklyLoads stays 0 and LoadsKnown stays false — the orchestrator already
// treats LoadsKnown=false as "stats unavailable" and skips typosquat/popularity
// rather than fabricate "0 downloads" evidence against a real module.
func (p *Provider) Metadata(ctx context.Context, name string) (seam.Metadata, error) {
	if err := p.ValidateName(name); err != nil {
		return seam.Metadata{}, err
	}
	var lj latestJSON
	code, err := p.http.GetJSON(ctx, p.base+"/"+name+"/@latest", &lj)
	if err != nil {
		return seam.Metadata{}, err
	}
	if code != 200 {
		return seam.Metadata{Exists: false}, nil
	}
	return seam.Metadata{
		Exists:    true,
		Latest:    lj.Version,
		Published: lj.Time,
		RepoURL:   repoURLFromPath(name),
	}, nil
}

// repoURLFromPath derives a repo URL for the common case where the module path
// itself IS the repo location (github.com/<owner>/<repo>[/...]) — the proxy
// protocol carries no separate repository field the way npm/PyPI registries do.
func repoURLFromPath(modPath string) string {
	parts := strings.SplitN(modPath, "/", 4)
	if len(parts) < 3 || parts[0] != "github.com" {
		return ""
	}
	return "https://github.com/" + parts[1] + "/" + parts[2]
}

// InstallCode always returns empty: unlike npm postinstall scripts, PyPI's
// setup.py, or crates' build.rs, fetching a Go module (`go mod download` /
// `go get`) never executes any code from it — there is no install-time hook to
// statically analyze. Returning empty immediately (rather than downloading and
// discarding the module zip) avoids a wasted network round-trip under --deep.
func (p *Provider) InstallCode(ctx context.Context, name, version string) (map[string]string, error) {
	if err := p.ValidateName(name); err != nil {
		return nil, err
	}
	return map[string]string{}, nil
}

// installArgs builds the `go get` argument array. Names and versions are
// re-validated here as defense in depth — they never touch a shell, and a
// pinned version adds exactly the version that was vetted.
func (p *Provider) installArgs(pkgs []seam.InstallRef) ([]string, error) {
	args := []string{"get"}
	for _, pkg := range pkgs {
		if err := p.ValidateName(pkg.Name); err != nil {
			return nil, err
		}
		if err := seam.ValidateVersion(pkg.Version); err != nil {
			return nil, err
		}
		if pkg.Version != "" && !safeVersion.MatchString(pkg.Version) {
			return nil, fmt.Errorf("invalid Go module version %q", pkg.Version)
		}
		spec := pkg.Name
		if pkg.Version != "" {
			spec += "@" + pkg.Version
		}
		args = append(args, spec)
	}
	return args, nil
}

// Install runs `go get <pkgs>` (the add-a-dependency analog) with array args.
// IgnoreScripts has no `go get` equivalent (module fetch runs no code) and is
// ignored, like pip.
func (p *Provider) Install(ctx context.Context, pkgs []seam.InstallRef, _ seam.InstallOpts) error {
	args, err := p.installArgs(pkgs)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Stdout, cmd.Stderr = stdout(), stderr()
	return cmd.Run()
}
