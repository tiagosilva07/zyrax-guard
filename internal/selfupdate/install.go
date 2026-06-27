package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
)

// Method is how Guard was installed, which dictates how to upgrade it.
type Method string

const (
	MethodNPM    Method = "npm"
	MethodBrew   Method = "brew"
	MethodGo     Method = "go"
	MethodBinary Method = "binary"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// verifySHA256 confirms data's SHA-256 matches the entry for filename in a
// checksums.txt body ("<hex>  <filename>" per line). Missing filename or mismatch
// is an error — the caller must abort before replacing the binary.
func verifySHA256(data []byte, checksums, filename string) error {
	want := ""
	for _, line := range strings.Split(checksums, "\n") {
		line = strings.TrimRight(line, "\r") // tolerate CRLF-terminated checksums.txt
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == filename {
			want = strings.ToLower(f[0])
			break
		}
	}
	if want == "" {
		return fmt.Errorf("no checksum for %q", filename)
	}
	if got := sha256Hex(data); got != want {
		return fmt.Errorf("checksum mismatch for %q: got %s want %s", filename, got, want)
	}
	return nil
}

// DetectInstall guesses the install method from the resolved executable path.
// gobin is $GOPATH/bin or $HOME/go/bin (pass "" to skip the go heuristic).
func DetectInstall(execPath, gobin string) Method {
	p := filepath.ToSlash(execPath)
	switch {
	case strings.Contains(p, "/node_modules/"):
		return MethodNPM
	case strings.Contains(p, "/Cellar/"):
		return MethodBrew
	case gobin != "" && strings.HasPrefix(p, filepath.ToSlash(gobin)+"/"):
		return MethodGo
	default:
		return MethodBinary
	}
}

// Downloader fetches a release asset and the checksums.txt body for a version.
type Downloader func(ctx context.Context, version, asset string) (assetBytes []byte, checksums string, err error)

// UpgradeOptions configures Upgrade. Production callers fill these from runtime values.
type UpgradeOptions struct {
	Current  string
	Method   Method
	ExecPath string
	Fetch    Fetcher
	Download Downloader                              // defaults to the GitHub-release downloader
	Runner   func(name string, args ...string) error // defaults to exec; injectable for tests
}

func assetName(goos, goarch string) string {
	n := "zyrax-guard-" + goos + "-" + goarch
	if goos == "windows" {
		n += ".exe"
	}
	return n
}

// Upgrade performs the upgrade appropriate to opts.Method, writing progress to w.
func Upgrade(w io.Writer, opts UpgradeOptions) error {
	if opts.Fetch == nil {
		opts.Fetch = npmFetcher(httpx.New([]string{"registry.npmjs.org"}), NPMRegistryURL)
	}
	if opts.Runner == nil {
		opts.Runner = func(name string, args ...string) error {
			cmd := exec.Command(name, args...)
			cmd.Stdout, cmd.Stderr = w, w
			return cmd.Run()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	latest, err := opts.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("resolve latest version: %w", err)
	}
	if compareSemver(latest, opts.Current) <= 0 {
		fmt.Fprintf(w, "already up to date (%s)\n", opts.Current)
		return nil
	}

	switch opts.Method {
	case MethodNPM:
		fmt.Fprintln(w, "upgrading via npm…")
		return opts.Runner("npm", "install", "-g", "zyrax-guard@latest")
	case MethodBrew:
		fmt.Fprintln(w, "upgrading via Homebrew…")
		return opts.Runner("brew", "upgrade", "zyrax-guard")
	case MethodGo:
		fmt.Fprintln(w, "upgrading via go install…")
		return opts.Runner("go", "install", "github.com/tiagosilva07/zyrax-guard/cmd/zyrax-guard@latest")
	case MethodBinary:
		if runtime.GOOS == "windows" {
			fmt.Fprintf(w, "automatic upgrade is not supported for the standalone Windows binary yet.\n"+
				"Download zyrax-guard %s from https://github.com/tiagosilva07/zyrax-guard/releases\n", latest)
			return fmt.Errorf("manual upgrade needed on windows")
		}
		return upgradeBinary(ctx, w, opts, latest)
	default:
		return fmt.Errorf("unknown install method %q", opts.Method)
	}
}

func upgradeBinary(ctx context.Context, w io.Writer, opts UpgradeOptions, latest string) error {
	if opts.Download == nil {
		opts.Download = githubDownloader(httpx.New([]string{"github.com", "objects.githubusercontent.com"}))
	}
	asset := assetName(runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(w, "downloading %s %s…\n", asset, latest)
	data, checksums, err := opts.Download(ctx, latest, asset)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if err := verifySHA256(data, checksums, asset); err != nil {
		return fmt.Errorf("verification failed (binary NOT replaced): %w", err)
	}
	fmt.Fprintln(w, "checksum OK; replacing binary…")
	if err := selfReplace(opts.ExecPath, data); err != nil {
		return fmt.Errorf("replace: %w", err)
	}
	fmt.Fprintf(w, "upgraded to %s\n", latest)
	return nil
}

// selfReplace atomically swaps the file at path with newData. It writes a temp file in
// the same directory (so os.Rename stays on one filesystem) and renames over path. On
// Unix this works even while the old binary is executing.
func selfReplace(path string, newData []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".zyrax-guard-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if _, err := tmp.Write(newData); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// githubDownloader builds a Downloader that fetches the asset and checksums.txt from
// the GitHub release for version (tag "v<version>").
func githubDownloader(c *httpx.Client) Downloader {
	return githubDownloaderBase(c, "https://github.com/tiagosilva07/zyrax-guard/releases/download/")
}

// githubDownloaderBase is the testable core of githubDownloader. repoBase is the
// URL prefix before the version segment, e.g.
// "https://github.com/.../releases/download/" — the downloader appends "v<version>/".
func githubDownloaderBase(c *httpx.Client, repoBase string) Downloader {
	return func(ctx context.Context, version, asset string) ([]byte, string, error) {
		base := repoBase + "v" + version + "/"
		code, assetBytes, err := c.GetBytes(ctx, base+asset, 64<<20)
		if err != nil {
			return nil, "", err
		}
		if code != 200 {
			return nil, "", fmt.Errorf("download %s: HTTP %d", asset, code)
		}
		code, sums, err := c.GetBytes(ctx, base+"checksums.txt", 1<<20)
		if err != nil {
			return nil, "", err
		}
		if code != 200 {
			return nil, "", fmt.Errorf("download checksums.txt: HTTP %d", code)
		}
		return assetBytes, string(sums), nil
	}
}
