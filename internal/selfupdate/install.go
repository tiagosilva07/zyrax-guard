package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
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
