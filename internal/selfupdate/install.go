package selfupdate

import (
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
