package check

import (
	"github.com/tiagosilva07/invoke-guard/internal/ecosystem/npm"
	"github.com/tiagosilva07/invoke-guard/internal/httpx"
	"github.com/tiagosilva07/invoke-guard/internal/intel"
	"github.com/tiagosilva07/invoke-guard/internal/policy"
	"github.com/tiagosilva07/invoke-guard/internal/seam"
)

// NewNPM wires the default npm orchestrator: hardened HTTP client allowlisting the
// npm + OSV hosts, the npm provider with the bundled popular list, OSV intel, and
// the project-local policy.
func NewNPM(projectDir string, popular []string) (*Orchestrator, error) {
	client := httpx.New([]string{npm.RegistryHost, npm.DownloadsHost, intel.OSVHost})
	pol, err := policy.Load(projectDir)
	if err != nil {
		return nil, err
	}
	return &Orchestrator{
		Eco:    npm.New(client, popular),
		Intel:  intel.NewOSV(client),
		Policy: pol,
	}, nil
}

var _ seam.Policy = (*policy.Local)(nil)
