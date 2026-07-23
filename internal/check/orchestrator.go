package check

import (
	"context"

	"github.com/tiagosilva07/zyrax-guard/internal/seam"
	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

// Orchestrator runs all package-level checks for one package and applies policy.
type Orchestrator struct {
	Eco    seam.Ecosystem
	Intel  seam.ThreatIntel
	Policy seam.Policy
	GitHub *GitHubClient // optional; nil skips the repo-context signal
}

// Check vets one package end-to-end and returns the verdict Result. Policy
// allow/deny short-circuits (with an explanatory signal) before the checks run.
func (o *Orchestrator) Check(ctx context.Context, name, version string) verdict.Result {
	return o.CheckWith(ctx, name, version, false)
}

// CheckWith vets a package; when deep, it also downloads the artifact and runs the
// install-script analyzer (best-effort: a fetch error is an Info signal, not a BLOCK).
func (o *Orchestrator) CheckWith(ctx context.Context, name, version string, deep bool) verdict.Result {
	switch o.Policy.Decide(name) {
	case seam.ForceAllow:
		return verdict.Decide(o.Eco.Name(), name, version, []verdict.Signal{
			{Check: "policy-allow", Level: verdict.LevelInfo, Message: "explicitly allowed by local policy"},
		})
	case seam.ForceDeny:
		return verdict.Decide(o.Eco.Name(), name, version, []verdict.Signal{
			{Check: "policy-deny", Level: verdict.LevelBlock, Message: "explicitly denied by local policy"},
		})
	}

	var signals []verdict.Signal
	exists, err := o.Eco.Exists(ctx, name, version)
	if err != nil {
		return verdict.Decide(o.Eco.Name(), name, version, []verdict.Signal{
			{Check: verdict.RuleCheckError, Level: verdict.LevelError, Message: "could not reach the registry to verify this package: " + err.Error()},
		})
	}
	signals = append(signals, Existence(exists))
	if !exists {
		return verdict.Decide(o.Eco.Name(), name, version, signals)
	}
	md, mdErr := o.Eco.Metadata(ctx, name)
	if version == "" {
		version = md.Latest // check the version a bare install would actually pull
	}
	switch {
	case mdErr != nil:
		// Fail closed like the other registry paths — but keep going so the
		// denylist/OSV lookup can still escalate to BLOCK.
		signals = append(signals, verdict.Signal{Check: verdict.RuleCheckError, Level: verdict.LevelError, Message: "could not fetch registry metadata: " + mdErr.Error()})
	case !md.LoadsKnown:
		// The stats endpoint failed: WeeklyLoads is unknown, not zero. Running
		// typosquat/popularity would manufacture "0 weekly downloads" evidence
		// and false-BLOCK legitimate packages, so skip them — visibly.
		signals = append(signals, verdict.Signal{Check: verdict.RuleCheckError, Level: verdict.LevelInfo, Message: "download statistics unavailable — typosquat and popularity checks skipped"})
	default:
		signals = append(signals, Typosquat(name, md.WeeklyLoads, o.Eco.PopularList()))
		signals = append(signals, Popularity(md))
	}
	advs, lookupErr := o.Intel.Lookup(ctx, o.Eco.Name(), name, version)
	if len(advs) > 0 {
		signals = append(signals, KnownBad(advs)) // denylist/OSV hits (BLOCK dominates ERROR)
	}
	if lookupErr != nil {
		signals = append(signals, verdict.Signal{Check: verdict.RuleCheckError, Level: verdict.LevelError, Message: "could not verify against the malware database: " + lookupErr.Error()})
	} else if len(advs) == 0 {
		signals = append(signals, KnownBad(advs)) // explicit "no known advisories" info when OSV succeeded clean
	}
	if deep {
		if files, err := o.Eco.InstallCode(ctx, name, version); err != nil {
			signals = append(signals, verdict.Signal{Check: verdict.RuleSuspiciousInstall, Level: verdict.LevelInfo, Message: "could not fetch artifact for deep analysis: " + err.Error()})
		} else {
			signals = append(signals, AnalyzeInstallScripts(o.Eco.Name(), files))
		}
		// Advisory-only context, never wired into the verdict — see the design
		// note on GitHubClient.Context for why reputation must not suppress a
		// behavioral finding.
		if o.GitHub != nil && md.RepoURL != "" {
			signals = append(signals, o.GitHub.Context(ctx, md.RepoURL))
		}
	}
	return verdict.Decide(o.Eco.Name(), name, version, signals)
}
