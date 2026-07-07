package seam_test

import (
	"context"
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/seam"
)

type fakeEco struct{}

func (fakeEco) Name() string                                                       { return "npm" }
func (fakeEco) ValidateName(string) error                                          { return nil }
func (fakeEco) Exists(context.Context, string, string) (bool, error)               { return true, nil }
func (fakeEco) Metadata(context.Context, string) (seam.Metadata, error)            { return seam.Metadata{}, nil }
func (fakeEco) PopularList() []string                                              { return []string{"request"} }
func (fakeEco) Install(context.Context, []seam.InstallRef, seam.InstallOpts) error { return nil }
func (fakeEco) InstallCode(context.Context, string, string) (map[string]string, error) {
	return map[string]string{}, nil
}

func TestEcosystemSatisfiable(t *testing.T) {
	var _ seam.Ecosystem = fakeEco{} // compile-time assertion
}

func TestValidateVersion(t *testing.T) {
	valid := []string{"", "1.0.0", "4.17.20", "0.0.1-security", "1.0.0+build.5", "2024.1", "v1.2.3"}
	for _, v := range valid {
		if err := seam.ValidateVersion(v); err != nil {
			t.Errorf("ValidateVersion(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{"--ignore-scripts", "-1.0", "1.0.0 && rm -rf /", "1.0\n2.0", "ver$ion"}
	for _, v := range invalid {
		if err := seam.ValidateVersion(v); err == nil {
			t.Errorf("ValidateVersion(%q) = nil, want error — must never reach an exec arg", v)
		}
	}
}
