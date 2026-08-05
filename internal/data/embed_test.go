package data

import "testing"

func TestPopularNPMNonEmpty(t *testing.T) {
	if len(PopularNPM()) < 10 {
		t.Fatalf("expected a seed popular list, got %d", len(PopularNPM()))
	}
}

func TestPopularPyPIAndCratesNonEmpty(t *testing.T) {
	if len(PopularPyPI()) < 10 {
		t.Errorf("pypi list too small: %d", len(PopularPyPI()))
	}
	if len(PopularCrates()) < 10 {
		t.Errorf("crates list too small: %d", len(PopularCrates()))
	}
}

func TestPopularGoModulesNonEmpty(t *testing.T) {
	if len(PopularGoModules()) < 10 {
		t.Errorf("gomod list too small: %d", len(PopularGoModules()))
	}
}

func TestDenylistEmbedNonEmpty(t *testing.T) {
	d := Denylist()
	if len(d["npm"]) == 0 {
		t.Fatal("embedded denylist must contain the npm seed entries")
	}
}
