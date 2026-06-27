package selfupdate

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAssetName(t *testing.T) {
	got := assetName("linux", "amd64")
	if got != "zyrax-guard-linux-amd64" {
		t.Fatalf("got %q", got)
	}
	if assetName("windows", "amd64") != "zyrax-guard-windows-amd64.exe" {
		t.Fatalf("windows asset must end in .exe")
	}
}

func TestSelfReplaceUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("self-replace is Unix-only this version")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "zyrax-guard")
	if err := os.WriteFile(target, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := selfReplace(target, []byte("NEWBINARY")); err != nil {
		t.Fatalf("selfReplace: %v", err)
	}
	b, _ := os.ReadFile(target)
	if string(b) != "NEWBINARY" {
		t.Fatalf("target not replaced, got %q", b)
	}
	fi, _ := os.Stat(target)
	if fi.Mode().Perm()&0o100 == 0 {
		t.Fatalf("replaced binary not executable: %v", fi.Mode())
	}
}

func TestUpgradeAbortsWhenCosignFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("self-replace is Unix-only")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "zyrax-guard")
	os.WriteFile(target, []byte("OLD"), 0o755)
	asset := assetName(runtime.GOOS, runtime.GOARCH)

	opts := UpgradeOptions{
		Current: "0.8.0", Method: MethodBinary, ExecPath: target,
		Fetch: func(context.Context) (string, error) { return "0.9.0", nil },
		Download: func(_ context.Context, _, _ string) ([]byte, string, error) {
			data := []byte("NEWBINARY")
			return data, sha256Hex(data) + "  " + asset, nil // checksum matches
		},
		CosignVerify: func(context.Context, string, string, []byte) error {
			return errors.New("signature mismatch")
		},
	}
	if err := Upgrade(io.Discard, opts); err == nil {
		t.Fatal("cosign failure must abort the upgrade")
	}
	if b, _ := os.ReadFile(target); string(b) != "OLD" {
		t.Fatalf("binary must be untouched on cosign failure, got %q", b)
	}
}

func TestUpgradeProceedsWhenCosignPasses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("self-replace is Unix-only")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "zyrax-guard")
	os.WriteFile(target, []byte("OLD"), 0o755)
	asset := assetName(runtime.GOOS, runtime.GOARCH)
	data := []byte("NEWBINARY")
	opts := UpgradeOptions{
		Current: "0.8.0", Method: MethodBinary, ExecPath: target,
		Fetch: func(context.Context) (string, error) { return "0.9.0", nil },
		Download: func(_ context.Context, _, _ string) ([]byte, string, error) {
			return data, sha256Hex(data) + "  " + asset, nil
		},
		CosignVerify: func(context.Context, string, string, []byte) error { return nil },
	}
	if err := Upgrade(io.Discard, opts); err != nil {
		t.Fatalf("upgrade should succeed when cosign passes: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "NEWBINARY" {
		t.Fatalf("binary should be replaced, got %q", b)
	}
}

func TestUpgradeBinaryVerifiesBeforeReplace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("self-replace is Unix-only this version")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "zyrax-guard")
	os.WriteFile(target, []byte("OLD"), 0o755)

	opts := UpgradeOptions{
		Current:  "0.8.0",
		Method:   MethodBinary,
		ExecPath: target,
		Fetch:    func(context.Context) (string, error) { return "0.9.0", nil },
		// Download returns the asset bytes and a checksums body that does NOT match.
		Download: func(_ context.Context, _, _ string) (asset []byte, checksums string, err error) {
			return []byte("PAYLOAD"), "0000  zyrax-guard-" + runtime.GOOS + "-" + runtime.GOARCH, nil
		},
	}
	var buf strings.Builder
	if err := Upgrade(&buf, opts); err == nil {
		t.Fatal("expected verification failure to abort upgrade")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "OLD" {
		t.Fatalf("binary must be untouched on verification failure, got %q", b)
	}
}

// TestDefaultCosignVerifyRequireSignature verifies the --require-signature contract for
// the absent-cosign branch. This test is deterministic regardless of whether cosign is
// installed on the machine: when cosign is present it is skipped (the test covers only
// the absence path); when cosign is absent both branches are exercised.
func TestDefaultCosignVerifyRequireSignature(t *testing.T) {
	if _, err := exec.LookPath("cosign"); err == nil {
		t.Skip("cosign is installed; this test covers the absent+required branch only")
	}
	asset := assetName(runtime.GOOS, runtime.GOARCH)
	ctx := context.Background()

	// requireSig=true must error when cosign is absent.
	got := defaultCosignVerify(io.Discard, true)(ctx, "0.9.0", asset, []byte("x"))
	if got == nil {
		t.Fatal("require-signature must return an error when cosign is absent")
	}
	if !strings.Contains(got.Error(), "cosign") {
		t.Errorf("error message should mention cosign, got: %v", got)
	}

	// requireSig=false must NOT error on cosign absence (best-effort).
	got2 := defaultCosignVerify(io.Discard, false)(ctx, "0.9.0", asset, []byte("x"))
	if got2 != nil {
		t.Fatalf("best-effort must not error when cosign absent, got: %v", got2)
	}
}
