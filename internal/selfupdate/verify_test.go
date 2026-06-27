package selfupdate

import "testing"

func TestVerifySHA256(t *testing.T) {
	data := []byte("hello zyrax")
	// checksums.txt format: "<hex>  <filename>" per line.
	checksums := "deadbeef  other-file\n" +
		"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  zyrax-guard-linux-amd64\n"
	// wrong sum first to prove we match by filename, not position:
	if err := verifySHA256(data, checksums, "zyrax-guard-linux-amd64"); err == nil {
		t.Fatal("expected mismatch error for tampered data")
	}
	real := sha256Hex(data)
	good := "x  other\n" + real + "  zyrax-guard-linux-amd64\n"
	if err := verifySHA256(data, good, "zyrax-guard-linux-amd64"); err != nil {
		t.Fatalf("expected match, got %v", err)
	}
	if err := verifySHA256(data, good, "missing-asset"); err == nil {
		t.Fatal("expected error when filename absent from checksums")
	}
}
