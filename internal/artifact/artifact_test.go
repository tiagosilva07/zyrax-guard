package artifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func makeTarGz(t *testing.T, entries map[string]string, extra func(*tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	if extra != nil {
		extra(tw)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestExtractBasic(t *testing.T) {
	tgz := makeTarGz(t, map[string]string{"package/package.json": `{"name":"x"}`, "package/index.js": "ok"}, nil)
	files, err := ExtractTarGz(tgz, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if files["package/package.json"] != `{"name":"x"}` {
		t.Fatalf("missing package.json: %v", files)
	}
}

func TestExtractRejectsTraversalAndSymlink(t *testing.T) {
	trav := makeTarGz(t, map[string]string{"../evil": "x"}, nil)
	if f, _ := ExtractTarGz(trav, DefaultLimits()); len(f) != 0 {
		t.Errorf("path traversal entry must be skipped: %v", f)
	}
	sym := makeTarGz(t, nil, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	})
	if f, _ := ExtractTarGz(sym, DefaultLimits()); len(f) != 0 {
		t.Errorf("symlink entry must be skipped: %v", f)
	}
}

func TestExtractFileCountCap(t *testing.T) {
	many := map[string]string{}
	for i := 0; i < 50; i++ {
		many[fmtName(i)] = "x"
	}
	lim := DefaultLimits()
	lim.MaxFiles = 10
	if _, err := ExtractTarGz(makeTarGz(t, many, nil), lim); err == nil {
		t.Fatal("exceeding MaxFiles must error")
	}
}

func TestExtractTarGzCapsTotalDecompression(t *testing.T) {
	// One entry larger than MaxFileBytes (so it's skipped) but whose decompressed size
	// exceeds a small MaxDecompressedBytes must abort rather than decompress it all.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	big := make([]byte, 2<<20) // 2 MiB entry
	tw.WriteHeader(&tar.Header{Name: "big.bin", Mode: 0o644, Size: int64(len(big)), Typeflag: tar.TypeReg})
	tw.Write(big)
	tw.Close()
	gz.Close()

	lim := DefaultLimits()
	lim.MaxFileBytes = 1 << 10          // 1 KiB → big.bin is skipped
	lim.MaxDecompressedBytes = 64 << 10 // 64 KiB ceiling → must abort while skipping
	if _, err := ExtractTarGz(buf.Bytes(), lim); err == nil {
		t.Fatal("expected decompression-cap error when a skipped entry exceeds MaxDecompressedBytes")
	}
}

func fmtName(i int) string {
	return "package/f" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + ".js"
}

func makeZip(t *testing.T, entries map[string]string, extra func(*zip.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if extra != nil {
		extra(zw)
	}
	zw.Close()
	return buf.Bytes()
}

func TestExtractZipBasic(t *testing.T) {
	z := makeZip(t, map[string]string{
		"example.com/mod@v1.0.0/go.mod": "module example.com/mod\n",
		"example.com/mod@v1.0.0/mod.go": "package mod\n",
	}, nil)
	files, err := ExtractZip(z, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if files["example.com/mod@v1.0.0/go.mod"] != "module example.com/mod\n" {
		t.Fatalf("missing go.mod: %v", files)
	}
}

func TestExtractZipRejectsTraversal(t *testing.T) {
	z := makeZip(t, map[string]string{"../evil": "x"}, nil)
	if f, _ := ExtractZip(z, DefaultLimits()); len(f) != 0 {
		t.Errorf("path traversal entry must be skipped: %v", f)
	}
}

func TestExtractZipFileCountCap(t *testing.T) {
	many := map[string]string{}
	for i := 0; i < 50; i++ {
		many[fmtName(i)] = "x"
	}
	lim := DefaultLimits()
	lim.MaxFiles = 10
	if _, err := ExtractZip(makeZip(t, many, nil), lim); err == nil {
		t.Fatal("exceeding MaxFiles must error")
	}
}

func TestExtractZipCapsDecompression(t *testing.T) {
	// Zip entries are independently addressable, so a single oversized entry
	// is already bounded by the io.LimitReader on its own read (unlike tar's
	// shared gzip stream). The bomb risk here is many skipped-oversized entries
	// each contributing their own bounded-but-nonzero read: the running
	// decompressed-bytes total must still cap that cumulative cost.
	entries := map[string]string{}
	for i := 0; i < 100; i++ {
		entries[fmtName(i)] = strings.Repeat("x", 200) // over MaxFileBytes below
	}
	z := makeZip(t, entries, nil)

	lim := DefaultLimits()
	lim.MaxFiles = 1000
	lim.MaxFileBytes = 50          // every entry skipped (200 > 50); ~51 bytes read each
	lim.MaxDecompressedBytes = 500 // exceeded well before all 100 entries are read
	if _, err := ExtractZip(z, lim); err == nil {
		t.Fatal("expected decompression-cap error from cumulative skipped-entry reads")
	}
}
