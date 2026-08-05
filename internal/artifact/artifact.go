// Package artifact extracts a gzipped tar (npm .tgz, PyPI sdist, crates .crate) or a
// zip (Go module source) into an in-memory path->content map, with strict caps and
// path/symlink sanitization — the files are untrusted, so this never writes to disk,
// never follows links, and never lets an entry escape the archive root.
package artifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path"
	"strings"
)

type Limits struct {
	MaxTotalBytes        int64 // total decompressed bytes across all kept files
	MaxFileBytes         int64 // per-file cap
	MaxFiles             int   // number of entries processed
	MaxDecompressedBytes int64 // hard ceiling on bytes pulled from gzip (incl. skipped) — zip-bomb guard
}

func DefaultLimits() Limits {
	return Limits{MaxTotalBytes: 64 << 20, MaxFileBytes: 1 << 20, MaxFiles: 2000, MaxDecompressedBytes: 256 << 20}
}

type countingReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.max > 0 && c.n > c.max {
		return 0, fmt.Errorf("decompressed stream exceeds %d bytes (possible zip bomb)", c.max)
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ExtractTarGz returns regular-file path->content. Entries that are symlinks/hard
// links, escape the root (.. or absolute), exceed MaxFileBytes, or are non-text are
// skipped; exceeding MaxFiles or MaxTotalBytes is an error (bomb defense).
func ExtractTarGz(b []byte, lim Limits) (map[string]string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(&countingReader{r: gz, max: lim.MaxDecompressedBytes})
	out := map[string]string{}
	var total int64
	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		count++
		if count > lim.MaxFiles {
			return nil, fmt.Errorf("archive exceeds %d entries", lim.MaxFiles)
		}
		if h.Typeflag != tar.TypeReg {
			continue // skip dirs, symlinks, hardlinks, devices
		}
		clean := path.Clean(h.Name)
		if strings.HasPrefix(clean, "..") || strings.HasPrefix(clean, "/") {
			continue // path traversal / absolute — reject
		}
		if h.Size > lim.MaxFileBytes {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, lim.MaxFileBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > lim.MaxFileBytes {
			continue
		}
		total += int64(len(data))
		if total > lim.MaxTotalBytes {
			return nil, fmt.Errorf("archive exceeds %d total bytes", lim.MaxTotalBytes)
		}
		out[clean] = string(data)
	}
	return out, nil
}

// ExtractZip returns regular-file path->content from a zip archive (the Go module
// proxy serves module source as .zip, unlike npm/PyPI/crates.io's gzipped tar).
// Same safety guarantees as ExtractTarGz: symlinks and non-regular entries are
// skipped, traversal/absolute paths are rejected, and per-file/total/entry-count
// caps are enforced. Zip entries are independently addressable (no single shared
// decompression stream to wrap in a counting reader), so the decompressed-bytes
// bomb guard is enforced by running total across each entry's capped read instead.
func ExtractZip(b []byte, lim Limits) (map[string]string, error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, fmt.Errorf("zip: %w", err)
	}
	if len(zr.File) > lim.MaxFiles {
		return nil, fmt.Errorf("archive exceeds %d entries", lim.MaxFiles)
	}
	out := map[string]string{}
	var total, decompressed int64
	for _, f := range zr.File {
		if !f.Mode().IsRegular() {
			continue // skip dirs, symlinks
		}
		clean := path.Clean(f.Name)
		if strings.HasPrefix(clean, "..") || strings.HasPrefix(clean, "/") {
			continue // path traversal / absolute — reject
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("zip entry %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, lim.MaxFileBytes+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("zip entry %s: %w", f.Name, err)
		}
		decompressed += int64(len(data))
		if decompressed > lim.MaxDecompressedBytes {
			return nil, fmt.Errorf("archive decompresses beyond %d bytes (possible zip bomb)", lim.MaxDecompressedBytes)
		}
		if int64(len(data)) > lim.MaxFileBytes {
			continue // per-file cap exceeded — skip, don't keep partial content
		}
		total += int64(len(data))
		if total > lim.MaxTotalBytes {
			return nil, fmt.Errorf("archive exceeds %d total bytes", lim.MaxTotalBytes)
		}
		out[clean] = string(data)
	}
	return out, nil
}
