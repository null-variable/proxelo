package nginx

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// Limits on an uploaded archive.
const (
	maxFiles     = 4096
	maxTotalSize = 64 << 20
)

// Load reads an upload: nginx -T output, or a tar (optionally gzipped) or
// zip archive of the configuration directory. In an archive the main file
// is the nginx.conf nearest the top; its paths are kept as in the archive,
// rooted at /, so an archive of /etc/nginx keeps include paths working
// when its entries are etc/nginx/...
func Load(raw []byte) (Files, string, error) {
	switch {
	case bytes.HasPrefix(raw, []byte("PK\x03\x04")):
		return unzip(raw)
	case bytes.HasPrefix(raw, []byte{0x1f, 0x8b}):
		z, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, "", err
		}
		return untar(z)
	case len(raw) > 262 && string(raw[257:262]) == "ustar":
		return untar(bytes.NewReader(raw))
	}
	return SplitDump(string(raw))
}

func untar(r io.Reader) (Files, string, error) {
	files := Files{}
	total := 0
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("reading tar: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxTotalSize-int64(total)+1))
		if err != nil {
			return nil, "", fmt.Errorf("reading tar: %w", err)
		}
		if err := add(files, h.Name, b, &total); err != nil {
			return nil, "", err
		}
	}
	return withMain(files)
}

func unzip(raw []byte) (Files, string, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, "", fmt.Errorf("reading zip: %w", err)
	}
	files := Files{}
	total := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !f.Mode().IsRegular() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, "", fmt.Errorf("reading zip: %w", err)
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxTotalSize-int64(total)+1))
		rc.Close()
		if err != nil {
			return nil, "", fmt.Errorf("reading zip: %w", err)
		}
		if err := add(files, f.Name, b, &total); err != nil {
			return nil, "", err
		}
	}
	return withMain(files)
}

func add(files Files, name string, b []byte, total *int) error {
	name = path.Clean("/" + name)
	// macOS archivers add AppleDouble metadata next to each file.
	if strings.HasPrefix(path.Base(name), "._") || strings.HasPrefix(name, "/__MACOSX/") {
		return nil
	}
	*total += len(b)
	if *total > maxTotalSize {
		return fmt.Errorf("archive is larger than %d MiB", maxTotalSize>>20)
	}
	if len(files) >= maxFiles {
		return fmt.Errorf("archive has more than %d files", maxFiles)
	}
	files[name] = string(b)
	return nil
}

// withMain picks the nginx.conf with the fewest path elements.
func withMain(files Files) (Files, string, error) {
	main := ""
	for p := range files {
		if path.Base(p) != "nginx.conf" {
			continue
		}
		if main == "" || strings.Count(p, "/") < strings.Count(main, "/") || strings.Count(p, "/") == strings.Count(main, "/") && p < main {
			main = p
		}
	}
	if main == "" {
		return nil, "", errors.New("the archive has no nginx.conf")
	}
	return files, main, nil
}
