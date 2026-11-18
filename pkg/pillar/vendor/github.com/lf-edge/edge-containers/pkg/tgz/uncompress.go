package tgz

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Uncompress extracts the regular files in the tgz file infile into outdir,
// creating parent directories as needed. Directory entries are skipped; any
// other entry type, and any name that is absolute or escapes outdir, is an
// error.
func Uncompress(infile, outdir string) error {
	tgzfile, err := os.Open(infile)
	if err != nil {
		return fmt.Errorf("could not open tgz file '%s': %v", infile, err)
	}
	defer func() { _ = tgzfile.Close() }()
	gzipReader, err := gzip.NewReader(tgzfile)
	if err != nil {
		return fmt.Errorf("could not open tgzfile %s to read: %v", infile, err)
	}
	defer func() { _ = gzipReader.Close() }()
	tarReader := tar.NewReader(gzipReader)

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("error reading tar entry header: %v", err)
		}
		filename := hdr.Name
		if !filepath.IsLocal(filename) {
			return fmt.Errorf("invalid tar entry path %q: not local to output directory", filename)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return fmt.Errorf("unsupported tar entry type %q for %s", hdr.Typeflag, filename)
		}
		fullFilename := filepath.Join(outdir, filename)
		if err := os.MkdirAll(filepath.Dir(fullFilename), 0o755); err != nil {
			return fmt.Errorf("error creating directory for %s: %w", fullFilename, err)
		}
		f, err := os.Create(fullFilename)
		if err != nil {
			return fmt.Errorf("error creating file %s: %w", fullFilename, err)
		}
		if _, err := io.Copy(f, tarReader); err != nil {
			_ = f.Close()
			return fmt.Errorf("error reading tar file %s and writing to %s: %v", filename, fullFilename, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("error closing %s: %w", fullFilename, err)
		}
	}
	return nil
}
