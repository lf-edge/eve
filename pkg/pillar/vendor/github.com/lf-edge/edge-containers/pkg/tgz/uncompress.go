package tgz

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
)

// Uncompress takes a given path to a tgz file and extracts the contents
// to the target directory.
// contains only that file.
func Uncompress(infile, outdir string) error {
	tgzfile, err := os.Open(infile)
	if err != nil {
		return fmt.Errorf("Could not open tgz file '%s': %v", infile, err)
	}
	defer tgzfile.Close()
	gzipReader, err := gzip.NewReader(tgzfile)
	if err != nil {
		return fmt.Errorf("could not open tgzfile %s to read: %v", infile, err)
	}
	defer gzipReader.Close()
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
		fullFilename := path.Join(outdir, filename)
		// open a file to write
		f, err := os.Create(fullFilename)
		if err != nil {
			return fmt.Errorf("error creating file %s: %w", fullFilename, err)
		}
		if _, err := io.Copy(f, tarReader); err != nil {
			f.Close()
			return fmt.Errorf("error reading tar file %s and writing to %s: %v", filename, fullFilename, err)
		}
		f.Close()
	}
	return nil
}
