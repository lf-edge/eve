package verifier

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/google/go-containerregistry/pkg/v1"
)

/*
 utilities for verifying docker export tar files
 it makes several very important assumptions

 - the registry manifest *also* is in the tar file, named "manifest-<sha256hash>.json"
 - the file is structured as a "docker export" format, and not an OCI v1 format

 The latter is in place only because we still are using rkt, which needs an aci,
 which we get via running docker2aci, which only supports docker export files.
 When we get rid of rkt, we should convert these all to OCI v1.
*/

// compute the sha for an OCI tar file with the manifest inside
func computeShaOCITar(filename string) ([]byte, error) {
	// extract the image manifest itself, and calculate its hash
	// then check the hash of each layer and the config against the information in the manifest
	// if all adds up, return the hash of the manifest, nil error

	var (
		f               *os.File
		err             error
		re              *regexp.Regexp
		manifestB, hash []byte
	)

	if re, err = regexp.Compile(`imagemanifest-([a-f0-9]+).json`); err != nil {
		return nil, fmt.Errorf("unable to compile regexp to find imagemanifest: %v", err)
	}

	// open our tar file
	if f, err = os.Open(filename); err != nil {
		return nil, err
	}
	defer f.Close()

	manifestB, err = readFromTar(f, re)
	if err != nil {
		return nil, fmt.Errorf("error reading image manifest %s from tar %s: %v", re, filename, err)
	}
	hashArray := sha256.Sum256(manifestB)
	hash = hashArray[:]

	// convert the manifest into a processable structure
	manifest, err := v1.ParseManifest(bytes.NewReader(manifestB))
	if err != nil {
		return nil, fmt.Errorf("invalid image manifest file %s: %v", filename, err)
	}

	// TODO: Look at using img.Validate()
	// which does sha validation
	// github.com/google/go-containerregistry/blob/master/pkg/v1/validate/
	configHash := manifest.Config.Digest

	// find that file in the tar, and check its contents
	configFileRegex, err := regexp.Compile(fmt.Sprintf("sha256:%s", configHash.Hex))
	if err != nil {
		return nil, fmt.Errorf("unable to create regex filename for config manifest: %v", err)
	}
	if err = checkHashInTar(f, configFileRegex, configHash.Hex); err != nil {
		return nil, fmt.Errorf("mismatched config in tar for %s: %v", configHash.Hex, err)
	}

	// go through the layers
	layers := manifest.Layers
	for _, layer := range layers {
		digest := layer.Digest
		// create the name of the file in the archive
		layerFileNameRegex, err := regexp.Compile(fmt.Sprintf("%s.tar.gz", digest.Hex))
		if err != nil {
			return nil, fmt.Errorf("unable to create regex filename for config manifest: %v", err)
		}
		if err = checkHashInTar(f, layerFileNameRegex, digest.Hex); err != nil {
			return nil, fmt.Errorf("mismatched layer in tar for %s: %v", digest.Hex, err)
		}
	}
	// if we made it this far, everything matched
	return hash, nil
}

// readFromTar given an io.ReadSeeker and a filename, get the contents of the
// file from the ReadSeeker
func readFromTar(f io.ReadSeeker, re *regexp.Regexp) ([]byte, error) {
	hdr, reader, err := getFileReaderInTar(f, re)
	if err != nil {
		return nil, err
	}
	// read the data
	b := make([]byte, hdr.Size)
	read, err := reader.Read(b)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("error reading %s from tarfile: %v", re, err)
	}
	if read != len(b) {
		return nil, fmt.Errorf("file %s had mismatched size to tar header, expected %d, actual %d", re, len(b), read)
	}
	return b, nil
}

func checkHashInTar(f io.ReadSeeker, re *regexp.Regexp, hash string) error {
	_, reader, err := getFileReaderInTar(f, re)
	if err != nil {
		return err
	}
	// stream the data to check the hash
	streamHash, err := hashStream(reader)
	if err != nil {
		return fmt.Errorf("error calculating stream on hash for %s: %v", re, err)
	}
	streamHashStr := hex.EncodeToString(streamHash)
	if streamHashStr != hash {
		return fmt.Errorf("mismatched hash for %s, actual %s, expected %s", re, streamHashStr, hash)
	}
	return nil
}

// getFileReaderInTar scan a tar stream to get a header and reader for the
// file data that matches the provided regexp
func getFileReaderInTar(f io.ReadSeeker, re *regexp.Regexp) (*tar.Header, io.Reader, error) {
	var (
		err error
		hdr *tar.Header
	)
	if _, err = f.Seek(0, 0); err != nil {
		return nil, nil, fmt.Errorf("unable to reset tar file reader %s: %v", re, err)
	}

	// get a new reader
	tr := tar.NewReader(f)

	// go through each file in the archive, looking for the file we want
	for {
		if hdr, err = tr.Next(); err != nil {
			if err == io.EOF {
				return nil, nil, fmt.Errorf("could not find file matching %s in tar stream: %v", re, err)
			}
			return nil, nil, fmt.Errorf("error reading information from tar stream: %v", err)
		}
		// if the name matches the format of the requested file, use it
		if re.MatchString(hdr.Name) {
			return hdr, tr, nil
		}
	}
}

func hashStream(reader io.Reader) ([]byte, error) {
	digester := sha256.New()
	_, err := io.Copy(digester, reader)
	if err != nil {
		return nil, err
	}
	return digester.Sum(make([]byte, 0, digester.Size())), nil
}
