package verifier

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

const (
	testDir        = "testdata"
	testTarFile    = "basic.tar"
	testTarContent = "basic.txt"
)

func TestComputeShaOCITar(t *testing.T) {
	// we need several test cases:
	// - missing imagemanifest file
	// - missing config file
	// - mismatched config hash
	// - missing layer file
	// - mismatched layer hash
	// - valid everything
	//
	// simplest way to do all of this is separate tar files, each of which
	// represents a different use case

	const (
		tarMissingManifest  = "basic.tar"
		tarMissingConfig    = "missingconfig.tar"
		tarMismatchedConfig = "mismatchedconfig.tar"
		tarMissingLayer     = "missinglayer.tar"
		tarMismatchedLayer  = "mismatchedlayer.tar"
		tarValid            = "valid.tar"
	)

	tests := []struct {
		tarfile string
		err     error
	}{
		{tarMissingManifest, fmt.Errorf("error reading image manifest")},
		{tarMissingConfig, fmt.Errorf("mismatched config in tar")},
		{tarMismatchedConfig, fmt.Errorf("mismatched config in tar")},
		{tarMissingLayer, fmt.Errorf("mismatched layer in tar")},
		{tarMismatchedLayer, fmt.Errorf("mismatched layer in tar")},
		{tarValid, nil},
	}
	for i, tt := range tests {
		hash, err := computeShaOCITar(path.Join(testDir, tt.tarfile))
		if (err == nil && tt.err != nil) || (err != nil && tt.err == nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())) {
			t.Errorf("%d: mismatched errors\nactual %v\nexpected %v", i, err, tt.err)
			continue
		}
		if err != nil {
			continue
		}
		hashfile := path.Join(testDir, fmt.Sprintf("%s.hash", tt.tarfile))
		valid, err := ioutil.ReadFile(hashfile)
		if err != nil {
			t.Errorf("%d: unable to read tarfile hash %s: %v", i, hashfile, err)
		}
		hashStr := fmt.Sprintf("%x", hash)
		validStr := fmt.Sprintf("%s", valid)
		if hashStr != validStr {
			t.Errorf("%d: mismatched hash vs file %s\nactual '%s'\nexpected '%s'", i, hashfile, hashStr, validStr)
		}
	}
}

func TestReadFromTar(t *testing.T) {
	/*
		tests:
		- internal file does not exist
		- compare output
	*/
	tests := []struct {
		filename string
		err      error
	}{
		{"basicnotexistslalal.txt", fmt.Errorf("could not find file matching")},
		{testTarContent, nil},
	}
	// open our tar file
	myTarFile := path.Join(testDir, testTarFile)
	f, err := os.Open(myTarFile)
	if err != nil {
		t.Fatalf("unable to open tar file %s for reading: %v", myTarFile, err)
	}
	defer f.Close()

	for i, tt := range tests {
		re, err := regexp.Compile(tt.filename)
		if err != nil {
			t.Fatalf("%d: unable to compile filename regex: %v", i, err)
		}
		b, err := readFromTar(f, re)
		// mismatched errors
		if (err == nil && tt.err != nil) || (err != nil && tt.err == nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())) {
			t.Errorf("%d: mismatched error, actual then expected", i)
			t.Logf("%v", err)
			t.Logf("%v", tt.err)
			continue
		}
		// matched errors, but still errors, so don't try to match up the bytes
		if err != nil {
			continue
		}
		// no errors, try to match up the bytes
		validFile := path.Join(testDir, tt.filename)
		valid, err := ioutil.ReadFile(validFile)
		if err != nil {
			t.Errorf("%d: could not read %s: %v", i, validFile, err)
			continue
		}
		if bytes.Compare(valid, b) != 0 {
			t.Errorf("%d: mismatched content, actual then expected\n%s\n%s", i, b, valid)
		}
	}

}

func TestCheckHashInTar(t *testing.T) {
	// we check everything in checkHashInTar except for matching the hash, e.g.
	// all errors in called funcs, so just need to check the hash itself

	// read the file contents and get the hash
	validFile := path.Join(testDir, testTarContent)
	b, err := ioutil.ReadFile(validFile)
	if err != nil {
		t.Fatalf("could not read %s: %v", validFile, err)
	}
	hash := sha256.Sum256(b)

	// get a reader for the tar file
	myTarFile := path.Join(testDir, testTarFile)
	f, err := os.Open(myTarFile)
	if err != nil {
		t.Fatalf("unable to open tar file %s for reading: %v", myTarFile, err)
	}
	defer f.Close()

	re, err := regexp.Compile(testTarContent)
	if err != nil {
		t.Fatalf("unable to compile filename regex: %v", err)
	}
	if err := checkHashInTar(f, re, fmt.Sprintf("%x", hash)); err != nil {
		t.Errorf("mismatched hash, err: %v", err)
	}
}

func TestHashStream(t *testing.T) {
	// just create a stream from []byte and check the hash
	b := make([]byte, 5000)
	rand.Read(b)
	valid := sha256.Sum256(b)
	reader := bytes.NewReader(b)
	hash, err := hashStream(reader)
	if err != nil {
		t.Fatalf("unexpected error getting hash stream: %v", err)
	}
	if len(hash) == 0 || bytes.Compare(valid[:], hash) != 0 {
		t.Fatalf("mismatched hashes\nactual: %x\nexpected: %x", hash, valid)
	}
}
