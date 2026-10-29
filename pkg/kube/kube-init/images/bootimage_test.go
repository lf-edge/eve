// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func testBootFiles(t *testing.T) []bootFile {
	t.Helper()
	dir := t.TempDir()
	files := []bootFile{
		{name: "kernel", src: filepath.Join(dir, "kernel")},
		{name: "runx-initrd", src: filepath.Join(dir, "runx-initrd")},
	}
	for i, f := range files {
		if err := os.WriteFile(f.src, bytes.Repeat([]byte{byte('a' + i)}, 1000+i), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func readTar(t *testing.T, data []byte) (map[string][]byte, map[string]*tar.Header) {
	t.Helper()
	contents := map[string][]byte{}
	headers := map[string]*tar.Header{}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		contents[hdr.Name] = b
		headers[hdr.Name] = hdr
	}
	return contents, headers
}

func TestBootImageArchiveIsReproducible(t *testing.T) {
	files := testBootFiles(t)
	const tag = ExternalBootImageName + ":1.2.3-k-amd64"
	var a, b bytes.Buffer
	idA, err := writeBootImageArchive(&a, files, tag)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.Chtimes(f.src, time.Now(), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	idB, err := writeBootImageArchive(&b, files, tag)
	if err != nil {
		t.Fatal(err)
	}
	if idA != idB || !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("archives differ for the same inputs: %s vs %s", idA, idB)
	}

	if err := os.WriteFile(files[0].src, []byte("other kernel"), 0o600); err != nil {
		t.Fatal(err)
	}
	idC, err := writeBootImageArchive(io.Discard, files, tag)
	if err != nil {
		t.Fatal(err)
	}
	if idC == idA {
		t.Fatalf("diff ID did not change with the kernel")
	}
}

func TestBootImageArchiveLayout(t *testing.T) {
	files := testBootFiles(t)
	const tag = ExternalBootImageName + ":1.2.3-k-amd64"
	var buf bytes.Buffer
	diffID, err := writeBootImageArchive(&buf, files, tag)
	if err != nil {
		t.Fatal(err)
	}
	outer, _ := readTar(t, buf.Bytes())

	var manifest []archiveManifest
	if err := json.Unmarshal(outer["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest) != 1 || len(manifest[0].RepoTags) != 1 || manifest[0].RepoTags[0] != tag {
		t.Fatalf("manifest = %+v, want one image tagged %s", manifest, tag)
	}
	m := manifest[0]

	configSum := sha256.Sum256(outer[m.Config])
	if m.Config != hex.EncodeToString(configSum[:])+".json" {
		t.Errorf("config %s is not named by its digest", m.Config)
	}
	var config imageConfig
	if err := json.Unmarshal(outer[m.Config], &config); err != nil {
		t.Fatal(err)
	}
	if config.Architecture != runtime.GOARCH || config.OS != "linux" {
		t.Errorf("config platform = %s/%s", config.OS, config.Architecture)
	}

	if len(m.Layers) != 1 {
		t.Fatalf("layers = %v, want one", m.Layers)
	}
	layer := outer[m.Layers[0]]
	layerSum := sha256.Sum256(layer)
	if got := "sha256:" + hex.EncodeToString(layerSum[:]); got != diffID ||
		len(config.RootFS.DiffIDs) != 1 || config.RootFS.DiffIDs[0] != diffID {
		t.Errorf("layer digest %s, returned diff ID %s, config diff IDs %v",
			got, diffID, config.RootFS.DiffIDs)
	}

	inner, headers := readTar(t, layer)
	if len(inner) != len(files) {
		t.Errorf("layer has %d files, want %d", len(inner), len(files))
	}
	for _, f := range files {
		want, err := os.ReadFile(f.src)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(inner[f.name], want) {
			t.Errorf("%s content differs from %s", f.name, f.src)
		}
		hdr := headers[f.name]
		if hdr.Mode != 0o666 || hdr.Uid != 0 || hdr.Gid != 0 || !hdr.ModTime.Equal(time.Unix(0, 0)) {
			t.Errorf("%s header mode %o uid %d gid %d mtime %v",
				f.name, hdr.Mode, hdr.Uid, hdr.Gid, hdr.ModTime)
		}
	}
}
