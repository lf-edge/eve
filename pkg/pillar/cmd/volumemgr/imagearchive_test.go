// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// fakeCAS embeds the cas.CAS interface so that only the methods exercised by a
// test need real implementations; any other call dereferences the nil embedded
// interface and panics, which is the desired behavior for a focused unit test.
type fakeCAS struct {
	cas.CAS
	children   map[string][]string // "sha256:<h>" -> children ["sha256:<h>", ...]
	mediaTypes map[string]string   // "sha256:<h>" -> media type
	sizes      map[string]int64    // "sha256:<h>" -> size
}

func (f *fakeCAS) Children(blobHash string) ([]string, error) {
	return f.children[blobHash], nil
}

func (f *fakeCAS) ListBlobsMediaTypes() (map[string]string, error) {
	return f.mediaTypes, nil
}

func (f *fakeCAS) GetBlobInfo(blobHash string) (*cas.BlobInfo, error) {
	return &cas.BlobInfo{Digest: blobHash, Size: f.sizes[blobHash]}, nil
}

// makeTarFile writes a tar (optionally gzip-compressed) containing zero-length
// entries with the given names, and returns its path.
func makeTarFile(t *testing.T, gz bool, names ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "artifact")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	var underlying io.Writer = f
	var zw *gzip.Writer
	if gz {
		zw = gzip.NewWriter(f)
		underlying = zw
	}
	tw := tar.NewWriter(underlying)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{
			Name:     n,
			Mode:     0644,
			Size:     0,
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("write header %s: %v", n, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if zw != nil {
		if err := zw.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
	}
	return p
}

func makeRawFile(t *testing.T, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "raw")
	if err := os.WriteFile(p, content, 0644); err != nil {
		t.Fatalf("write raw: %v", err)
	}
	return p
}

func TestDetectImageArchive(t *testing.T) {
	ociNames := []string{"oci-layout", "index.json", "manifest.json", "blobs/sha256/abc"}
	dockerNames := []string{"manifest.json", "blobs/sha256/abc"}

	tests := []struct {
		name string
		path string
		want imageArchiveKind
	}{
		{"gzip oci-layout", makeTarFile(t, true, ociNames...), ociLayoutArchive},
		{"plain oci-layout", makeTarFile(t, false, ociNames...), ociLayoutArchive},
		{"gzip docker-save", makeTarFile(t, true, dockerNames...), dockerArchive},
		{"plain docker-save", makeTarFile(t, false, dockerNames...), dockerArchive},
		{"unrelated tar", makeTarFile(t, false, "disk.raw", "boot/kernel"), notImageArchive},
		{"raw bytes", makeRawFile(t, []byte("this is just a raw disk image, not a tar")), notImageArchive},
		{"empty path", "", notImageArchive},
		{"missing file", filepath.Join(t.TempDir(), "does-not-exist"), notImageArchive},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := detectImageArchive(tc.path); got != tc.want {
				t.Fatalf("detectImageArchive(%s) = %d, want %d", tc.name, got, tc.want)
			}
		})
	}
}

// split-rootfs-shaped tree: index -> manifest -> {config, root layer, ext layer}.
func splitRootfsFakeCAS() *fakeCAS {
	return &fakeCAS{
		children: map[string][]string{
			"sha256:idx":       {"sha256:man"},
			"sha256:man":       {"sha256:cfg", "sha256:rootlayer", "sha256:extlayer"},
			"sha256:cfg":       nil,
			"sha256:rootlayer": nil,
			"sha256:extlayer":  nil,
		},
		mediaTypes: map[string]string{
			"sha256:idx":       "application/vnd.oci.image.index.v1+json",
			"sha256:man":       "application/vnd.oci.image.manifest.v1+json",
			"sha256:cfg":       "application/vnd.oci.image.config.v1+json",
			"sha256:rootlayer": "application/vnd.oci.image.layer.v1.tar",
			"sha256:extlayer":  "application/vnd.oci.image.layer.v1.tar",
		},
		sizes: map[string]int64{
			"sha256:idx":       300,
			"sha256:man":       1623,
			"sha256:cfg":       3367,
			"sha256:rootlayer": 268435456,  // ~256 MB Core
			"sha256:extlayer":  1503564288, // ~1.4 GB Extension
		},
	}
}

func TestCollectImageBlobTree(t *testing.T) {
	got, err := collectImageBlobTree(splitRootfsFakeCAS(), "idx")
	if err != nil {
		t.Fatalf("collectImageBlobTree: %v", err)
	}
	want := []string{"idx", "man", "cfg", "rootlayer", "extlayer"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (index first, BFS)", got, want)
		}
	}
}

func TestCollectImageBlobTreeDedup(t *testing.T) {
	// A blob shared by two parents must appear only once.
	f := &fakeCAS{
		children: map[string][]string{
			"sha256:idx":  {"sha256:man1", "sha256:man2"},
			"sha256:man1": {"sha256:shared"},
			"sha256:man2": {"sha256:shared"},
		},
	}
	got, err := collectImageBlobTree(f, "idx")
	if err != nil {
		t.Fatalf("collectImageBlobTree: %v", err)
	}
	seen := map[string]int{}
	for _, h := range got {
		seen[h]++
	}
	if seen["shared"] != 1 {
		t.Fatalf("shared blob appeared %d times, want 1 (got %v)", seen["shared"], got)
	}
}

func TestBuildLoadedBlobStatuses(t *testing.T) {
	f := splitRootfsFakeCAS()
	blobs, err := buildLoadedBlobStatuses(f, "idx")
	if err != nil {
		t.Fatalf("buildLoadedBlobStatuses: %v", err)
	}
	if len(blobs) != 5 {
		t.Fatalf("got %d blobs, want 5", len(blobs))
	}
	if blobs[0].Sha256 != "idx" {
		t.Fatalf("first blob = %s, want idx", blobs[0].Sha256)
	}
	for _, b := range blobs {
		if b.State != types.LOADED {
			t.Fatalf("blob %s state = %v, want LOADED", b.Sha256, b.State)
		}
		full := "sha256:" + b.Sha256
		if b.MediaType != f.mediaTypes[full] {
			t.Fatalf("blob %s media type = %q, want %q", b.Sha256, b.MediaType, f.mediaTypes[full])
		}
		if int64(b.Size) != f.sizes[full] {
			t.Fatalf("blob %s size = %d, want %d", b.Sha256, b.Size, f.sizes[full])
		}
	}
}
