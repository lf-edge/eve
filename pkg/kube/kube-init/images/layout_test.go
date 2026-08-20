// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestParseLayout(t *testing.T) {
	imgs, err := parseLayout("testdata/layout")
	if err != nil {
		t.Fatal(err)
	}
	if len(imgs) != 1 {
		t.Fatalf("want 1 image, got %d", len(imgs))
	}
	got := imgs[0]
	if got.RefName != "docker.io_library_alpine_3.21" {
		t.Errorf("RefName=%q", got.RefName)
	}
	if got.Manifest.Digest == "" {
		t.Error("empty manifest digest")
	}
	// manifest + config + >=1 layer
	if len(got.Blobs) < 3 {
		t.Errorf("want >=3 blobs (manifest,config,layer), got %d", len(got.Blobs))
	}
}

// TestParseLayoutIndex exercises the manifest-list (multi-arch) branch:
// resolveToManifest must follow the index to the manifest matching
// runtime.GOARCH, not a hardcoded arch. The alpine fixture flattens to a
// direct manifest and never hits this path.
func TestParseLayoutIndex(t *testing.T) {
	dir := t.TempDir()
	blobs := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0755); err != nil {
		t.Fatal(err)
	}
	writeBlob := func(v any) ocispec.Descriptor {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		d := digest.NewDigestFromBytes(digest.SHA256, sum(b))
		if err := os.WriteFile(filepath.Join(blobs, d.Encoded()), b, 0644); err != nil {
			t.Fatal(err)
		}
		return ocispec.Descriptor{Digest: d, Size: int64(len(b))}
	}

	layer := writeBlob(map[string]any{"layer": "data"})
	buildManifest := func(arch string) ocispec.Descriptor {
		config := writeBlob(map[string]any{"architecture": arch, "os": "linux"})
		m := ocispec.Manifest{Config: config, Layers: []ocispec.Descriptor{layer}}
		m.MediaType = ocispec.MediaTypeImageManifest
		d := writeBlob(m)
		d.MediaType = ocispec.MediaTypeImageManifest
		return d
	}
	// Distinct content per arch → distinct digests, so the assertion below
	// truly proves the host-arch manifest was selected (not just any entry).
	otherArch := "amd64"
	if runtime.GOARCH == "amd64" {
		otherArch = "arm64"
	}
	hostManifest := buildManifest(runtime.GOARCH)
	otherManifest := buildManifest(otherArch)

	index := ocispec.Index{Manifests: []ocispec.Descriptor{
		{Digest: otherManifest.Digest, Size: otherManifest.Size, MediaType: ocispec.MediaTypeImageManifest,
			Platform: &ocispec.Platform{OS: "linux", Architecture: otherArch}},
		{Digest: hostManifest.Digest, Size: hostManifest.Size, MediaType: ocispec.MediaTypeImageManifest,
			Platform: &ocispec.Platform{OS: "linux", Architecture: runtime.GOARCH}},
	}}
	index.MediaType = ocispec.MediaTypeImageIndex
	listDesc := writeBlob(index)
	listDesc.MediaType = ocispec.MediaTypeImageIndex

	topIndex := ocispec.Index{Manifests: []ocispec.Descriptor{
		{Digest: listDesc.Digest, Size: listDesc.Size, MediaType: ocispec.MediaTypeImageIndex,
			Annotations: map[string]string{ocispec.AnnotationRefName: "example.com_multiarch_latest"}},
	}}
	topIndex.MediaType = ocispec.MediaTypeImageIndex
	b, err := json.Marshal(topIndex)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), b, 0644); err != nil {
		t.Fatal(err)
	}

	imgs, err := parseLayout(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(imgs) != 1 {
		t.Fatalf("want 1 image, got %d", len(imgs))
	}
	if imgs[0].Manifest.Digest != hostManifest.Digest {
		t.Errorf("resolved to %s, want host-arch manifest %s", imgs[0].Manifest.Digest, hostManifest.Digest)
	}
	if imgs[0].RefName != "example.com_multiarch_latest" {
		t.Errorf("RefName=%q", imgs[0].RefName)
	}
}

func sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
