// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"fmt"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// The gc.ref.content.* labels on a manifest are the only thing keeping its
// config and layers reachable once the import lease drops. Getting the set
// wrong is invisible on the boot that writes it: the images work, then GC
// runs and every affected blob disappears, leaving image records whose
// content is gone -- on a device with no path to a registry.
func TestGcRefLabels(t *testing.T) {
	children := []ocispec.Descriptor{
		{Digest: digest.FromString("config")},
		{Digest: digest.FromString("layer0")},
		{Digest: digest.FromString("layer1")},
	}
	labels := gcRefLabels(children)

	if len(labels) != len(children) {
		t.Fatalf("%d labels for %d children: %v", len(labels), len(children), labels)
	}
	// Indices start at 0 and are dense: containerd walks
	// gc.ref.content.<n> by prefix, so a gap costs nothing but a
	// duplicate key silently drops a child.
	for i, c := range children {
		key := fmt.Sprintf("containerd.io/gc.ref.content.%d", i)
		if labels[key] != c.Digest.String() {
			t.Errorf("%s = %q, want %s", key, labels[key], c.Digest)
		}
	}
}

// Callers pass Blobs[1:] because Blobs[0] is the manifest itself, and a
// manifest that references itself is a cycle the GC follows forever. This
// pins the convention the call sites depend on.
func TestGcRefLabelsExcludesTheManifestItself(t *testing.T) {
	manifest := ocispec.Descriptor{Digest: digest.FromString("manifest")}
	blobs := []ocispec.Descriptor{
		manifest,
		{Digest: digest.FromString("config")},
		{Digest: digest.FromString("layer")},
	}
	for k, v := range gcRefLabels(blobs[1:]) {
		if v == manifest.Digest.String() {
			t.Errorf("%s names the manifest itself", k)
		}
	}
}
