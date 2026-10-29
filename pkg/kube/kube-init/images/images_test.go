// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"strings"
	"testing"
)

func TestUpstreamImageFullRef(t *testing.T) {
	img := UpstreamImage{Name: "docker.io/library/alpine", Tag: "3.21"}
	if got := img.FullRef(); got != "docker.io/library/alpine:3.21" {
		t.Errorf("FullRef = %q, want %q", got, "docker.io/library/alpine:3.21")
	}
}

// TestUpstreamImagesCatalogShape guards against accidental drift:
// every entry must have non-empty Tarball / Name / Tag fields, the
// tarball must live under /images/, and the Name must look like a
// fully-qualified registry/repo (contains "/", does not contain ":").
//
// A regression here usually indicates a typo in a one-line catalog
// edit; cheap to catch at build time.
func TestUpstreamImagesCatalogShape(t *testing.T) {
	if len(UpstreamImages) == 0 {
		t.Fatal("UpstreamImages catalog is empty")
	}
	seen := make(map[string]bool, len(UpstreamImages))
	for i, img := range UpstreamImages {
		if img.Tarball == "" || img.Name == "" || img.Tag == "" {
			t.Errorf("UpstreamImages[%d] %+v: empty field", i, img)
			continue
		}
		if !strings.HasPrefix(img.Tarball, "/images/") {
			t.Errorf("UpstreamImages[%d] Tarball = %q, want /images/ prefix",
				i, img.Tarball)
		}
		if !strings.HasSuffix(img.Tarball, ".tar") {
			t.Errorf("UpstreamImages[%d] Tarball = %q, want .tar suffix",
				i, img.Tarball)
		}
		if !strings.Contains(img.Name, "/") {
			t.Errorf("UpstreamImages[%d] Name = %q, want registry/repo form",
				i, img.Name)
		}
		if strings.Contains(img.Name, ":") {
			t.Errorf("UpstreamImages[%d] Name = %q must not contain ':' (tag goes in Tag)",
				i, img.Name)
		}
		// Catalog should not list the same image:tag twice.
		ref := img.FullRef()
		if seen[ref] {
			t.Errorf("UpstreamImages[%d]: duplicate image ref %q", i, ref)
		}
		seen[ref] = true
	}
}
