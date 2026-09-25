// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// layoutImage is one image resolved from the OCI layout index.
type layoutImage struct {
	RefName  string               // org.opencontainers.image.ref.name
	Manifest ocispec.Descriptor   // the platform image manifest
	Blobs    []ocispec.Descriptor // manifest + config + layers, to register
}

// parseLayout reads an OCI image layout and returns one entry per
// top-level index manifest, resolved to the running host's image manifest.
func parseLayout(layoutDir string) ([]layoutImage, error) {
	idx, err := readIndex(filepath.Join(layoutDir, "index.json"))
	if err != nil {
		return nil, err
	}
	var out []layoutImage
	for _, entry := range idx.Manifests {
		ref := entry.Annotations[ocispec.AnnotationRefName]
		manifestDesc, err := resolveToManifest(layoutDir, entry)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", ref, err)
		}
		man, err := readManifest(layoutDir, manifestDesc)
		if err != nil {
			return nil, fmt.Errorf("read manifest %s: %w", ref, err)
		}
		blobs := []ocispec.Descriptor{manifestDesc, man.Config}
		blobs = append(blobs, man.Layers...)
		out = append(out, layoutImage{RefName: ref, Manifest: manifestDesc, Blobs: blobs})
	}
	return out, nil
}

// resolveToManifest returns desc unchanged if it is an image manifest;
// if it is an index, it follows one level to the manifest matching the
// running host's architecture (linux/runtime.GOARCH).
func resolveToManifest(layoutDir string, desc ocispec.Descriptor) (ocispec.Descriptor, error) {
	switch desc.MediaType {
	case ocispec.MediaTypeImageManifest, "application/vnd.docker.distribution.manifest.v2+json":
		return desc, nil
	case ocispec.MediaTypeImageIndex, "application/vnd.docker.distribution.manifest.list.v2+json":
		idx, err := readIndexBlob(layoutDir, desc)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		for _, m := range idx.Manifests {
			if m.Platform != nil && m.Platform.OS == "linux" && m.Platform.Architecture == runtime.GOARCH {
				return m, nil
			}
		}
		return ocispec.Descriptor{}, fmt.Errorf("no linux/%s manifest in index %s", runtime.GOARCH, desc.Digest)
	default:
		return ocispec.Descriptor{}, fmt.Errorf("unexpected mediaType %q", desc.MediaType)
	}
}

func blobPath(layoutDir string, d ocispec.Descriptor) string {
	return filepath.Join(layoutDir, "blobs", d.Digest.Algorithm().String(), d.Digest.Encoded())
}

func readIndex(path string) (*ocispec.Index, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var idx ocispec.Index
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &idx, nil
}

func readIndexBlob(layoutDir string, d ocispec.Descriptor) (*ocispec.Index, error) {
	return readIndex(blobPath(layoutDir, d))
}

func readManifest(layoutDir string, d ocispec.Descriptor) (*ocispec.Manifest, error) {
	b, err := os.ReadFile(blobPath(layoutDir, d))
	if err != nil {
		return nil, err
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", d.Digest, err)
	}
	return &m, nil
}
