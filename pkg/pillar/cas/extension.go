// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"runtime"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/lf-edge/edge-containers/pkg/registry"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
)

// FindAdditionalDiskBlob walks the OCI manifest tree for the given image
// reference and returns the digest of the first layer with the
// "disk-additional" role annotation. Returns ("", nil) if no such layer
// exists (monolithic image). Returns an error only on CAS read failures.
func FindAdditionalDiskBlob(casClient CAS, reference string) (string, error) {
	imageHash, err := casClient.GetImageHash(reference)
	if err != nil {
		return "", fmt.Errorf("FindAdditionalDiskBlob: failed to get image hash for %s: %w", reference, err)
	}

	ctrdCtx, done := casClient.CtrNewUserServicesCtx()
	defer done()

	// Read the top-level blob (could be an index or a manifest)
	reader, err := casClient.ReadBlob(ctrdCtx, imageHash)
	if err != nil {
		return "", fmt.Errorf("FindAdditionalDiskBlob: failed to read blob %s: %w", imageHash, err)
	}
	blobData, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("FindAdditionalDiskBlob: failed to read blob data %s: %w", imageHash, err)
	}

	// Try to parse as OCI index first (multi-arch image)
	var manifest *v1.Manifest
	var index ocispec.Index
	if err := json.Unmarshal(blobData, &index); err == nil && index.Manifests != nil {
		// It's an index — find manifest for current architecture
		manifestHash := ""
		for _, m := range index.Manifests {
			if m.Platform != nil && m.Platform.Architecture == runtime.GOARCH {
				manifestHash = m.Digest.String()
				break
			}
		}
		if manifestHash == "" {
			return "", fmt.Errorf("FindAdditionalDiskBlob: no manifest for arch %s in index", runtime.GOARCH)
		}
		ctrdCtx2, done2 := casClient.CtrNewUserServicesCtx()
		defer done2()
		mReader, err := casClient.ReadBlob(ctrdCtx2, manifestHash)
		if err != nil {
			return "", fmt.Errorf("FindAdditionalDiskBlob: failed to read manifest %s: %w", manifestHash, err)
		}
		manifest, err = v1.ParseManifest(mReader)
		if err != nil {
			return "", fmt.Errorf("FindAdditionalDiskBlob: failed to parse manifest %s: %w", manifestHash, err)
		}
	} else {
		// Try to parse as direct manifest (single-arch image)
		parsed, err := v1.ParseManifest(bytes.NewReader(blobData))
		if err != nil {
			return "", fmt.Errorf("FindAdditionalDiskBlob: blob %s is neither index nor manifest: %w", imageHash, err)
		}
		manifest = parsed
	}

	// Walk layers looking for disk-additional role
	for _, layer := range manifest.Layers {
		role, ok := layer.Annotations[registry.AnnotationRole]
		if ok && role == registry.RoleAdditionalDisk {
			logrus.Infof("FindAdditionalDiskBlob: found disk-additional layer %s", layer.Digest.String())
			return layer.Digest.String(), nil
		}
	}

	// No disk-additional layer — monolithic image
	logrus.Infof("FindAdditionalDiskBlob: no disk-additional layer in %s (monolithic image)", reference)
	return "", nil
}
