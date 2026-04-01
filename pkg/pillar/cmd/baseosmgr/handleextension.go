// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"fmt"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// WriteExtensionToPersist extracts the Extension Image (disk-0) from the OCI
// image in containerd CAS and writes it to the paired PERSIST file.
// The target filename is derived from the partition label:
// IMGA → ext-imga.img, IMGB → ext-imgb.img.
//
// Uses the same registry.Puller mechanism as WriteToPartition so it correctly
// reads Docker labels (org.lfedge.eci.artifact.disk-0) set by linuxkit.
//
// Returns nil if the OCI image has no Extension disk (monolithic image).
func WriteExtensionToPersist(ref, targetPartLabel string) error {
	targetPath, err := types.ExtensionImagePath(targetPartLabel)
	if err != nil {
		return fmt.Errorf("WriteExtensionToPersist: %w", err)
	}

	casClient, err := cas.NewCAS("containerd")
	if err != nil {
		return fmt.Errorf("WriteExtensionToPersist: failed to create CAS client: %w", err)
	}
	defer casClient.CloseClient()

	log.Noticef("WriteExtensionToPersist: extracting Extension from %s to %s", ref, targetPath)

	if err := cas.ExtractExtensionDisk(casClient, ref, targetPath); err != nil {
		return fmt.Errorf("WriteExtensionToPersist: %w", err)
	}

	if _, err := os.Stat(targetPath); err != nil {
		log.Noticef("WriteExtensionToPersist: no Extension disk in %s (monolithic image)", ref)
		return nil
	}

	log.Noticef("WriteExtensionToPersist: successfully wrote Extension to %s", targetPath)
	return nil
}

// CleanupUnusedExtension removes the Extension image file paired with the
// given partition label. Called when a partition transitions to "unused"
// state — the Extension is no longer needed and wastes persist space.
// Safe to call even if the file doesn't exist.
func CleanupUnusedExtension(partLabel string) {
	path, err := types.ExtensionImagePath(partLabel)
	if err != nil {
		log.Functionf("CleanupUnusedExtension: %v (ignoring)", err)
		return
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Noticef("CleanupUnusedExtension: %s does not exist, nothing to clean", path)
		return
	}
	if err := os.Remove(path); err != nil {
		log.Errorf("CleanupUnusedExtension: failed to remove %s: %v", path, err)
		return
	}
	log.Noticef("CleanupUnusedExtension: removed stale Extension %s (partition %s now unused)", path, partLabel)
}
