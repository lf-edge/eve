// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cas

import (
	"fmt"
	"io"
	"os"

	"github.com/lf-edge/edge-containers/pkg/registry"
	"github.com/sirupsen/logrus"
)

// HasExtensionDisk checks whether the given OCI image reference in CAS
// has an Extension disk (org.lfedge.eci.artifact.disk-0 label).
// Uses the same registry.Puller mechanism as WriteToPartition so it works
// with Docker labels (set by linuxkit), not just OCI layer annotations.
//
// Returns true if the image has an additional disk, false if monolithic.
func HasExtensionDisk(casClient CAS, reference string) (bool, error) {
	puller := registry.Puller{
		Image: reference,
	}

	ctrdCtx, done := casClient.CtrNewUserServicesCtx()
	defer done()

	resolver, err := casClient.Resolver(ctrdCtx)
	if err != nil {
		return false, fmt.Errorf("HasExtensionDisk: failed to get CAS resolver: %w", err)
	}

	// Pull with a nil Disks writer — the puller reads the config to check
	// for disk annotations. If disk-0 label exists, it maps to Disks[0].
	// We use a probe writer that just records whether anything was written.
	probe := &writeProbe{}
	target := &registry.FilesTarget{
		Disks: []io.Writer{probe},
	}

	if _, _, err := puller.Pull(target, 0, false, io.Discard, resolver); err != nil {
		return false, fmt.Errorf("HasExtensionDisk: pull probe failed for %s: %w", reference, err)
	}

	return probe.written, nil
}

// ExtractExtensionDisk extracts the Extension disk (disk-0) from the given
// OCI image reference in CAS and writes it to the specified path.
// Uses the same registry.Puller approach as WriteToPartition.
//
// Returns nil if the image has no Extension disk (monolithic image).
func ExtractExtensionDisk(casClient CAS, reference, targetPath string) error {
	puller := registry.Puller{
		Image: reference,
	}

	ctrdCtx, done := casClient.CtrNewUserServicesCtx()
	defer done()

	resolver, err := casClient.Resolver(ctrdCtx)
	if err != nil {
		return fmt.Errorf("ExtractExtensionDisk: failed to get CAS resolver: %w", err)
	}

	// Write to a temp file, then atomically rename
	tmpPath := targetPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("ExtractExtensionDisk: failed to create %s: %w", tmpPath, err)
	}

	target := &registry.FilesTarget{
		Disks: []io.Writer{f},
	}

	_, _, err = puller.Pull(target, 0, false, io.Discard, resolver)
	f.Close()
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("ExtractExtensionDisk: pull failed for %s: %w", reference, err)
	}

	// Check if anything was written (monolithic images have no disk-0)
	info, err := os.Stat(tmpPath)
	if err != nil || info.Size() == 0 {
		os.Remove(tmpPath)
		logrus.Infof("ExtractExtensionDisk: no Extension disk in %s (monolithic image)", reference)
		return nil
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("ExtractExtensionDisk: failed to rename %s to %s: %w", tmpPath, targetPath, err)
	}

	logrus.Infof("ExtractExtensionDisk: wrote Extension (%d bytes) to %s", info.Size(), targetPath)
	return nil
}

// writeProbe is a minimal writer that just records whether Write was called.
type writeProbe struct {
	written bool
}

func (w *writeProbe) Write(p []byte) (int, error) {
	if len(p) > 0 {
		w.written = true
	}
	return len(p), nil
}
