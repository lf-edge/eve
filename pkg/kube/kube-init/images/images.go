// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package images makes the pre-packaged container images available to
// the k3s user-containerd that kubelet consumes, without a first-boot
// network pull and without copying gigabytes of layer blobs onto
// /persist.
//
// The images ship as a plain OCI layout in the eve-kube-images volume,
// which linuxkit unpacks into the rootfs at build time and overlay-mounts
// read-only at /images before any service starts. Nothing to mount here,
// and the blob paths live in the rootfs, so a symlink to one survives a
// reboot. At the IMPORTING phase kube-init:
//
//  1. stages the blobs into containerd's content store by symlink, so
//     registration is metadata-only while the symlink is honoured (a
//     correct copy otherwise);
//  2. registers each image under the registry ref kubelet's pod specs
//     use, places its layers as erofs snapshots, and assembles the
//     external-boot-image for the running release (bootimage.go) — that
//     one is not in the payload, being two files of the running rootfs.
package images

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

const (
	// KubeImagesDir is the OCI image layout of every pre-packaged
	// image, bound in by the linuxkit rootfs (kube-images:/images:ro).
	KubeImagesDir = "/images"

	// ExternalBootImageName is the image kube-init assembles for the
	// running release. It is registered under both the release tag and
	// :latest, and pillar's VMIRS references :latest (see
	// registerBootImage).
	ExternalBootImageName = "docker.io/lfedge/eve-external-boot-image"

	// contentStoreBlobs is the digest dir of the user-containerd
	// content store (root from pkg/kube/config-k3s.toml).
	contentStoreBlobs = "/persist/vault/containerd/io.containerd.content.v1.content/blobs/sha256"

	// catalogInLayout is the real-ref list shipped inside the layout.
	catalogInLayout = KubeImagesDir + "/upstream-images.list"
)

// ImportAll makes the pre-packaged images available to the k3s user
// containerd with no blob copy to /persist.
//
// Per-image failures stay best-effort inside registerLayout, which leaves
// kubelet's network pull as the fallback for that image. A setup failure
// (no layout, containerd unreachable) is returned: the caller's state
// machine retries IMPORTING and records the error for the status socket,
// and reporting RUNNING with no images registered is worse than retrying.
func ImportAll(ctx context.Context, eveRelease string, installKubevirt bool) error {
	log.Printf("importing images (release=%s, kubevirt=%v)", eveRelease, installKubevirt)

	externalBootRef := ""
	if installKubevirt {
		externalBootRef = ExternalBootImageName + ":" + eveRelease
	}
	if err := registerLayout(ctx, state.ContainerdSocket, KubeImagesDir, catalogInLayout, externalBootRef); err != nil {
		return fmt.Errorf("register kube-images: %w", err)
	}
	log.Printf("image import phase complete")
	return nil
}

// linkBlob symlinks a single content-store blob at dst to src in the
// read-only payload, unless dst already exists. Symlink because src is on
// another filesystem (hardlink impossible) and a copy is exactly what we
// avoid. content.Store.Info os.Stats the path
// (following the link), which enables the shared-mode zero-copy
// short-circuit. Returns true if a new link was created.
//
// Staged per-blob immediately before WriteBlob: a symlink no registered
// image references yet is unreferenced content that containerd's GC
// reaps, so a bulk pre-stage would lose whatever registration has not
// reached.
func linkBlob(src, dst string) (linked bool, err error) {
	if _, statErr := os.Lstat(dst); statErr == nil {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}
	if err := os.Symlink(src, dst); err != nil {
		return false, fmt.Errorf("symlink %s -> %s: %w", dst, src, err)
	}
	return true, nil
}

// isMounted reports whether mountpoint appears in /proc/mounts.
func isMounted(mountpoint string) (bool, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false, fmt.Errorf("read /proc/mounts: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == mountpoint {
			return true, nil
		}
	}
	return false, nil
}
