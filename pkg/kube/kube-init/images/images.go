// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package images imports pre-packaged container image tarballs into
// the user-side containerd that k3s' kubelet consumes. Two flavours:
//
//   - The EVE-authored external-boot-image, which gets re-tagged to
//     match the running EVE release so KubeVirt can reference a
//     stable image:tag across upgrades.
//   - The catalog of upstream component images (KubeVirt, CDI,
//     Longhorn, Multus, SUC, etc.) shipped as exported tarballs at
//     their pinned versions. Importing locally avoids first-boot
//     internet pulls.
//
// All imports are idempotent and best-effort: a missing tarball or
// failed import is logged and the daemon continues. kubelet falls
// back to its default pull behaviour for any image we couldn't pre-
// load.
package images

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
)

const (
	// ExternalBootImageTar is the on-disk path of the EVE-authored
	// external-boot-image tarball. KubeVirt's virt-handler downloads
	// the kernel/initrd from this image to boot guest VMs.
	ExternalBootImageTar = "/images/external-boot-image.tar"

	// ExternalBootImageName is the fully-qualified image name
	// kubelet pod specs reference (re-tagged to the running EVE
	// release at import time).
	ExternalBootImageName = "docker.io/lfedge/eve-external-boot-image"
)

// UpstreamImage describes one pre-packaged upstream image tarball.
//
// Coupling rules: every entry in UpstreamImages must have a matching
// Makefile .tar rule (see upstream-image-tar-rule) and the same
// image:tag must also appear in whichever YAML manifest / Helm
// values / operator default actually references it from a pod spec.
// A version bump is a three-site change in one commit.
type UpstreamImage struct {
	// Tarball is the on-disk path of the exported tarball (mounted
	// read-only from the eve-kube-images volume into /images/).
	Tarball string
	// Name is the fully-qualified image name (registry/repo) that
	// kubelet's pod spec references — without the :<tag> suffix.
	Name string
	// Tag is the pinned image version. Together with Name this forms
	// the :<tag> suffix that kubelet will resolve.
	Tag string
}

// FullRef returns "Name:Tag" — the form kubelet + ctr expect.
func (u UpstreamImage) FullRef() string {
	return u.Name + ":" + u.Tag
}

// UpstreamImages is the full catalog of pre-packaged upstream images
// walked by ImportAll at first boot. Kept as a flat slice so adding
// a new image is a one-line change; failures are per-image warnings,
// not fatal.
var UpstreamImages = []UpstreamImage{
	// k3s-stack controllers.
	{Tarball: "/images/system-upgrade-controller.tar", Name: "docker.io/rancher/system-upgrade-controller", Tag: "v0.19.2"},
	{Tarball: "/images/descheduler.tar", Name: "registry.k8s.io/descheduler/descheduler", Tag: "v0.29.0"},

	// CNI multiplexer.
	{Tarball: "/images/multus-cni.tar", Name: "ghcr.io/k8snetworkplumbingwg/multus-cni", Tag: "v3.9.3"},

	// alpine — SUC Plan's upgrade-container image. Tiny (~8 MB);
	// the local copy saves a pull round-trip per upgrade Plan.
	{Tarball: "/images/alpine.tar", Name: "docker.io/library/alpine", Tag: "3.21"},

	// KubeVirt v1.6.0 (5 images — operator + the 4 pods it spawns).
	{Tarball: "/images/virt-operator.tar", Name: "quay.io/kubevirt/virt-operator", Tag: "v1.6.0"},
	{Tarball: "/images/virt-api.tar", Name: "quay.io/kubevirt/virt-api", Tag: "v1.6.0"},
	{Tarball: "/images/virt-controller.tar", Name: "quay.io/kubevirt/virt-controller", Tag: "v1.6.0"},
	{Tarball: "/images/virt-handler.tar", Name: "quay.io/kubevirt/virt-handler", Tag: "v1.6.0"},
	{Tarball: "/images/virt-launcher.tar", Name: "quay.io/kubevirt/virt-launcher", Tag: "v1.6.0"},

	// CDI v1.57.1 (7 images — operator + the 6 pods it spawns).
	{Tarball: "/images/cdi-operator.tar", Name: "quay.io/kubevirt/cdi-operator", Tag: "v1.57.1"},
	{Tarball: "/images/cdi-apiserver.tar", Name: "quay.io/kubevirt/cdi-apiserver", Tag: "v1.57.1"},
	{Tarball: "/images/cdi-controller.tar", Name: "quay.io/kubevirt/cdi-controller", Tag: "v1.57.1"},
	{Tarball: "/images/cdi-importer.tar", Name: "quay.io/kubevirt/cdi-importer", Tag: "v1.57.1"},
	{Tarball: "/images/cdi-cloner.tar", Name: "quay.io/kubevirt/cdi-cloner", Tag: "v1.57.1"},
	{Tarball: "/images/cdi-uploadproxy.tar", Name: "quay.io/kubevirt/cdi-uploadproxy", Tag: "v1.57.1"},
	{Tarball: "/images/cdi-uploadserver.tar", Name: "quay.io/kubevirt/cdi-uploadserver", Tag: "v1.57.1"},

	// Longhorn v1.9.1 + CSI sidecars (13 images; CSI sidecars follow
	// their own release cadence, hence different tags).
	{Tarball: "/images/longhorn-manager.tar", Name: "docker.io/longhornio/longhorn-manager", Tag: "v1.9.1"},
	{Tarball: "/images/longhorn-engine.tar", Name: "docker.io/longhornio/longhorn-engine", Tag: "v1.9.1"},
	{Tarball: "/images/longhorn-instance-manager.tar", Name: "docker.io/longhornio/longhorn-instance-manager", Tag: "v1.9.1"},
	{Tarball: "/images/longhorn-share-manager.tar", Name: "docker.io/longhornio/longhorn-share-manager", Tag: "v1.9.1"},
	{Tarball: "/images/longhorn-ui.tar", Name: "docker.io/longhornio/longhorn-ui", Tag: "v1.9.1"},
	{Tarball: "/images/backing-image-manager.tar", Name: "docker.io/longhornio/backing-image-manager", Tag: "v1.9.1"},
	{Tarball: "/images/support-bundle-kit.tar", Name: "docker.io/longhornio/support-bundle-kit", Tag: "v0.0.61"},
	{Tarball: "/images/csi-attacher.tar", Name: "docker.io/longhornio/csi-attacher", Tag: "v4.9.0-20250709"},
	{Tarball: "/images/csi-provisioner.tar", Name: "docker.io/longhornio/csi-provisioner", Tag: "v5.3.0-20250709"},
	{Tarball: "/images/csi-node-driver-registrar.tar", Name: "docker.io/longhornio/csi-node-driver-registrar", Tag: "v2.14.0-20250709"},
	{Tarball: "/images/csi-resizer.tar", Name: "docker.io/longhornio/csi-resizer", Tag: "v1.14.0-20250709"},
	{Tarball: "/images/csi-snapshotter.tar", Name: "docker.io/longhornio/csi-snapshotter", Tag: "v8.3.0-20250709"},
	{Tarball: "/images/livenessprobe.tar", Name: "docker.io/longhornio/livenessprobe", Tag: "v2.16.0-20250709"},
}

// ImportAll orchestrates the per-boot image import phase: the EVE
// external-boot-image (only when KubeVirt is enabled) plus the full
// UpstreamImages catalog.
//
// Per-image failures are logged as warnings and not propagated:
// kubelet's pull-on-first-use behaviour is the fall-back contract.
// Returns nil unconditionally for the same reason — a "fatal" image
// import would block kube-init's progression on a transient I/O
// hiccup that kubelet would have recovered from anyway.
func ImportAll(ctx context.Context, eveRelease string, installKubevirt bool) error {
	log.Printf("importing images (release=%s, kubevirt=%v)", eveRelease, installKubevirt)

	if installKubevirt {
		if err := ImportExternalBootImage(ctx, eveRelease); err != nil {
			log.Printf("WARNING: external-boot-image import failed: %v", err)
		}
	}

	for _, img := range UpstreamImages {
		if err := ImportUpstreamImage(ctx, img.Tarball, img.Name, img.Tag); err != nil {
			log.Printf("WARNING: %s import failed: %v", img.FullRef(), err)
		}
	}

	log.Printf("image import phase complete")
	return nil
}

// ImportUpstreamImage imports a single upstream-tarball entry from
// the UpstreamImages catalog. Unlike EVE-authored images, upstream
// tarballs already carry the exact <imageName>:<tag> kubelet expects
// — there is no re-tag step.
//
// Idempotent: if the image is already present in containerd, this
// is a no-op. If the tarball is missing (minimal builds may omit
// some images), the function logs and returns nil — kubelet will
// pull the image from its registry on first use.
func ImportUpstreamImage(ctx context.Context, tarball, imageName, tag string) error {
	fullRef := imageName + ":" + tag
	if imageExists(fullRef) {
		return nil
	}
	if _, err := os.Stat(tarball); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("upstream image tarball %s not found, skipping (will pull on first use)",
				tarball)
			return nil
		}
		return fmt.Errorf("stat %s: %w", tarball, err)
	}
	log.Printf("importing upstream image %s from %s", fullRef, tarball)
	if _, err := kubectlx.CtrRunContext(ctx, "images", "import", tarball); err != nil {
		return fmt.Errorf("import %s: %w", tarball, err)
	}
	log.Printf("successfully imported upstream image %s", fullRef)
	return nil
}

// ImportExternalBootImage imports the external-boot-image tarball
// and re-tags it as ExternalBootImageName:<eveRelease>. After a
// successful import any prior :<release> tags are removed so the
// image set tracks the running EVE release.
//
// Missing tarball is a silent no-op — the install may have skipped
// KubeVirt artifacts deliberately.
func ImportExternalBootImage(ctx context.Context, eveRelease string) error {
	if _, err := os.Stat(ExternalBootImageTar); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("external-boot-image tarball not found at %s, skipping",
				ExternalBootImageTar)
			return nil
		}
		return fmt.Errorf("stat %s: %w", ExternalBootImageTar, err)
	}

	fullImageName := ExternalBootImageName + ":" + eveRelease
	if imageExists(fullImageName) {
		log.Printf("external-boot-image %s already imported", fullImageName)
		cleanupOldImages(ctx, ExternalBootImageName, eveRelease)
		return nil
	}
	if err := importImage(ctx, ExternalBootImageTar,
		ExternalBootImageName, eveRelease); err != nil {
		return fmt.Errorf("import external-boot-image: %w", err)
	}
	log.Printf("successfully imported external-boot-image as %s", fullImageName)
	cleanupOldImages(ctx, ExternalBootImageName, eveRelease)
	return nil
}

// importImage is the shared import-then-retag flow for EVE-authored
// images whose tarball-internal tag may not match the
// expectedName:expectedTag kubelet pod specs reference. Reads the
// tarball's manifest.json, imports via ctr, and re-tags if needed.
func importImage(ctx context.Context, tarball, expectedName, expectedTag string) error {
	tarballNameTag, err := getImageNameFromTarball(tarball)
	if err != nil {
		return fmt.Errorf("read image name from tarball %s: %w", tarball, err)
	}
	log.Printf("tarball %s contains image: %s", tarball, tarballNameTag)
	if _, err := kubectlx.CtrRunContext(ctx, "images", "import", tarball); err != nil {
		return fmt.Errorf("import %s: %w", tarball, err)
	}
	log.Printf("imported tarball %s into containerd", tarball)

	target := expectedName + ":" + expectedTag
	if tarballNameTag != "" && tarballNameTag != "null" && tarballNameTag != target {
		log.Printf("re-tagging %s -> %s", tarballNameTag, target)
		if _, err := kubectlx.CtrRunContext(ctx,
			"images", "tag", tarballNameTag, target); err != nil {
			return fmt.Errorf("tag %s -> %s: %w", tarballNameTag, target, err)
		}
	}
	return nil
}

// manifestJSON is the subset of Docker image manifest.json we parse.
type manifestJSON struct {
	RepoTags []string `json:"RepoTags"`
}

// getImageNameFromTarball returns the first RepoTags entry from
// manifest.json inside tarball. Runs `tar -xf <tarball> manifest.json
// -O` (stdout extraction) and parses the JSON in Go to avoid a jq
// runtime dependency.
func getImageNameFromTarball(tarball string) (string, error) {
	output, err := exec.Command("tar", "-xf", tarball, "manifest.json", "-O").Output()
	if err != nil {
		return "", fmt.Errorf("extract manifest.json from %s: %w", tarball, err)
	}
	return parseFirstRepoTag(output)
}

// parseFirstRepoTag is the pure half of getImageNameFromTarball,
// factored out for unit testing.
func parseFirstRepoTag(manifestBytes []byte) (string, error) {
	var manifests []manifestJSON
	if err := json.Unmarshal(manifestBytes, &manifests); err != nil {
		return "", fmt.Errorf("parse manifest.json: %w", err)
	}
	if len(manifests) == 0 || len(manifests[0].RepoTags) == 0 {
		return "", errors.New("manifest.json has no RepoTags")
	}
	return manifests[0].RepoTags[0], nil
}

// imageExists asks crictl whether the image is present in the
// k8s.io namespace kubelet consumes. crictl is preferred over ctr
// here because `ctr images list` does not filter to the kubelet
// namespace and would produce false positives.
func imageExists(imageName string) bool {
	_, err := kubectlx.CrictlRun("inspecti", imageName)
	return err == nil
}

// cleanupOldImages lists every image whose name starts with baseName
// in containerd and removes the entries that don't match the current
// tag. Prevents stale EVE-authored images from accumulating across
// upgrades. Best-effort: per-remove failures are warnings.
func cleanupOldImages(ctx context.Context, baseName, currentTag string) {
	log.Printf("cleaning up old images for %s, keeping tag: %s", baseName, currentTag)
	output, err := kubectlx.CtrRunContext(ctx, "images", "list", "-q")
	if err != nil {
		log.Printf("WARNING: failed to list images for cleanup: %v", err)
		return
	}
	currentImage := baseName + ":" + currentTag
	prefix := baseName + ":"
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, prefix) || line == currentImage {
			continue
		}
		log.Printf("removing old image: %s", line)
		if _, rmErr := kubectlx.CtrRunContext(ctx, "images", "rm", line); rmErr != nil {
			log.Printf("WARNING: failed to remove old image %s: %v", line, rmErr)
		}
	}
	log.Printf("old image cleanup completed for %s", baseName)
}
