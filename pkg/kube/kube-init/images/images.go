// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package images imports pre-packaged container image tarballs into
// the user-side containerd that k3s' kubelet consumes. Two flavours:
//
//   - The external-boot-image, built on the device from the kernel
//     and initrd in the running rootfs and tagged with the running EVE
//     release, so KubeVirt can reference a stable image:tag across
//     upgrades.
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
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	"github.com/lf-edge/eve/pkg/kube/kube-init/versions"
)

const (
	// BootKernel and BootInitrd are the host rootfs's kernel and the
	// initrd of the VMs container apps run in, seen through the
	// /:/hostfs bind in pkg/kube/build.yml. They form the
	// external-boot-image, from which KubeVirt boots container apps.
	BootKernel = "/hostfs/boot/kernel"
	BootInitrd = "/hostfs/boot/runx-initrd"

	// ExternalBootImageName is the fully-qualified image name
	// kubelet pod specs reference, tagged with the running EVE
	// release and :latest.
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
	{Tarball: "/images/system-upgrade-controller.tar", Name: "docker.io/rancher/system-upgrade-controller", Tag: versions.SystemUpgradeController},
	{Tarball: "/images/descheduler.tar", Name: "registry.k8s.io/descheduler/descheduler", Tag: versions.Descheduler},

	// CNI multiplexer.
	{Tarball: "/images/multus-cni.tar", Name: "ghcr.io/k8snetworkplumbingwg/multus-cni", Tag: versions.Multus},

	// alpine — SUC Plan's upgrade-container image. Tiny (~8 MB);
	// the local copy saves a pull round-trip per upgrade Plan.
	{Tarball: "/images/alpine.tar", Name: "docker.io/library/alpine", Tag: versions.Alpine},

	// KubeVirt (5 images — operator + the 4 pods it spawns).
	{Tarball: "/images/virt-operator.tar", Name: "quay.io/kubevirt/virt-operator", Tag: versions.KubeVirt},
	{Tarball: "/images/virt-api.tar", Name: "quay.io/kubevirt/virt-api", Tag: versions.KubeVirt},
	{Tarball: "/images/virt-controller.tar", Name: "quay.io/kubevirt/virt-controller", Tag: versions.KubeVirt},
	{Tarball: "/images/virt-handler.tar", Name: "quay.io/kubevirt/virt-handler", Tag: versions.KubeVirt},
	{Tarball: "/images/virt-launcher.tar", Name: "quay.io/kubevirt/virt-launcher", Tag: versions.KubeVirt},

	// CDI (7 images — operator + the 6 pods it spawns).
	{Tarball: "/images/cdi-operator.tar", Name: "quay.io/kubevirt/cdi-operator", Tag: versions.CDI},
	{Tarball: "/images/cdi-apiserver.tar", Name: "quay.io/kubevirt/cdi-apiserver", Tag: versions.CDI},
	{Tarball: "/images/cdi-controller.tar", Name: "quay.io/kubevirt/cdi-controller", Tag: versions.CDI},
	{Tarball: "/images/cdi-importer.tar", Name: "quay.io/kubevirt/cdi-importer", Tag: versions.CDI},
	{Tarball: "/images/cdi-cloner.tar", Name: "quay.io/kubevirt/cdi-cloner", Tag: versions.CDI},
	{Tarball: "/images/cdi-uploadproxy.tar", Name: "quay.io/kubevirt/cdi-uploadproxy", Tag: versions.CDI},
	{Tarball: "/images/cdi-uploadserver.tar", Name: "quay.io/kubevirt/cdi-uploadserver", Tag: versions.CDI},

	// Longhorn + CSI sidecars (13 images).
	{Tarball: "/images/longhorn-manager.tar", Name: "docker.io/longhornio/longhorn-manager", Tag: versions.Longhorn},
	{Tarball: "/images/longhorn-engine.tar", Name: "docker.io/longhornio/longhorn-engine", Tag: versions.Longhorn},
	{Tarball: "/images/longhorn-instance-manager.tar", Name: "docker.io/longhornio/longhorn-instance-manager", Tag: versions.Longhorn},
	{Tarball: "/images/longhorn-share-manager.tar", Name: "docker.io/longhornio/longhorn-share-manager", Tag: versions.Longhorn},
	{Tarball: "/images/longhorn-ui.tar", Name: "docker.io/longhornio/longhorn-ui", Tag: versions.Longhorn},
	{Tarball: "/images/backing-image-manager.tar", Name: "docker.io/longhornio/backing-image-manager", Tag: versions.Longhorn},
	{Tarball: "/images/support-bundle-kit.tar", Name: "docker.io/longhornio/support-bundle-kit", Tag: versions.SupportBundleKit},
	{Tarball: "/images/csi-attacher.tar", Name: "docker.io/longhornio/csi-attacher", Tag: versions.CSIAttacher},
	{Tarball: "/images/csi-provisioner.tar", Name: "docker.io/longhornio/csi-provisioner", Tag: versions.CSIProvisioner},
	{Tarball: "/images/csi-node-driver-registrar.tar", Name: "docker.io/longhornio/csi-node-driver-registrar", Tag: versions.CSINodeDriverRegistrar},
	{Tarball: "/images/csi-resizer.tar", Name: "docker.io/longhornio/csi-resizer", Tag: versions.CSIResizer},
	{Tarball: "/images/csi-snapshotter.tar", Name: "docker.io/longhornio/csi-snapshotter", Tag: versions.CSISnapshotter},
	{Tarball: "/images/livenessprobe.tar", Name: "docker.io/longhornio/livenessprobe", Tag: versions.CSILivenessProbe},
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

	// Open one containerd client for the whole batch; dozens of
	// per-image dials against the same socket were pure overhead.
	cc, err := kubectlx.NewContainerd(ctx, state.ContainerdSocket)
	if err != nil {
		log.Printf("WARNING: containerd client: %v (skipping image import phase)", err)
		return nil
	}
	defer cc.Close()

	if installKubevirt {
		if err := EnsureExternalBootImage(ctx, cc, eveRelease); err != nil {
			log.Printf("WARNING: external-boot-image build failed: %v", err)
		}
		cleanupOldImages(ctx, cc, ExternalBootImageName, eveRelease)
	}

	for _, img := range UpstreamImages {
		if err := importUpstreamImageWith(ctx, cc, img.Tarball, img.Name, img.Tag); err != nil {
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
	cc, err := kubectlx.NewContainerd(ctx, state.ContainerdSocket)
	if err != nil {
		return fmt.Errorf("containerd client: %w", err)
	}
	defer cc.Close()
	return importUpstreamImageWith(ctx, cc, tarball, imageName, tag)
}

// importUpstreamImageWith is the per-image body of ImportUpstreamImage
// against a caller-owned containerd client. ImportAll uses this
// directly so the whole batch shares one dial.
func importUpstreamImageWith(ctx context.Context, cc *kubectlx.ContainerdClient,
	tarball, imageName, tag string,
) error {
	fullRef := imageName + ":" + tag
	exists, err := cc.ImageExists(ctx, fullRef)
	if err != nil {
		log.Printf("warning: image existence check %s failed: %v", fullRef, err)
	}
	if exists {
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
	if _, err := cc.ImportImage(ctx, tarball); err != nil {
		return fmt.Errorf("import %s: %w", tarball, err)
	}
	log.Printf("successfully imported upstream image %s", fullRef)
	return nil
}

// EnsureExternalBootImage makes ExternalBootImageName:<eveRelease>
// and :latest name an image built from BootKernel and BootInitrd. It
// does nothing when the :<eveRelease> tag exists, so the image is
// built once per EVE release; distinct builds have distinct release
// strings. Missing inputs are a logged no-op.
func EnsureExternalBootImage(ctx context.Context, cc *kubectlx.ContainerdClient,
	eveRelease string,
) error {
	fullImageName := ExternalBootImageName + ":" + eveRelease
	exists, err := cc.ImageExists(ctx, fullImageName)
	if err != nil {
		return fmt.Errorf("check %s: %w", fullImageName, err)
	}
	if exists {
		return nil
	}
	for _, f := range bootFiles {
		if _, err := os.Stat(f.src); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				log.Printf("%s not found, skipping external-boot-image", f.src)
				return nil
			}
			return fmt.Errorf("stat %s: %w", f.src, err)
		}
	}

	pr, pw := io.Pipe()
	go func() {
		_, err := writeBootImageArchive(pw, bootFiles, fullImageName)
		pw.CloseWithError(err)
	}()
	_, err = cc.ImportImageFrom(ctx, pr)
	pr.CloseWithError(err)
	if err != nil {
		return fmt.Errorf("import external-boot-image: %w", err)
	}
	log.Printf("built external-boot-image %s", fullImageName)
	// The image store on /persist survives upgrades, so :latest
	// already points at the previous release; TagImage overwrites it.
	latestRef := ExternalBootImageName + ":latest"
	if err := cc.TagImage(ctx, fullImageName, latestRef); err != nil {
		return fmt.Errorf("re-tag %s -> %s: %w", fullImageName, latestRef, err)
	}
	return nil
}

// cleanupOldImages lists every image whose name starts with baseName
// in containerd's k8s.io namespace and removes the entries that
// don't match the current tag. Prevents stale EVE-authored images
// from accumulating across upgrades. Best-effort: per-remove
// failures are warnings.
func cleanupOldImages(ctx context.Context, cc *kubectlx.ContainerdClient,
	baseName, currentTag string,
) {
	log.Printf("cleaning up old images for %s, keeping tag: %s", baseName, currentTag)
	refs, err := cc.ListImages(ctx)
	if err != nil {
		log.Printf("WARNING: failed to list images for cleanup: %v", err)
		return
	}
	currentImage := baseName + ":" + currentTag
	latestImage := baseName + ":latest"
	prefix := baseName + ":"
	for _, ref := range refs {
		if ref == "" || !strings.HasPrefix(ref, prefix) ||
			ref == currentImage || ref == latestImage {
			continue
		}
		log.Printf("removing old image: %s", ref)
		if err := cc.DeleteImage(ctx, ref); err != nil {
			log.Printf("WARNING: failed to remove old image %s: %v", ref, err)
		}
	}
	log.Printf("old image cleanup completed for %s", baseName)
}
