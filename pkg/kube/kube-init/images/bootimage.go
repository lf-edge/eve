// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	"github.com/google/uuid"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// The external-boot-image is two files pillar's kubevirt hypervisor
// references from every container-as-VM VMIRS, by the paths they take
// inside the image (/kernel and /runx-initrd). Both already exist in the
// running rootfs, which pkg/kube/build.yml binds at /hostfs -- so the
// device can assemble the image itself instead of the payload build
// baking in a kernel that may not be the one this rootfs boots.
const (
	hostRoot = "/hostfs"

	bootImageKernel  = hostRoot + "/boot/kernel"
	bootImageInitrd  = hostRoot + "/containers/services/xen-tools/lower/usr/lib/xen/boot/runx-initrd"
	bootImageWorkDir = "/run/kube-init"

	// erofsLayerMediaType selects containerd's native erofs differ path:
	// any media type ending in ".erofs" with no "+suffix" is placed as-is
	// instead of being run through mkfs (v2.1 differ_linux.go).
	erofsLayerMediaType = "application/vnd.oci.image.layer.v1.erofs"

	// bootImageFileMode makes the two files readable by the non-root user
	// KubeVirt runs container-disk as; bootImageRootMode keeps the layer
	// root traversable for it.
	bootImageFileMode = 0666
	bootImageRootMode = 0755
)

// bootImageSources are staged into the layer under these names because
// that is how the VMIRS spec addresses them.
var bootImageSources = map[string]string{
	"kernel":      bootImageKernel,
	"runx-initrd": bootImageInitrd,
}

// mkfsFunc builds an EROFS image of srcDir at out. Indirected so the
// assembly logic is testable without erofs-utils.
type mkfsFunc func(out, srcDir string) error

// mkfsErofsBootImage builds the layer. -U and -T pin the two sources of
// run-to-run variance (random UUID, build timestamp): with them an
// unchanged kernel yields an unchanged digest, which is what makes
// re-running on every boot free.
func mkfsErofsBootImage(out, srcDir string) error {
	u := uuid.NewSHA1(uuid.NameSpaceURL, []byte("erofs:"+externalBootLayoutRef))
	cmd := exec.Command("mkfs.erofs", "--quiet", "-Enoinline_data",
		"--force-uid=0", "--force-gid=0", "-U", u.String(), "-T", "0",
		out, srcDir)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.erofs: %w: %s", err, b)
	}
	return nil
}

// stageBootImage copies the sources into dir with modes KubeVirt can
// read. They are copied rather than linked because the originals live on
// the read-only rootfs at modes that would ride along on the inode
// (runx-initrd ships 0600 root).
func stageBootImage(dir string) error {
	if err := os.MkdirAll(dir, bootImageRootMode); err != nil {
		return err
	}
	// MkdirAll honours umask; the layer root must be traversable.
	if err := os.Chmod(dir, bootImageRootMode); err != nil {
		return err
	}
	for name, src := range bootImageSources {
		in, err := os.Open(src)
		if err != nil {
			return fmt.Errorf("open %s: %w", src, err)
		}
		out, err := os.OpenFile(filepath.Join(dir, name),
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC, bootImageFileMode)
		if err != nil {
			_ = in.Close()
			return err
		}
		_, cerr := io.Copy(out, in)
		_ = in.Close()
		if err := out.Close(); err != nil && cerr == nil {
			cerr = err
		}
		if cerr != nil {
			return fmt.Errorf("copy %s: %w", src, cerr)
		}
		if err := os.Chmod(filepath.Join(dir, name), bootImageFileMode); err != nil {
			return err
		}
	}
	return nil
}

// buildBootImageLayer stages the sources, builds the EROFS layer under
// workDir and returns its descriptor. The caller removes workDir.
func buildBootImageLayer(workDir string, mkfs mkfsFunc) (string, ocispec.Descriptor, error) {
	src := filepath.Join(workDir, "root")
	if err := stageBootImage(src); err != nil {
		return "", ocispec.Descriptor{}, err
	}
	out := filepath.Join(workDir, erofsLayerFile)
	if err := mkfs(out, src); err != nil {
		return "", ocispec.Descriptor{}, err
	}
	f, err := os.Open(out)
	if err != nil {
		return "", ocispec.Descriptor{}, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", ocispec.Descriptor{}, fmt.Errorf("digest layer: %w", err)
	}
	return out, ocispec.Descriptor{
		MediaType: erofsLayerMediaType,
		Digest:    digest.NewDigest(digest.SHA256, h),
		Size:      n,
	}, nil
}

// bootImageBlobs builds the config and manifest describing a single
// native-erofs layer. The config records the LAYER digest as its
// diff_id: containerd's native path returns the layer descriptor
// unchanged from Apply(), and that returned digest is what the unpacker
// compares against diff_ids.
func bootImageBlobs(layer ocispec.Descriptor) (cfg, man []byte, cfgDesc, manDesc ocispec.Descriptor, err error) {
	cfg, err = json.Marshal(ocispec.Image{
		Platform: ocispec.Platform{Architecture: runtime.GOARCH, OS: "linux"},
		RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{layer.Digest}},
	})
	if err != nil {
		return nil, nil, cfgDesc, manDesc, err
	}
	cfgDesc = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageConfig,
		Digest:    digest.FromBytes(cfg),
		Size:      int64(len(cfg)),
	}
	man, err = json.Marshal(ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    cfgDesc,
		Layers:    []ocispec.Descriptor{layer},
	})
	if err != nil {
		return nil, nil, cfgDesc, manDesc, err
	}
	manDesc = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromBytes(man),
		Size:      int64(len(man)),
	}
	return cfg, man, cfgDesc, manDesc, nil
}

// writeBlobFrom records one blob in the content store from r.
func writeBlobFrom(ctx context.Context, cs content.Store, desc ocispec.Descriptor, r io.Reader) error {
	if err := content.WriteBlob(ctx, cs, "ebi-"+desc.Digest.String(), r, desc); err != nil {
		return fmt.Errorf("write %s: %w", desc.Digest, err)
	}
	return nil
}

// registerBootImage assembles the external-boot-image from the running
// rootfs and makes it available under name, with its single layer
// already placed as an erofs snapshot.
//
// Deliberately unconditional: the build is deterministic, so an
// unchanged kernel produces the digest that is already there and every
// step below is an idempotent no-op (WriteBlob returns early, the
// snapshot Stat skips the placement, putImage repoints rather than
// fails). Detecting that up front would cost the same mkfs it would
// save -- 17 MB of input, well under a second.
func registerBootImage(ctx context.Context, client *containerd.Client, name string) error {
	if err := os.MkdirAll(bootImageWorkDir, 0755); err != nil {
		return err
	}
	workDir, err := os.MkdirTemp(bootImageWorkDir, "ebi-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	layerPath, layer, err := buildBootImageLayer(workDir, mkfsErofsBootImage)
	if err != nil {
		return err
	}
	cfg, man, cfgDesc, manDesc, err := bootImageBlobs(layer)
	if err != nil {
		return err
	}

	cs, is := client.ContentStore(), client.ImageService()
	f, err := os.Open(layerPath)
	if err != nil {
		return err
	}
	err = writeBlobFrom(ctx, cs, layer, f)
	_ = f.Close()
	if err != nil {
		return err
	}
	if err := writeBlobFrom(ctx, cs, cfgDesc, bytes.NewReader(cfg)); err != nil {
		return err
	}
	if err := writeBlobFrom(ctx, cs, manDesc, bytes.NewReader(man)); err != nil {
		return err
	}

	// The manifest's labels are what keep the graph reachable once our
	// lease drops: gc.ref.content.* for the config and layer blobs,
	// gc.ref.snapshot.<snapshotter> for the snapshot placed below.
	labels := gcRefLabels([]ocispec.Descriptor{cfgDesc, layer})
	// For a single-layer image the chainID is the layer's own diff_id.
	chainID := layer.Digest.String()
	sn := client.SnapshotService(erofsSnapshotter)
	var placeErr error
	if _, err := sn.Stat(ctx, chainID); err != nil {
		if !errdefs.IsNotFound(err) {
			log.Printf("WARNING: stat snapshot %s: %v; placing it again", chainID, err)
		}
		placeErr = placeOne(ctx, sn, chainID, "",
			filepath.Join(contentStoreBlobs, layer.Digest.Encoded()))
	}
	if placeErr == nil {
		labels[gcSnapshotRefLabel] = chainID
	}
	fieldpaths := make([]string, 0, len(labels))
	for k := range labels {
		fieldpaths = append(fieldpaths, "labels."+k)
	}
	if _, err := cs.Update(ctx, content.Info{Digest: manDesc.Digest, Labels: labels},
		fieldpaths...); err != nil {
		return fmt.Errorf("label manifest: %w", err)
	}

	if err := putImage(ctx, is, name, manDesc); err != nil {
		return err
	}
	// pillar's VMIRS hardcodes :latest with imagePullPolicy Never so the
	// reference survives a baseOS upgrade pruning the versioned tag
	// (lf-edge/eve#6100); registering only the versioned ref leaves
	// virt-launcher wedged in ErrImageNeverPull.
	latest := ExternalBootImageName + ":latest"
	if err := putImage(ctx, is, latest, manDesc); err != nil {
		return fmt.Errorf("alias %s: %w", latest, err)
	}

	if placeErr != nil {
		// Fall back to containerd's own unpack, which copies the layer
		// into a snapshot instead of pointing at it -- 17 MB, so the
		// warning matters more than the cost. Both records exist by now
		// because Unpack needs one; if it fails they have to go, or
		// virt-launcher finds the image present and fails at
		// CreateContainer instead of reporting ErrImageNeverPull.
		log.Printf("WARNING: place external-boot-image snapshot: %v; falling back to unpack",
			placeErr)
		if uerr := unpackImage(ctx, client, name); uerr != nil {
			for _, ref := range []string{name, latest} {
				if derr := is.Delete(ctx, ref); derr != nil {
					log.Printf("ERROR: delete %s: %v", ref, derr)
				}
			}
			return fmt.Errorf("no snapshot for %s (place: %v; unpack: %w)",
				name, placeErr, uerr)
		}
	}
	log.Printf("kube-images: assembled external-boot-image %s (layer %s, %d bytes)",
		name, layer.Digest, layer.Size)
	return nil
}
