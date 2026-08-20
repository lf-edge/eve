// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	ctrdimages "github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
)

// gcRefLabels builds the containerd.io/gc.ref.content.* labels naming a
// manifest's children (config + layers) so the GC keeps the whole image
// graph reachable from the image record.
func gcRefLabels(children []ocispec.Descriptor) map[string]string {
	labels := make(map[string]string, len(children))
	for i, c := range children {
		labels[fmt.Sprintf("containerd.io/gc.ref.content.%d", i)] = c.Digest.String()
	}
	return labels
}

// externalBootLayoutRef is the name the payload build used for the
// EVE-authored external-boot-image while it still baked one. The device
// assembles that image itself now (bootimage.go), and keeps the name as
// the mkfs UUID namespace so it reproduces the same bytes.
const externalBootLayoutRef = "eve-external-boot-image"

// erofsSnapshotter is the snapshotter whose snapshots kube-init places
// the payload's pre-built layers into. Must match snapshotter in
// pkg/kube/config-k3s.toml.
const erofsSnapshotter = "erofs"

// registerLayout registers every image in the OCI layout into the k8s.io
// containerd namespace: content refs (metadata-only when the blobs were
// staged into the store and the sharing policy is "shared"; a correct
// copy otherwise) plus image records named with the real registry refs.
// It also places each image's layers as erofs snapshots and assembles
// the external-boot-image, which runs mkfs.erofs. Best-effort per image:
// one image's failure leaves the rest registered.
func registerLayout(ctx context.Context, socket, layoutDir, listPath, externalBootRef string) error {
	imgs, err := parseLayout(layoutDir)
	if err != nil {
		return fmt.Errorf("parse layout: %w", err)
	}
	refMap, err := loadRefMap(listPath)
	if err != nil {
		return fmt.Errorf("load ref map: %w", err)
	}

	client, err := containerd.New(socket)
	if err != nil {
		return fmt.Errorf("containerd client: %w", err)
	}
	ctx = namespaces.WithNamespace(ctx, kubectlx.K8sContainerdNamespace)

	// Probe reachability once up front: a dead or not-yet-listening socket
	// would otherwise fail every image's first RPC individually, producing
	// a wall of per-image warnings instead of one clear setup error.
	if serving, err := client.IsServing(ctx); err != nil || !serving {
		_ = client.Close()
		if err == nil {
			err = fmt.Errorf("health check reports not serving")
		}
		return fmt.Errorf("containerd not reachable: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Hold a lease across the whole import so each blob is GC-protected the
	// moment WriteBlob records it (the shared short-circuit adds leased
	// content), and stays protected until every image record is created and
	// references it. Without this, containerd's GC reaps freshly written but
	// not-yet-referenced content mid-import.
	ctx, done, err := client.WithLease(ctx)
	if err != nil {
		return fmt.Errorf("create lease: %w", err)
	}
	defer func() { _ = done(ctx) }()

	cs := client.ContentStore()
	is := client.ImageService()
	sn := client.SnapshotService(erofsSnapshotter)

	// contentStoreBlobs duplicates `root` from pkg/kube/config-k3s.toml. If
	// that root ever moves, staging would write symlinks into a directory
	// nothing reads and every blob would be copied instead -- correct, but
	// silently several GB slower. Say so rather than letting it pass.
	if _, err := os.Stat(contentStoreBlobs); err != nil {
		log.Printf("WARNING: content store %s not found (%v); images will be "+
			"copied instead of staged -- has containerd's root moved in config-k3s.toml?",
			contentStoreBlobs, err)
	}

	// The external-boot-image is built here rather than shipped in the
	// payload: its two files come from the running rootfs, so the image
	// matches the kernel this device actually boots (bootimage.go).
	if externalBootRef != "" {
		if err := registerBootImage(ctx, client, externalBootRef); err != nil {
			log.Printf("WARNING: external-boot-image: %v; container-as-VM app "+
				"instances will not start (virt-launcher stays in ErrImageNeverPull)", err)
		}
	}

	importStart := time.Now()
	var registered, staged, unpacked, failed int
	var stageTotal time.Duration
	claimed := make(map[string]bool, len(imgs))
	for _, img := range imgs {
		name := refMap[img.RefName]
		if name == "" {
			log.Printf("WARNING: no name mapping for %q, skipping", img.RefName)
			continue
		}
		claimed[name] = true
		if err := registerOne(ctx, cs, is, layoutDir, img, name); err != nil {
			log.Printf("WARNING: register %s: %v", name, err)
			continue
		}
		registered++
		// Make the layers available as erofs snapshots now, so the deploy
		// waves find one ready at CreateContainer instead of unpacking
		// under a CPU-constrained node past the CreateContainer deadline.
		// The layers are already erofs images inside the payload, so this
		// only writes snapshot metadata and a symlink per layer -- see
		// placeLayers. Best-effort: on any failure fall back to
		// containerd's own unpack, which copies the blobs but works.
		t0 := time.Now()
		copied := false
		if perr := placeLayers(ctx, sn, cs, layoutDir, img); perr != nil {
			log.Printf("WARNING: place snapshots for %s: %v; falling back to unpack", name, perr)
			uerr := unpackImage(ctx, client, name)
			if uerr != nil {
				// An image record with no snapshot is worse than no
				// record: kubelet sees the image as present, never
				// pulls, and every pod using it dies at
				// CreateContainer. Dropping the record restores the
				// pull fallback this whole path is predicated on.
				log.Printf("ERROR: %s has no snapshot (place: %v; unpack: %v); "+
					"removing the image record so kubelet re-pulls it", name, perr, uerr)
				if derr := is.Delete(ctx, name); derr != nil {
					log.Printf("ERROR: delete %s: %v; pods using it will fail at "+
						"CreateContainer", name, derr)
				}
				registered--
				failed++
				continue
			}
			unpacked++
			copied = true
		}
		d := time.Since(t0)
		stageTotal += d
		staged++
		how := "placed"
		if copied {
			how = "unpacked (copied)"
		}
		log.Printf("kube-images: %s %s for %s in %s (%d/%d)",
			how, name, erofsSnapshotter, d.Round(time.Millisecond), staged, len(imgs))
	}

	// A catalog entry with no image in the payload is a build-side
	// mistake that is otherwise invisible here: the device simply never
	// mentions it, and it resurfaces as a slow or impossible network pull
	// on a constrained node.
	for _, name := range refMap {
		if !claimed[name] {
			log.Printf("ERROR: %s is in the catalog but not in the payload; "+
				"kubelet will have to pull it", name)
		}
	}

	logf := log.Printf
	if failed > 0 {
		logf("ERROR: %d image(s) ended up with no snapshot; their pods depend on a "+
			"network pull", failed)
	}
	logf("kube-images: registerLayout done: %d registered, %d with snapshots "+
		"(%d needed a copying unpack), %d failed, stage-time %s, wall %s",
		registered, staged, unpacked, failed, stageTotal.Round(time.Second),
		time.Since(importStart).Round(time.Second))
	return nil
}

// unpackImage falls back to containerd's own unpack, which copies the
// layers into snapshots instead of pointing at them.
func unpackImage(ctx context.Context, client *containerd.Client, name string) error {
	img, err := client.GetImage(ctx, name)
	if err != nil {
		return fmt.Errorf("get image: %w", err)
	}
	if err := img.Unpack(ctx, erofsSnapshotter); err != nil {
		return fmt.Errorf("unpack: %w", err)
	}
	return nil
}

// blobKind reports how a blob (given by its digest hex) is materialised
// in the containerd content store on disk: "symlink" (staged, zero-copy),
// "regular" (copied), or "absent" — used for the per-image zero-copy tally.
func blobKind(hex string) string {
	fi, err := os.Lstat(filepath.Join(contentStoreBlobs, hex))
	if err != nil {
		return "absent"
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "symlink"
	}
	return "regular"
}

func registerOne(ctx context.Context, cs content.Store, is ctrdimages.Store,
	layoutDir string, img layoutImage, name string) error {
	var zerocopy, copied int
	for _, b := range img.Blobs {
		// Stage this blob into the content store right before writing it, so
		// its symlink exists for at most one WriteBlob before it becomes
		// referenced — too short a window for GC to reap it.
		src := blobPath(layoutDir, b)
		dst := filepath.Join(contentStoreBlobs, b.Digest.Encoded())
		if _, lerr := linkBlob(src, dst); lerr != nil {
			log.Printf("WARNING: stage %s %s: %v; this blob will be copied to "+
				"/persist instead of staged", name, b.Digest, lerr)
		}
		f, err := os.Open(src)
		if err != nil {
			return fmt.Errorf("open blob %s: %w", b.Digest, err)
		}
		// WriteBlob short-circuits to metadata-only when the staged symlink
		// resolves in the backend store (shared policy); otherwise it copies
		// from f. Either way correct.
		writeErr := content.WriteBlob(ctx, cs, "kube-images-"+b.Digest.String(), f, b)
		_ = f.Close()
		if writeErr != nil {
			return fmt.Errorf("write blob %s: %w", b.Digest, writeErr)
		}
		// symlink still present => zero-copy; regular file => copied.
		if blobKind(b.Digest.Encoded()) == "symlink" {
			zerocopy++
		} else {
			copied++
		}
	}
	// The manifest carries containerd.io/gc.ref.content.* labels naming its
	// config + layers. Without them GC can't see the manifest's children and
	// reaps every config/layer once our lease releases, leaving image records
	// whose content is incomplete.
	//
	// Set with an explicit Update rather than as WriteBlob options: WriteBlob
	// only passes its options down to Commit, and returns early without
	// calling it when the digest is already recorded in the metadata store --
	// which is the case for any blob already registered by an earlier image.
	// An Update applies either way and is idempotent.
	labels := gcRefLabels(img.Blobs[1:])
	fieldpaths := make([]string, 0, len(labels))
	for k := range labels {
		fieldpaths = append(fieldpaths, "labels."+k)
	}
	if _, err := cs.Update(ctx, content.Info{
		Digest: img.Manifest.Digest,
		Labels: labels,
	}, fieldpaths...); err != nil {
		return fmt.Errorf("label manifest with content refs: %w", err)
	}

	if err := putImage(ctx, is, name, img.Manifest); err != nil {
		return err
	}
	log.Printf("kube-images: registered %s (%d blobs, %d zero-copy, %d copied)",
		name, len(img.Blobs), zerocopy, copied)
	return nil
}

// putImage creates the image record for name, or repoints an existing
// record at target. The update path is what makes re-tagging safe: the
// content store lives on /persist and survives upgrades, so a stable
// alias like :latest already exists pointing at the previous release,
// and a plain Create would fail with AlreadyExists (the equivalent of
// `ctr image tag --force`).
func putImage(ctx context.Context, is ctrdimages.Store, name string, target ocispec.Descriptor) error {
	image := ctrdimages.Image{Name: name, Target: target}
	if _, err := is.Create(ctx, image); err != nil {
		if !errdefs.IsAlreadyExists(err) {
			return fmt.Errorf("create image: %w", err)
		}
		// Already exists -> update to point at our manifest (idempotent).
		if _, uerr := is.Update(ctx, image); uerr != nil {
			return fmt.Errorf("create/update image: create=%w update=%w", err, uerr)
		}
	}
	return nil
}
