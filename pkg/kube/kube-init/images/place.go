// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	// erofsLayerFile is the per-snapshot blob the erofs snapshotter
	// mounts as that layer's lower dir.
	erofsLayerFile = "layer.erofs"

	// erofsLayerMarker is written into every snapshot directory the
	// erofs snapshotter prepares. Its presence is how the differ
	// confirms a directory belongs to that snapshotter, and we use it
	// the same way before writing into one.
	erofsLayerMarker = ".erofslayer"

	// snapshotRefLabel names the chainID a prepared snapshot will be
	// committed as; set for parity with containerd's own unpacker.
	snapshotRefLabel = "containerd.io/snapshot.ref"

	// gcSnapshotRefLabel, set on an image's MANIFEST blob, is how
	// containerd's GC reaches the snapshots belonging to that image
	// (v2.1 core/metadata/gc.go follows this prefix). Without it the
	// snapshots placed here are unreferenced and get reaped.
	gcSnapshotRefLabel = "containerd.io/gc.ref.snapshot." + erofsSnapshotter
)

// placeLayers makes an image's layers available as erofs snapshots
// without writing their bytes anywhere.
//
// Unpacking would copy each blob into the snapshot directory; the
// payload is a read-only mount that outlives the boot, so the snapshot
// can point at it instead. Commit only converts an upperdir when
// layer.erofs is MISSING, so one we placed is mounted as-is. chainIDs
// come from the config's diff_ids exactly as the unpacker derives them,
// so the snapshots land under the names CRI looks up at
// CreateContainer.
func placeLayers(ctx context.Context, sn snapshots.Snapshotter, cs content.Store,
	layoutDir string, img layoutImage) error {
	man, err := readManifest(layoutDir, img.Manifest)
	if err != nil {
		return err
	}
	cfg, err := readImageConfig(layoutDir, man.Config)
	if err != nil {
		return err
	}
	if len(cfg.RootFS.DiffIDs) != len(man.Layers) {
		return fmt.Errorf("%d layers but %d diff_ids", len(man.Layers), len(cfg.RootFS.DiffIDs))
	}
	if len(man.Layers) == 0 {
		return fmt.Errorf("no layers")
	}

	chain := identity.ChainIDs(append([]digest.Digest{}, cfg.RootFS.DiffIDs...))
	var parent string
	for i, layer := range man.Layers {
		chainID := chain[i].String()
		if _, serr := sn.Stat(ctx, chainID); serr == nil {
			// Already placed by an earlier image (shared base layer) or
			// by a previous run: nothing to do, but it is still the
			// parent of the next layer.
			parent = chainID
			continue
		}
		if !isErofsLayer(layer.MediaType) {
			return fmt.Errorf("layer %d is %q, not a native erofs layer", i, layer.MediaType)
		}
		if err := placeOne(ctx, sn, chainID, parent, blobPath(layoutDir, layer)); err != nil {
			return fmt.Errorf("layer %d (%s): %w", i, layer.Digest, err)
		}
		parent = chainID
	}

	// Point the GC at the top of the chain before the caller's lease
	// expires, or every snapshot placed above is unreferenced.
	info := content.Info{
		Digest: img.Manifest.Digest,
		Labels: map[string]string{gcSnapshotRefLabel: parent},
	}
	if _, err := cs.Update(ctx, info, "labels."+gcSnapshotRefLabel); err != nil {
		return fmt.Errorf("label manifest with snapshot ref: %w", err)
	}
	return nil
}

// placeOne prepares one snapshot, points its layer file at blob and
// commits it under chainID. AlreadyExists from either Prepare or Commit
// means someone placed this chainID first and is reported as success.
func placeOne(ctx context.Context, sn snapshots.Snapshotter, chainID, parent, blob string) error {
	unique, err := uniquePart()
	if err != nil {
		return err
	}
	key := fmt.Sprintf(snapshots.UnpackKeyFormat, unique, chainID)
	mounts, err := sn.Prepare(ctx, key, parent,
		snapshots.WithLabels(map[string]string{snapshotRefLabel: chainID}))
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("prepare: %w", err)
	}
	abort := func() {
		if rerr := sn.Remove(ctx, key); rerr != nil && !errdefs.IsNotFound(rerr) {
			log.Printf("WARNING: cleanup snapshot %s: %v", key, rerr)
		}
	}
	dir, err := mountsToLayer(mounts)
	if err != nil {
		abort()
		return err
	}
	link := filepath.Join(dir, erofsLayerFile)
	if err := os.Symlink(blob, link); err != nil {
		abort()
		return fmt.Errorf("link layer blob: %w", err)
	}
	// Stat through the link before committing. Commit treats a missing
	// layer.erofs as "convert the upperdir", so a dangling link would
	// yield a valid-looking snapshot with an empty rootfs -- which fails
	// much later, as a container whose files are simply absent.
	if _, err := os.Stat(link); err != nil {
		abort()
		return fmt.Errorf("layer blob %s does not resolve: %w", blob, err)
	}
	if err := sn.Commit(ctx, chainID, key); err != nil {
		if errdefs.IsAlreadyExists(err) {
			// Someone committed this chainID first. Ours is now an
			// orphan: Commit consumes the key only on success, so
			// without this it accumulates one prepared snapshot per
			// call that loses the race.
			abort()
			return nil
		}
		abort()
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// mountsToLayer returns the snapshot directory that holds layer.erofs,
// mirroring containerd's internal erofsutils.MountsToLayer (which we
// cannot import).
//
// The LAST entry is the one describing the snapshot being prepared. That
// matters across containerd versions: v2.1 returns a single mount, while
// v2.2 returns one erofs mount per parent followed by the target, so
// keying off mounts[0] there would resolve to a PARENT's directory --
// whose layer.erofs already exists, so the symlink would fail and every
// multi-layer image would fall back to a copying unpack. A "mkfs/" type
// prefix (v2.2) describes the same source path.
//
// The .erofslayer marker confirms the directory really belongs to the
// erofs snapshotter before we write into it.
func mountsToLayer(mounts []mount.Mount) (string, error) {
	if len(mounts) == 0 {
		return "", fmt.Errorf("no mounts returned")
	}
	var dir string
	m := mounts[len(mounts)-1]
	mtype := strings.TrimPrefix(m.Type, "mkfs/")
	switch mtype {
	case "bind", "rbind", "erofs":
		dir = filepath.Dir(m.Source)
	case "overlay":
		for _, o := range m.Options {
			if v, ok := strings.CutPrefix(o, "upperdir="); ok {
				dir = filepath.Dir(v)
			}
		}
	default:
		return "", fmt.Errorf("unexpected mount type %q", m.Type)
	}
	if dir == "" {
		return "", fmt.Errorf("no layer dir in mounts %v", mounts)
	}
	if _, err := os.Stat(filepath.Join(dir, erofsLayerMarker)); err != nil {
		return "", fmt.Errorf("%s is not an erofs snapshot dir: %w", dir, err)
	}
	return dir, nil
}

// isErofsLayer reports whether a media type selects containerd's native
// erofs handling: it must end in ".erofs" and carry no "+suffix"
// (v2.1 plugins/diff/erofs/differ_linux.go, isErofsMediaType).
func isErofsLayer(mt string) bool {
	base, _, hasExt := strings.Cut(mt, "+")
	return !hasExt && strings.HasSuffix(base, ".erofs")
}

func uniquePart() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A fixed key would collide with a leftover prepare from an
		// earlier boot, and Prepare's AlreadyExists is read as "someone
		// else placed it" -- so we would label the manifest with a
		// chainID that has no committed snapshot.
		return "", fmt.Errorf("random snapshot key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// readImageConfig reads an image config blob out of the layout.
func readImageConfig(layoutDir string, d ocispec.Descriptor) (*ocispec.Image, error) {
	b, err := os.ReadFile(blobPath(layoutDir, d))
	if err != nil {
		return nil, err
	}
	var cfg ocispec.Image
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", d.Digest, err)
	}
	return &cfg, nil
}
