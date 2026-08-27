// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
)

// staleSnapshotter is the snapshotter a pre-erofs release unpacked
// images into. Once the CRI snapshotter is erofs, nothing will ever
// look these up again: the erofs snapshotter cannot use them, and
// containerd re-unpacks from the content store instead
// (internal/cri/opts/container.go WithNewSnapshot).
const staleSnapshotter = "overlayfs"

// gcSnapshotLabelPrefix is the label containerd puts on an image's
// config blob to keep that image's snapshots reachable from the image
// record. One per snapshotter, so an image unpacked for both carries
// both, and dropping the stale one is what makes the snapshots
// collectable (client/image.go, end of Unpack).
const gcSnapshotLabelPrefix = "containerd.io/gc.ref.snapshot."

// criSnapshotterRE matches the CRI snapshotter setting in
// config-k3s.toml. This is a guard, not a config parser: it exists only
// to refuse to delete snapshots that are still live, and it fails
// closed — an unreadable or unrecognised config yields "", and the
// caller then does nothing.
var criSnapshotterRE = regexp.MustCompile(`^\s*snapshotter\s*=\s*"([^"]+)"`)

// ReclaimResult reports what a reclaim pass did, so the caller can log
// a real number rather than "freed space".
type ReclaimResult struct {
	// Removed is the number of snapshots deleted.
	Removed int
	// Bytes is the space those snapshots occupied, summed from
	// Usage() before removal.
	Bytes int64
	// Skipped is the number that could not be removed, e.g. because
	// something still holds them. Not an error: the next pass retries.
	Skipped int
	// Unlabelled is the number of image records that had a stale
	// gc.ref.snapshot label dropped.
	Unlabelled int
}

// configuredCRISnapshotter reads the snapshotter the CRI plugin is
// configured with. Returns "" when it cannot be determined, which
// callers must treat as "do not touch anything".
//
// Scanning is scoped to the [plugins."io.containerd.grpc.v1.cri".containerd]
// table: other tables (the transfer service's unpack_config, for one)
// also carry a snapshotter key, and matching the wrong one would invert
// the guard.
func configuredCRISnapshotter(configPath string) string {
	f, err := os.Open(configPath)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	const criTable = `[plugins."io.containerd.grpc.v1.cri".containerd]`
	inTable := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inTable = line == criTable
			continue
		}
		if !inTable {
			continue
		}
		if m := criSnapshotterRE.FindStringSubmatch(line); m != nil {
			return m[1]
		}
	}
	return ""
}

// ReclaimStaleSnapshots deletes the overlayfs snapshots left behind by
// a pre-erofs release.
//
// Safe to call on every tick: on all but one boot it walks an empty (or
// already-reclaimed) snapshotter and returns a zero result. It is the
// caller's job to gate it on the running partition being committed —
// see zbootstatus.CurrentPartitionCommitted. Deleting these while a
// revert is still possible would quietly destroy the fallback the A/B
// partition scheme exists to provide: the revert would succeed and the
// apps would not, because the old rootfs still runs the overlayfs
// snapshotter and still needs this state.
//
// Cost of being wrong is bounded in the other direction: if a snapshot
// is removed that something later wants, the content store still holds
// the layer and the differ re-converts it. That is time, not data loss.
func ReclaimStaleSnapshots(
	ctx context.Context, socket, configPath string) (ReclaimResult, error) {
	var res ReclaimResult

	// Refuse to run if overlayfs is what CRI is actually using —
	// someone reverted config-k3s.toml, and then these snapshots are
	// live. Fails closed on an unreadable config.
	switch configured := configuredCRISnapshotter(configPath); configured {
	case "":
		return res, fmt.Errorf(
			"cannot determine the CRI snapshotter from %s; refusing to reclaim",
			configPath)
	case staleSnapshotter:
		return res, fmt.Errorf(
			"CRI is configured with %q; its snapshots are live, refusing to reclaim",
			staleSnapshotter)
	}

	client, err := containerd.New(socket)
	if err != nil {
		return res, fmt.Errorf("containerd client: %w", err)
	}
	defer func() { _ = client.Close() }()
	ctx = namespaces.WithNamespace(ctx, kubectlx.K8sContainerdNamespace)

	// Drop the stale labels first. An image record that still claims
	// these snapshots would let containerd's GC recreate the reference
	// we are about to delete, and leaves a dangling reference behind if
	// it does not.
	res.Unlabelled, err = dropStaleSnapshotLabels(ctx, client)
	if err != nil {
		// Not fatal: the explicit removal below is what actually frees
		// the space, and a label we failed to drop only costs a
		// harmless dangling reference.
		log.Printf("WARNING: reclaim: dropping stale snapshot labels: %v", err)
	}

	sn := client.SnapshotService(staleSnapshotter)
	if sn == nil {
		return res, fmt.Errorf("no %q snapshotter", staleSnapshotter)
	}

	type entry struct {
		name  string
		bytes int64
	}
	var pending []entry
	err = sn.Walk(ctx, func(ctx context.Context, info snapshots.Info) error {
		var size int64
		if u, uerr := sn.Usage(ctx, info.Name); uerr == nil {
			size = u.Size
		}
		pending = append(pending, entry{name: info.Name, bytes: size})
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("walking %s snapshots: %w", staleSnapshotter, err)
	}
	if len(pending) == 0 {
		return res, nil
	}

	// Snapshots form parent/child chains and a parent cannot be removed
	// while a child references it. Rather than reconstruct the tree,
	// sweep repeatedly and keep whatever failed for the next round: each
	// sweep necessarily removes at least the current leaves, so this
	// converges in as many rounds as the chain is deep (single digits
	// for image layers).
	for len(pending) > 0 {
		var stuck []entry
		for _, e := range pending {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			switch err := sn.Remove(ctx, e.name); {
			case err == nil:
				res.Removed++
				res.Bytes += e.bytes
			case errdefs.IsNotFound(err):
				// Already gone, e.g. reaped by GC after we dropped the
				// label. Counts as done, but not as space we freed.
				res.Removed++
			default:
				stuck = append(stuck, e)
			}
		}
		if len(stuck) == len(pending) {
			// No progress: the remainder is genuinely held by something
			// (an active snapshot, a lease). Leave it for the next pass.
			res.Skipped = len(stuck)
			break
		}
		pending = stuck
	}
	return res, nil
}

// dropStaleSnapshotLabels removes the gc.ref.snapshot.<stale> label
// from every image record that carries one, and reports how many were
// changed.
func dropStaleSnapshotLabels(
	ctx context.Context, client *containerd.Client) (int, error) {
	is := client.ImageService()
	imgs, err := is.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("listing images: %w", err)
	}
	label := gcSnapshotLabelPrefix + staleSnapshotter
	var changed int
	for _, img := range imgs {
		if _, ok := img.Labels[label]; !ok {
			continue
		}
		delete(img.Labels, label)
		// The fieldpath scopes the update to this one label, so a
		// concurrent writer touching another field is not clobbered.
		if _, err := is.Update(ctx, img, "labels."+label); err != nil {
			if errdefs.IsNotFound(err) {
				continue
			}
			return changed, fmt.Errorf("updating image %s: %w", img.Name, err)
		}
		changed++
	}
	return changed, nil
}
