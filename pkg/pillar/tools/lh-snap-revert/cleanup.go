// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"strings"

	lh "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// runCleanup deletes the snapshots that are not on the current data's
// chain, such as the old branch a revert leaves. Longhorn cannot purge a
// snapshot with two branches below it, which can leave the volume attached.
func runCleanup(ctx context.Context, a api, o *revertOpts) error {
	rctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	_, volName, err := resolveVolume(rctx, a, o.namespace, o.pvc)
	if err != nil {
		return err
	}
	vol, err := a.Volume(rctx, volName)
	if err != nil {
		return fmt.Errorf("get Longhorn volume %s: %w", volName, err)
	}
	// Longhorn updates the snapshot tree only while the volume is attached.
	if vol.Status.State != lh.VolumeStateAttached {
		return fmt.Errorf("volume %s is %q; start the app first, so that the snapshot tree is current",
			volName, vol.Status.State)
	}
	snaps, err := a.Snapshots(rctx, volName)
	if err != nil {
		return fmt.Errorf("list snapshots of %s: %w", volName, err)
	}
	t := newSnapTree(snaps)
	if t.live == nil {
		return fmt.Errorf("cannot find %s in the snapshot tree of %s", volumeHead, volName)
	}
	old := t.oldBranch()
	if len(old) == 0 {
		fmt.Fprintln(o.out, "Nothing to clean up: all snapshots are on the current branch.")
		return nil
	}
	fmt.Fprintf(o.out, "Snapshots of %s off the current branch, to delete:\n  %s\n", volName, strings.Join(old, "\n  "))
	if o.dryRun {
		fmt.Fprintln(o.out, "Dry run: nothing changed.")
		return nil
	}
	if !o.yes && !confirm(ctx, o) {
		return errAborted
	}
	for _, n := range old {
		err := callAPI(ctx, func(c context.Context) error { return a.DeleteSnapshot(c, n) })
		if apierrors.IsNotFound(err) {
			continue // removed meanwhile, e.g. by a recurring job's retention
		}
		if err != nil {
			return fmt.Errorf("delete snapshot %s: %w", n, err)
		}
		fmt.Fprintf(o.out, "Deleted %s\n", n)
	}
	fmt.Fprintf(o.out, "Longhorn purges them in the background. Check with: lh-snap-revert list --pvc %s\n", o.pvc)
	return nil
}
