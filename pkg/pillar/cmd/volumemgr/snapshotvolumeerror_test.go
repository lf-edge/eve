// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"errors"
	"fmt"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

// An app must not run on an image that could not be repaired or checked. The
// error goes on the volume, where it keeps the app from starting, stays
// whatever happens to the snapshot, and goes away once an action leaves the
// image in a state that passes the check.
func TestUnusableImagePutsAnErrorOnTheVolume(t *testing.T) {
	unusable := fmt.Errorf("qemu-img: %w: qemu-img check failed", diskmetrics.ErrImageNotVerified)
	volumeKey := func(id uuid.UUID) string {
		return types.VolumeStatus{VolumeID: id}.Key()
	}
	volumeError := func(ctx *volumemgrContext, id uuid.UUID) string {
		return ctx.LookupVolumeStatus(volumeKey(id)).Error
	}
	refError := func(ctx *volumemgrContext, id uuid.UUID) string {
		ref := types.VolumeRefStatus{VolumeID: id, AppUUID: snapshotTestApp}
		st, err := ctx.pubVolumeRefStatus.Get(ref.Key())
		if err != nil {
			return "no VolumeRefStatus"
		}
		return st.(types.VolumeRefStatus).Error
	}
	// named returns the volumes that the error of the snapshot names, which
	// are the ones whose error zedmanager waits for.
	named := func(status types.VolumesSnapshotStatus) []string {
		var keys []string
		for _, entity := range status.ErrorEntities {
			assert.Equal(t, types.ErrorEntityVolume, entity.EntityType)
			keys = append(keys, entity.EntityID)
		}
		return keys
	}

	t.Run("rollback", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a", "b")
		existingSnapshot(ctx, "s1", ids[:1])
		fake.fail["rollback a"] = unusable
		wantSnapshot(ctx, snapshotTestConfig("s1", ids[:1], 1))
		finishSnapshotWork(t, ctx)

		assert.Contains(t, volumeError(ctx, ids[0]), "qemu-img check failed")
		assert.Contains(t, refError(ctx, ids[0]), "qemu-img check failed", "zedmanager looks at the VolumeRefStatus")
		assert.Empty(t, volumeError(ctx, ids[1]))
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateRollingBack, status.State)
		assert.Equal(t, []string{volumeKey(ids[0])}, named(status))
	})
	t.Run("action that fails on an image that is consistent", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s1", ids)
		fake.fail["rollback a"] = errors.New("no such snapshot")
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 1))
		finishSnapshotWork(t, ctx)

		status, _ := snapshotStatus(pub, "s1")
		assert.True(t, status.HasError())
		assert.Empty(t, named(status), "there is no error of a volume to wait for")
		assert.Empty(t, volumeError(ctx, ids[0]), "the app can run on the volume as it is")
	})
	t.Run("deletion", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s1", ids)
		fake.fail["delete a"] = unusable
		unwantSnapshot(ctx, "s1")
		finishSnapshotWork(t, ctx)
		assert.Contains(t, volumeError(ctx, ids[0]), "qemu-img check failed")
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, []string{volumeKey(ids[0])}, named(status))
	})
	t.Run("creation that may have left the snapshot on the image", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		fake.fail["create a"] = unusable
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 0))
		finishSnapshotWork(t, ctx)
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateCreating, status.State)
		assert.Contains(t, status.VolumeSnapshotMeta, ids[0].String(), "or nothing could delete it later")
		assert.Equal(t, []string{"create a"}, fake.made(), "the image is not worked on some more now")
		assert.NotEmpty(t, volumeError(ctx, ids[0]))

		delete(fake.fail, "create a")
		unwantSnapshot(ctx, "s1")
		finishSnapshotWork(t, ctx)
		assert.Equal(t, []string{"create a", "delete a"}, fake.made())
		assert.Empty(t, volumeError(ctx, ids[0]))
	})
	t.Run("stays until an action leaves the image consistent", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s0", ids)
		existingSnapshot(ctx, "s1", ids)
		fake.fail["delete a"] = unusable
		unwantSnapshot(ctx, "s1")
		finishSnapshotWork(t, ctx)
		failed, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, []string{volumeKey(ids[0])}, named(failed))

		// The deletion is taken along and fails again.
		fake.fail["rollback a"] = errors.New("no such snapshot")
		wantSnapshot(ctx, snapshotTestConfig("s0", ids, 1))
		finishSnapshotWork(t, ctx)
		finishSnapshotWork(t, ctx)
		assert.Contains(t, volumeError(ctx, ids[0]), "qemu-img check failed",
			"a rollback that did not get to check the image says nothing about it")
		rollback, _ := snapshotStatus(pub, "s0")
		assert.Equal(t, []string{volumeKey(ids[0])}, named(rollback),
			"zedmanager has to wait for the error whichever status it gets first")

		delete(fake.fail, "rollback a")
		delete(fake.fail, "delete a")
		existingSnapshot(ctx, "s2", ids)
		withError, _ := snapshotStatus(pub, "s1")
		withError.SetErrorWithSourceAndDescription(types.ErrorDescription{
			Error:         "qemu-img failed",
			ErrorEntities: []*types.ErrorEntity{{EntityType: types.ErrorEntityVolume, EntityID: volumeKey(ids[0])}},
		}, types.VolumesSnapshotStatus{})
		_ = publishVolumesSnapshotStatus(ctx, &withError)
		wantSnapshot(ctx, snapshotTestConfig("s2", ids, 1))
		for len(ctx.snapshotOpInFlight) > 0 || len(ctx.snapshotsWaiting) > 0 {
			finishSnapshotWork(t, ctx)
		}
		assert.Empty(t, volumeError(ctx, ids[0]))
		assert.Empty(t, refError(ctx, ids[0]))
		rollback, _ = snapshotStatus(pub, "s0")
		assert.Empty(t, named(rollback), "zedmanager would wait for an error that is gone")
	})
	t.Run("goes with an action that fails on an image which passes its check", func(t *testing.T) {
		ctx, _, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s0", ids)
		broken := types.VolumeStatus{VolumeID: ids[0], DisplayName: "a", State: types.CREATED_VOLUME}
		broken.SetErrorWithSource("qemu-img check failed", types.VolumesSnapshotStatus{}, broken.ErrorTime)
		assert.NoError(t, ctx.pubVolumeStatus.Publish(broken.Key(), broken))

		fake.fail["rollback a"] = fmt.Errorf("rollback: %w",
			&diskmetrics.SoundImageError{Err: errors.New("no such snapshot")})
		wantSnapshot(ctx, snapshotTestConfig("s0", ids, 1))
		finishSnapshotWork(t, ctx)
		assert.Empty(t, volumeError(ctx, ids[0]), "the app must not stay down on an image that is consistent")
	})
	t.Run("stays named for a volume that the action did not get to", func(t *testing.T) {
		ctx, _, _ := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a", "b")
		untouched := types.VolumeStatus{VolumeID: ids[1], DisplayName: "b", State: types.CREATED_VOLUME}
		untouched.SetErrorWithSource("qemu-img check failed", types.VolumesSnapshotStatus{}, untouched.ErrorTime)
		assert.NoError(t, ctx.pubVolumeStatus.Publish(untouched.Key(), untouched))

		// The rollback failed on volume a, whose image is consistent, and
		// stopped there.
		work := snapshotWork{
			action: snapshotRollback,
			status: types.VolumesSnapshotStatus{SnapshotID: "s1", State: types.VolumesSnapshotStateRollingBack},
			volumes: []snapshotVolume{
				{status: *ctx.LookupVolumeStatus(volumeKey(ids[0]))},
				{status: *ctx.LookupVolumeStatus(volumeKey(ids[1]))},
			},
			sound: []string{volumeKey(ids[0])},
		}
		snapshotError(&work.status, "Failed to roll back to snapshot s1")
		applyVolumeErrors(ctx, &work)
		assert.Equal(t, []string{volumeKey(ids[1])}, named(work.status),
			"zedmanager must go on waiting for the error of the volume")
	})
	t.Run("is gone after a reboot, and so is its name in the error of the snapshot", func(t *testing.T) {
		status := types.VolumesSnapshotStatus{SnapshotID: "s1", State: types.VolumesSnapshotStateRollingBack}
		status.SetErrorWithSourceAndDescription(types.ErrorDescription{
			Error:         "qemu-img failed",
			ErrorEntities: []*types.ErrorEntity{{EntityType: types.ErrorEntityVolume, EntityID: "a volume"}},
		}, types.VolumesSnapshotStatus{})
		restoreSnapshotState(&status)
		assert.Equal(t, "qemu-img failed", status.Error)
		assert.Empty(t, status.ErrorEntities, "zedmanager would wait for an error that never comes")
	})
}
