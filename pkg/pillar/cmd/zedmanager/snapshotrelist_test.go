// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"errors"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func snapshotIDs(snaps []types.SnapshotInstanceStatus) []string {
	ids := []string{}
	for _, s := range snaps {
		ids = append(ids, s.Snapshot.SnapshotID)
	}
	return ids
}

func descIDs(snaps []types.SnapshotDesc) []string {
	ids := []string{}
	for _, s := range snaps {
		ids = append(ids, s.SnapshotID)
	}
	return ids
}

// A config that does not know a snapshot gets it flagged for deletion. The
// device can boot on such a config when it is older than the snapshot; the
// config that lists the snapshot again must get it back, not have it taken anew.
func TestRelistedSnapshotIsKept(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), agentName, 0)
	app := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	desc := func(id string) types.SnapshotDesc {
		return types.SnapshotDesc{SnapshotID: id, SnapshotType: types.SnapshotTypeImmediate}
	}
	// Snapshots are as old as their names sort.
	onDisk := func(id string) types.SnapshotInstanceStatus {
		return types.SnapshotInstanceStatus{Snapshot: desc(id), Reported: true, AppInstanceID: app,
			TimeCreated: time.Unix(int64(id[len(id)-1]), 0)}
	}
	load := func(id string) (*types.SnapshotInstanceStatus, error) {
		s := onDisk(id)
		return &s, nil
	}
	config := func(max uint32, ids ...string) types.AppInstanceConfig {
		c := types.AppInstanceConfig{UUIDandVersion: types.UUIDandVersion{UUID: app}}
		c.Snapshot.MaxSnapshots = max
		for _, id := range ids {
			c.Snapshot.Snapshots = append(c.Snapshot.Snapshots, desc(id))
		}
		return c
	}
	newStatus := func(available ...string) *types.AppInstanceStatus {
		s := &types.AppInstanceStatus{UUIDandVersion: types.UUIDandVersion{UUID: app}}
		for _, id := range available {
			s.SnapStatus.AvailableSnapshots = append(s.SnapStatus.AvailableSnapshots, onDisk(id))
		}
		return s
	}

	t.Run("flagged by a config without it, then listed again", func(t *testing.T) {
		status := newStatus("s1")
		updateSnapshotsInAIStatus(status, config(1), load)
		assert.Equal(t, []string{"s1"}, descIDs(status.SnapStatus.SnapshotsToBeDeleted))

		updateSnapshotsInAIStatus(status, config(1, "s1"), load)
		assert.Empty(t, status.SnapStatus.SnapshotsToBeDeleted)
		assert.Equal(t, []string{"s1"}, snapshotIDs(status.SnapStatus.AvailableSnapshots))
		assert.Empty(t, status.SnapStatus.RequestedSnapshots)
		assert.Equal(t, types.NoSnapshotTake, status.SnapStatus.SnapshotTakenType)
	})

	t.Run("flagged to make room stays flagged", func(t *testing.T) {
		status := newStatus("s1")
		updateSnapshotsInAIStatus(status, config(1, "s1", "s2"), load)
		assert.Equal(t, []string{"s1"}, descIDs(status.SnapStatus.SnapshotsToBeDeleted))
		assert.Equal(t, []string{"s2"}, snapshotIDs(status.SnapStatus.RequestedSnapshots))

		updateSnapshotsInAIStatus(status, config(1, "s1", "s2"), load)
		assert.Equal(t, []string{"s1"}, descIDs(status.SnapStatus.SnapshotsToBeDeleted))
		assert.Empty(t, status.SnapStatus.AvailableSnapshots)
		assert.Equal(t, []string{"s2"}, snapshotIDs(status.SnapStatus.RequestedSnapshots))
	})

	t.Run("record cannot be read", func(t *testing.T) {
		status := newStatus("s1")
		updateSnapshotsInAIStatus(status, config(1), load)
		broken := func(string) (*types.SnapshotInstanceStatus, error) {
			return nil, errors.New("no such file")
		}
		updateSnapshotsInAIStatus(status, config(1, "s1"), broken)
		assert.Empty(t, status.SnapStatus.SnapshotsToBeDeleted)
		if assert.Equal(t, []string{"s1"}, snapshotIDs(status.SnapStatus.AvailableSnapshots)) {
			kept := status.SnapStatus.AvailableSnapshots[0]
			assert.True(t, kept.Reported)
			assert.Equal(t, app, kept.AppInstanceID)
			assert.Equal(t, types.SnapshotTypeImmediate, kept.Snapshot.SnapshotType)
		}
		assert.Empty(t, status.SnapStatus.RequestedSnapshots)
	})

	t.Run("a snapshot the config drops does not take up room", func(t *testing.T) {
		status := newStatus("s1", "s2")
		updateSnapshotsInAIStatus(status, config(2, "s2"), load)
		assert.Equal(t, []string{"s1"}, descIDs(status.SnapStatus.SnapshotsToBeDeleted))

		updateSnapshotsInAIStatus(status, config(1, "s1"), load)
		assert.Equal(t, []string{"s2"}, descIDs(status.SnapStatus.SnapshotsToBeDeleted))
		assert.Equal(t, []string{"s1"}, snapshotIDs(status.SnapStatus.AvailableSnapshots))
		assert.Empty(t, status.SnapStatus.RequestedSnapshots)
	})

	// The dropped snapshot is the older one, so it is also the first pick
	// when the limit asks for one more to go. It must not be counted twice.
	t.Run("taken back while another is dropped and a new one requested", func(t *testing.T) {
		status := newStatus("s1", "s2")
		updateSnapshotsInAIStatus(status, config(2, "s1"), load)
		assert.Equal(t, []string{"s2"}, descIDs(status.SnapStatus.SnapshotsToBeDeleted))

		updateSnapshotsInAIStatus(status, config(1, "s2", "s3"), load)
		assert.ElementsMatch(t, []string{"s1", "s2"}, descIDs(status.SnapStatus.SnapshotsToBeDeleted))
		assert.Empty(t, status.SnapStatus.AvailableSnapshots)
		assert.Equal(t, []string{"s3"}, snapshotIDs(status.SnapStatus.RequestedSnapshots))
		assert.Equal(t, types.SnapshotImmediate, status.SnapStatus.SnapshotTakenType)
	})
}
