// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumehandlers

import (
	"errors"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/stretchr/testify/assert"
)

// A deletion can be cut off after the snapshot was destroyed and before
// volumemgr has noted that, and is tried again then. A snapshot that is gone
// has to count as deleted, or that deletion never ends. Only a volume that is
// there can tell that its snapshot is gone: zfs not answering is no proof.
func TestZVolDeleteSnapshotThatIsGone(t *testing.T) {
	const (
		volume   = "persist/vault/volumes/vol"
		snapshot = volume + "@20261125-120000000"
	)
	tests := []struct {
		name       string
		meta       interface{}
		destroyErr error
		existing   []string
		wantErr    string
	}{
		{name: "deleted", meta: snapshot, existing: []string{volume, snapshot}},
		{name: "already gone", meta: snapshot, destroyErr: errors.New("dataset not found"),
			existing: []string{volume}},
		{name: "still there", meta: snapshot, destroyErr: errors.New("dataset is busy"),
			existing: []string{volume, snapshot}, wantErr: "dataset is busy"},
		{name: "zfs does not answer", meta: snapshot, destroyErr: errors.New("cannot open pool"),
			wantErr: "cannot open pool"},
		{name: "not the name of a snapshot", meta: volume, destroyErr: errors.New("dataset not found"),
			wantErr: "dataset not found"},
		{name: "no name at all", meta: 7, wantErr: "invalid snapshotMeta"},
	}
	savedDestroy, savedExists := destroyZFSDataset, zfsDatasetExists
	t.Cleanup(func() { destroyZFSDataset, zfsDatasetExists = savedDestroy, savedExists })
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var destroyed []string
			destroyZFSDataset = func(name string) error {
				destroyed = append(destroyed, name)
				return tt.destroyErr
			}
			zfsDatasetExists = func(_ *base.LogObject, name string) bool {
				for _, existing := range tt.existing {
					if existing == name {
						return true
					}
				}
				return false
			}
			handler := &volumeHandlerZVol{commonVolumeHandler: commonVolumeHandler{
				status: &types.VolumeStatus{DisplayName: "vol"},
				log:    newTestLog(t),
			}}

			err := handler.DeleteSnapshot(tt.meta)

			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else if assert.Error(t, err) {
				assert.Contains(t, err.Error(), tt.wantErr)
			}
			if _, isName := tt.meta.(string); isName {
				assert.Equal(t, []string{tt.meta.(string)}, destroyed)
			}
		})
	}
}
