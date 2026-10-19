// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// newDoInstallTestContext builds a zedmanagerContext wired up with just
// enough pub/sub plumbing for doInstall: an (empty) DomainConfig
// publication - no domain owns any volume - zedmanager's own outgoing
// VolumeRefConfig publication, and a VolumeRefStatus subscription seeded
// with whatever volumemgr is pretending to have live status for.
func newDoInstallTestContext(t *testing.T, liveVolumeRefStatus []types.VolumeRefStatus) *zedmanagerContext {
	t.Helper()
	logger := logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	pubDomainConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DomainConfig{},
	})
	assert.NoError(t, err)

	pubVolumeRefConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumeRefConfig{},
	})
	assert.NoError(t, err)

	volumemgrPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "volumemgr",
		TopicType: types.VolumeRefStatus{},
	})
	assert.NoError(t, err)
	for _, vrs := range liveVolumeRefStatus {
		assert.NoError(t, volumemgrPub.Publish(vrs.Key(), vrs))
	}

	subVolumeRefStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "volumemgr",
		MyAgentName: agentName,
		TopicImpl:   types.VolumeRefStatus{},
		Persistent:  true,
	})
	assert.NoError(t, err)
	assert.NoError(t, subVolumeRefStatus.Activate())

	return &zedmanagerContext{
		pubDomainConfig:    pubDomainConfig,
		pubVolumeRefConfig: pubVolumeRefConfig,
		subVolumeRefStatus: subVolumeRefStatus,
	}
}

// TestDoInstallDropsStaleVolumeRefWithNoLiveStatus is the regression test
// for the reboot-purge wedge: a VolumeRefStatus entry that the current
// AppInstanceConfig no longer wants, and that volumemgr has no live status
// for at all (never republished this boot, or already deleted), must be
// dropped immediately instead of parked on PendingAdd waiting for a delete
// event that can never arrive - which previously left doInstall returning
// early forever, never even requesting the newly desired volume.
func TestDoInstallDropsStaleVolumeRefWithNoLiveStatus(t *testing.T) {
	appUUID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	staleVolumeID := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))
	newVolumeID := uuid.Must(uuid.FromString("33333333-3333-3333-3333-333333333333"))

	// volumemgr has nothing live for the stale volume at all.
	ctx := newDoInstallTestContext(t, nil)

	// zedmanager itself still has a live VolumeRefConfig request out for the
	// stale volume (as it would across a reboot, if that publication is what
	// survived while volumemgr's own side did not) - doInstall must still
	// unpublish it, even though it drops the status entry immediately.
	staleVrc := types.VolumeRefConfig{VolumeID: staleVolumeID, AppUUID: appUUID, VerifyOnly: true}
	assert.NoError(t, ctx.pubVolumeRefConfig.Publish(staleVrc.Key(), staleVrc))

	config := types.AppInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: appUUID, Version: "1"},
		VolumeRefConfigList: []types.VolumeRefConfig{
			{VolumeID: newVolumeID, AppUUID: appUUID, VerifyOnly: true},
		},
	}
	status := &types.AppInstanceStatus{
		UUIDandVersion:  config.UUIDandVersion,
		PurgeInprogress: types.DownloadAndVerify,
		VolumeRefStatusList: []types.VolumeRefStatus{
			{
				VolumeID:   staleVolumeID,
				AppUUID:    appUUID,
				State:      types.LOADED,
				PendingAdd: false,
				VerifyOnly: true,
			},
		},
	}

	doInstall(ctx, config, status)

	for _, vrs := range status.VolumeRefStatusList {
		assert.NotEqual(t, staleVolumeID, vrs.VolumeID,
			"stale VolumeRefStatus must be dropped once volumemgr has no live status for it")
	}
	if assert.Len(t, status.VolumeRefStatusList, 1) {
		assert.Equal(t, newVolumeID, status.VolumeRefStatusList[0].VolumeID)
	}
	staleVrcAfter, _ := ctx.pubVolumeRefConfig.Get(staleVrc.Key())
	assert.Nil(t, staleVrcAfter,
		"the stale VolumeRefConfig request to volumemgr must still be unpublished")
}

// TestDoInstallWaitsForStaleVolumeRefWithLiveStatus pins the other half of
// the same invariant: if volumemgr still has a live VolumeRefStatus for the
// stale ref, doInstall must not drop it out from under an in-flight async
// removal - it should mark it PendingAdd and wait for volumemgr's delete,
// exactly as before this fix.
func TestDoInstallWaitsForStaleVolumeRefWithLiveStatus(t *testing.T) {
	appUUID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	staleVolumeID := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))
	newVolumeID := uuid.Must(uuid.FromString("33333333-3333-3333-3333-333333333333"))

	staleVrs := types.VolumeRefStatus{
		VolumeID:   staleVolumeID,
		AppUUID:    appUUID,
		State:      types.LOADED,
		PendingAdd: false,
		VerifyOnly: true,
	}
	// volumemgr still reports this volume as live.
	ctx := newDoInstallTestContext(t, []types.VolumeRefStatus{staleVrs})

	config := types.AppInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: appUUID, Version: "1"},
		VolumeRefConfigList: []types.VolumeRefConfig{
			{VolumeID: newVolumeID, AppUUID: appUUID, VerifyOnly: true},
		},
	}
	status := &types.AppInstanceStatus{
		UUIDandVersion:      config.UUIDandVersion,
		PurgeInprogress:     types.DownloadAndVerify,
		VolumeRefStatusList: []types.VolumeRefStatus{staleVrs},
	}

	doInstall(ctx, config, status)

	if assert.Len(t, status.VolumeRefStatusList, 1) {
		assert.Equal(t, staleVolumeID, status.VolumeRefStatusList[0].VolumeID)
		assert.True(t, status.VolumeRefStatusList[0].PendingAdd,
			"must be marked pending removal while waiting for volumemgr's delete")
	}
}
