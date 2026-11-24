// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// newActivatableTestContext is newRollbackTestContext with a config that
// asks for the app to run, an app that is installed and halted, and nothing
// in the way of starting it.
func newActivatableTestContext(t *testing.T) (*zedmanagerContext, types.AppInstanceConfig) {
	t.Helper()
	ctx, config := newRollbackTestContext(t)
	config.Activate = true
	ctx.globalConfig = types.DefaultConfigItemValueMap()
	ctx.globalConfig.SetGlobalValueBool(types.IgnoreMemoryCheckForApps, true)
	status := lookupAppInstanceStatus(ctx, config.Key())
	status.SnapStatus.RollbackInProgress = false
	status.PurgeInprogress = types.NotInprogress
	publishAppInstanceStatus(ctx, status)
	return ctx, config
}

// useVolumeRefStatus makes volumemgr report the given volumes.
func useVolumeRefStatus(t *testing.T, ctx *zedmanagerContext, volumes ...types.VolumeRefStatus) {
	t.Helper()
	ps := pubsub.New(pubsub.NewMemoryDriver(), logrus.StandardLogger(), log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "volumemgr",
		TopicType: types.VolumeRefStatus{},
	})
	assert.NoError(t, err)
	for _, volume := range volumes {
		assert.NoError(t, pub.Publish(volume.Key(), volume))
	}
	ctx.subVolumeRefStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "volumemgr",
		MyAgentName: agentName,
		TopicImpl:   types.VolumeRefStatus{},
		Persistent:  true,
	})
	assert.NoError(t, err)
	assert.NoError(t, ctx.subVolumeRefStatus.Activate())
}

// unusableVolume is the volume of the app as volumemgr reports it after a
// snapshot action left an image that could not be repaired or checked.
func unusableVolume(status *types.AppInstanceStatus) types.VolumeRefStatus {
	volume := status.VolumeRefStatusList[0]
	volume.SetErrorWithSourceAndDescription(
		types.ErrorDescription{Error: "disk image could not be verified"}, types.VolumeStatus{})
	return volume
}

// Running an app on a disk image that could not be repaired or checked
// corrupts it further. volumemgr puts the error on the volume, also on one of
// an app that is installed and only waits to be started, and takes it off
// again once an action leaves the image in a state that passes the check.
func TestAppStaysDownOnAVolumeThatCannotBeUsed(t *testing.T) {
	ctx, config := newActivatableTestContext(t)
	status := lookupAppInstanceStatus(ctx, config.Key())
	usable := status.VolumeRefStatusList[0]

	useVolumeRefStatus(t, ctx, unusableVolume(status))
	doUpdate(ctx, config, status)
	assert.Contains(t, status.Error, "disk image could not be verified")
	assert.False(t, status.ActivateInprogress)
	assert.Empty(t, ctx.pubAppNetworkConfig.GetAll())

	useVolumeRefStatus(t, ctx, usable)
	doUpdate(ctx, config, status)
	assert.Empty(t, status.Error)
	assert.NotEmpty(t, ctx.pubAppNetworkConfig.GetAll(), "on a volume without an error the app is brought up")
}

// What volumemgr says of a snapshot and the error of a volume come in two
// publications, in any order. A snapshot without an error means that the app
// can start. The error of a snapshot names the volumes that cannot be used,
// and the app must not be started before their error is in.
func TestAppWaitsForTheErrorOfAVolumeThatCannotBeUsed(t *testing.T) {
	ctx, config := newActivatableTestContext(t)
	app := config.UUIDandVersion.UUID
	status := lookupAppInstanceStatus(ctx, config.Key())
	usable := status.VolumeRefStatusList[0]
	answer := types.VolumesSnapshotStatus{
		SnapshotID:    "s2",
		AppUUID:       app,
		State:         types.VolumesSnapshotStateRollingBack,
		RollbackCount: 1,
	}
	answer.SetErrorWithSourceAndDescription(types.ErrorDescription{
		Error:         "qemu-img failed",
		ErrorEntities: []*types.ErrorEntity{{EntityType: types.ErrorEntityVolume, EntityID: usable.VolumeKey()}},
	}, types.VolumesSnapshotStatus{})
	useSnapshotState(t, ctx, kept(answer), []types.VolumesSnapshotStatus{answer})

	useVolumeRefStatus(t, ctx, usable)
	assert.True(t, snapshotOpInProgress(ctx, app), "the error of the volume is still to come")
	doUpdate(ctx, config, status)
	assert.Empty(t, ctx.pubAppNetworkConfig.GetAll())

	useVolumeRefStatus(t, ctx, unusableVolume(status))
	assert.False(t, snapshotOpInProgress(ctx, app), "the error is what keeps the app down from here on")

	useVolumeRefStatus(t, ctx)
	assert.False(t, snapshotOpInProgress(ctx, app), "the app does not have that volume any more")

	// A rollback that failed on images that are consistent names no volume.
	answer.ErrorEntities = nil
	useSnapshotState(t, ctx, kept(answer), []types.VolumesSnapshotStatus{answer})
	useVolumeRefStatus(t, ctx, usable)
	assert.False(t, snapshotOpInProgress(ctx, app), "the app can run on the volumes as they are")
}

// A purge gives the app new volumes, which is the way out when a volume
// cannot be repaired. The error of the volume it replaces must not stop it.
func TestPurgeGetsPastAVolumeThatCannotBeUsed(t *testing.T) {
	ctx, config := newActivatableTestContext(t)
	status := lookupAppInstanceStatus(ctx, config.Key())
	oldVolume := unusableVolume(status)
	useVolumeRefStatus(t, ctx, oldVolume)
	doInstall(ctx, config, status)
	assert.Contains(t, status.Error, "disk image could not be verified")
	// The old volume is still that of the domain.
	domain := types.DomainConfig{UUIDandVersion: status.UUIDandVersion}
	domain.DiskConfigList = []types.DiskConfig{{VolumeKey: oldVolume.VolumeKey()}}
	assert.NoError(t, ctx.pubDomainConfig.Publish(domain.Key(), domain))

	config.VolumeRefConfigList[0].GenerationCounter++
	newVolume := status.VolumeRefStatusList[0]
	newVolume.ClearErrorWithSource()
	newVolume.GenerationCounter++
	newVolume.State = types.INITIAL
	status.VolumeRefStatusList = append(status.VolumeRefStatusList, newVolume)
	status.PurgeInprogress = types.DownloadAndVerify

	status.ClearErrorWithSource()
	doInstall(ctx, config, status)
	assert.Empty(t, status.Error)

	status.PurgeInprogress = types.NotInprogress
	config.VolumeRefConfigList[0].GenerationCounter--
	status.VolumeRefStatusList = status.VolumeRefStatusList[:1]
	doInstall(ctx, config, status)
	assert.Contains(t, status.Error, "disk image could not be verified",
		"without a purge the volume stays, and so does its error")
}
