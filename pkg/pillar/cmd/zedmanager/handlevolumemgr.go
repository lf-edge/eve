// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

// Code for the interface with VolumeMgr

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/activeapp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
)

// MaybeAddVolumeRefConfig publishes VolumeRefConfig to the volumemgr
func MaybeAddVolumeRefConfig(ctx *zedmanagerContext, appInstID uuid.UUID,
	volumeID uuid.UUID, generationCounter, localGenerationCounter int64,
	mountDir string, verifyOnly bool) {

	// construct the key as in VolumeRefConfig.Key()
	key := fmt.Sprintf("%s#%d#%s", volumeID.String(),
		generationCounter+localGenerationCounter, appInstID.String())
	log.Functionf("MaybeAddVolumeRefConfig for %s", key)
	m := lookupVolumeRefConfig(ctx, key)
	if m != nil {
		// only update from VerifyOnly to non-VerifyOnly
		if m.VerifyOnly {
			m.VerifyOnly = verifyOnly
		}
		log.Functionf("VolumeRefConfig exists for %s. Setting verifyOnly to %v",
			key, m.VerifyOnly)
		publishVolumeRefConfig(ctx, m)
	} else {
		log.Tracef("MaybeAddVolumeRefConfig: add for %s", key)
		vrc := types.VolumeRefConfig{
			VolumeID:               volumeID,
			GenerationCounter:      generationCounter,
			LocalGenerationCounter: localGenerationCounter,
			AppUUID:                appInstID,
			MountDir:               mountDir,
			VerifyOnly:             verifyOnly,
		}
		publishVolumeRefConfig(ctx, &vrc)
	}
	base.NewRelationObject(log, base.AddRelationType, base.AppInstanceConfigLogType, appInstID.String(),
		base.VolumeRefConfigLogType, key).Noticef("App instance to volume relation.")
	log.Functionf("MaybeAddVolumeRefConfig done for %s", key)
}

// MaybeRemoveVolumeRefConfig unpublishes VolumeRefConfig for volumemgr (AppInstanceConfig remains unchanged)
func MaybeRemoveVolumeRefConfig(ctx *zedmanagerContext, appInstID uuid.UUID,
	volumeID uuid.UUID, generationCounter, localGenerationCounter int64) {

	// construct the key as in VolumeRefConfig.Key()
	key := fmt.Sprintf("%s#%d#%s", volumeID.String(),
		generationCounter+localGenerationCounter, appInstID.String())
	log.Functionf("MaybeRemoveVolumeRefConfig for %s", key)
	m := lookupVolumeRefConfig(ctx, key)
	if m == nil {
		log.Functionf("MaybeRemoveVolumeRefConfig: config missing for %s", key)
		return
	}

	log.Functionf("MaybeRemoveVolumeRefConfig deleting %s", key)
	unpublishVolumeRefConfig(ctx, key)

	base.NewRelationObject(log, base.DeleteRelationType, base.AppInstanceConfigLogType, appInstID.String(),
		base.VolumeRefConfigLogType, key).Noticef("App instance to volume relation.")
	log.Functionf("MaybeRemoveVolumeRefConfig done for %s", key)
}

func lookupVolumeRefConfig(ctx *zedmanagerContext, key string) *types.VolumeRefConfig {

	pub := ctx.pubVolumeRefConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Tracef("lookupVolumeRefConfig(%s) not found", key)
		return nil
	}
	config := c.(types.VolumeRefConfig)
	return &config
}

func getAllVolumeRefConfig(ctx *zedmanagerContext) []types.VolumeRefConfig {
	pub := ctx.pubVolumeRefConfig
	items := pub.GetAll()
	var configs []types.VolumeRefConfig
	for _, st := range items {
		config := st.(types.VolumeRefConfig)
		configs = append(configs, config)
	}
	return configs
}

func lookupVolumeRefStatus(ctx *zedmanagerContext, key string) *types.VolumeRefStatus {

	sub := ctx.subVolumeRefStatus
	c, _ := sub.Get(key)
	if c == nil {
		log.Tracef("lookupVolumeRefStatus(%s) not found", key)
		return nil
	}
	status := c.(types.VolumeRefStatus)
	return &status
}

func publishVolumeRefConfig(ctx *zedmanagerContext, config *types.VolumeRefConfig) {

	key := config.Key()
	log.Tracef("publishVolumeRefConfig(%s)", key)
	pub := ctx.pubVolumeRefConfig
	pub.Publish(key, *config)
	log.Tracef("publishVolumeRefConfig(%s) Done", key)
}

func unpublishVolumeRefConfig(ctx *zedmanagerContext, key string) {

	log.Tracef("unpublishVolumeRefConfig(%s)", key)
	pub := ctx.pubVolumeRefConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishVolumeRefConfig(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Tracef("unpublishVolumeRefConfig(%s) Done", key)
}

func handleVolumeRefStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleVolumeRefStatusImpl(ctxArg, key, statusArg)
}

func handleVolumeRefStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleVolumeRefStatusImpl(ctxArg, key, statusArg)
}

func handleVolumeRefStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.VolumeRefStatus)
	ctx := ctxArg.(*zedmanagerContext)
	log.Functionf("handleVolumeRefStatusImpl: key:%s, name:%s",
		key, status.DisplayName)
	pub := ctx.pubAppInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		aiStatus := st.(types.AppInstanceStatus)
		for _, vrs := range aiStatus.VolumeRefStatusList {
			if vrs.GenerationCounter == status.GenerationCounter &&
				vrs.LocalGenerationCounter == status.LocalGenerationCounter &&
				vrs.VolumeID == status.VolumeID {

				updateAIStatusUUID(ctx, aiStatus.UUIDandVersion.UUID.String())
			}
		}
	}
	log.Functionf("handleVolumeRefStatusImpl done for %s", key)
}

func handleVolumeRefStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.VolumeRefStatus)
	ctx := ctxArg.(*zedmanagerContext)
	log.Functionf("handleVolumeRefStatusDelete: key:%s, name:%s",
		key, status.DisplayName)
	pub := ctx.pubAppInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		aiStatus := st.(types.AppInstanceStatus)
		for _, vrs := range aiStatus.VolumeRefStatusList {
			if vrs.GenerationCounter == status.GenerationCounter &&
				vrs.LocalGenerationCounter == status.LocalGenerationCounter &&
				vrs.VolumeID == status.VolumeID {

				updateAIStatusUUID(ctx, aiStatus.UUIDandVersion.UUID.String())
			}
		}
	}
	log.Functionf("handleVolumeRefStatusDelete done for %s", key)
}

func getVolumeRefStatusFromAIStatus(status *types.AppInstanceStatus,
	vrc types.VolumeRefConfig) *types.VolumeRefStatus {

	log.Tracef("getVolumeRefStatusFromAIStatus(%v)", vrc.Key())
	for i := range status.VolumeRefStatusList {
		vrs := &status.VolumeRefStatusList[i]
		if vrs.Key() == vrc.Key() {
			log.Tracef("getVolumeRefStatusFromAIStatus(%v) found %s "+
				"generationCounter %d localGenerationCounter %d "+
				"appUUID %s",
				vrs.Key(), vrs.DisplayName, vrs.GenerationCounter,
				vrs.LocalGenerationCounter, vrs.AppUUID.String())
			return vrs
		}
	}
	log.Tracef("getVolumeRefStatusFromAIStatus(%v) Done", vrc.Key())
	return nil
}

func getVolumeRefConfigFromAIConfig(config *types.AppInstanceConfig,
	vrs types.VolumeRefStatus) *types.VolumeRefConfig {

	log.Tracef("getVolumeRefConfigFromAIConfig(%v)", vrs.Key())
	for i := range config.VolumeRefConfigList {
		vrc := &config.VolumeRefConfigList[i]
		if vrc.Key() == vrs.Key() {
			log.Tracef("getVolumeRefConfigFromAIConfig(%v) found %s "+
				"generationCounter %d localGenerationCounter %d "+
				"appUUID %s",
				vrs.Key(), vrs.DisplayName, vrs.GenerationCounter,
				vrs.LocalGenerationCounter, vrs.AppUUID.String())
			return vrc
		}
	}
	log.Tracef("getVolumeRefConfigFromAIConfig(%v) Done", vrs.Key())
	return nil
}

/* Handlers for VolumesSnapshotStatus */

// DeleteSnapshotFiles deletes the snapshot directory
func DeleteSnapshotFiles(snapshotID string) error {
	configDir := types.GetSnapshotDir(snapshotID)
	// delete the directory if it exists
	if _, err := os.Stat(configDir); err == nil {
		log.Noticef("Deleting snapshot directory %s", configDir)
		err = os.RemoveAll(configDir)
		if err != nil {
			log.Errorf("Failed to delete snapshot directory %s: %s", configDir, err)
			return err
		}
	}
	return nil
}

func reactToSnapshotRollback(ctx *zedmanagerContext, volumesSnapshotStatus types.VolumesSnapshotStatus) {
	log.Noticef("reactToSnapshotRollback: %s", volumesSnapshotStatus.SnapshotID)
	appInstanceStatus := lookupAppInstanceStatus(ctx, volumesSnapshotStatus.AppUUID.String())
	if appInstanceStatus == nil {
		log.Errorf("handleVolumesSnapshotStatusModify: AppInstanceStatus not found for %s", volumesSnapshotStatus.AppUUID.String())
		return
	}
	if volumesSnapshotStatus.HasError() {
		// Nothing else ends the rollback, so the app goes on with the
		// volumes as they are. The error stays with the snapshot.
		log.Errorf("Snapshot handling %s failed: %s", volumesSnapshotStatus.SnapshotID, volumesSnapshotStatus.Error)
	}
	refreshSnapshots(ctx, appInstanceStatus)
	appInstanceStatus.SnapStatus.RollbackInProgress = false
	// unpublish local app instance config, as the rollback is complete, we do not need to replace the config
	config := lookupAppInstanceConfig(ctx, appInstanceStatus.Key(), false)
	unpublishLocalAppInstanceConfig(ctx, appInstanceStatus.Key())
	publishAppInstanceStatus(ctx, appInstanceStatus)
	if config == nil {
		// The app was deleted meanwhile. Its removal ended as the purge of
		// this rollback, so take it up again.
		log.Warnf("reactToSnapshotRollback: no AppInstanceConfig for %s", appInstanceStatus.Key())
		removeAIStatus(ctx, appInstanceStatus)
		return
	}
	// Mark the app as active locally to ensure it immediately restarts after rollback from a snapshot.
	// This avoids delays in app activation that can occur due to edge app priority scheduling.
	activeapp.CreateLocalAppActiveFile(log, appInstanceStatus.UUIDandVersion.UUID.String())
	if doUpdate(ctx, *config, appInstanceStatus) {
		publishAppInstanceStatus(ctx, appInstanceStatus)
		publishAppInstanceSummary(ctx)
	}
}

func handleVolumesSnapshotStatusCreate(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	status := statusArg.(types.VolumesSnapshotStatus)
	log.Noticef("handleVolumesSnapshotStatusCreate(%s)", key)
	// What volumemgr restores at boot is from before the reboot. Its error
	// stays with the snapshot.
	handleVolumesSnapshotStatusImpl(ctx, status, ctx.snapshotsRestored && status.HasError())
}

func handleVolumesSnapshotStatusModify(ctxArg interface{}, key string, statusArg interface{}, oldStatusArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	status := statusArg.(types.VolumesSnapshotStatus)
	oldStatus := oldStatusArg.(types.VolumesSnapshotStatus)
	log.Noticef("handleVolumesSnapshotStatusModify(%s)", key)
	newError := status.HasError() && !status.ErrorTime.Equal(oldStatus.ErrorTime)
	handleVolumesSnapshotStatusImpl(ctx, status, newError)
}

// handleVolumesSnapshotStatusImpl takes in what volumemgr says about a
// snapshot. When volumemgr is through with it, the app may be able to go on.
// newError tells that an action on the snapshot has just failed.
func handleVolumesSnapshotStatusImpl(ctx *zedmanagerContext, volumesSnapshotStatus types.VolumesSnapshotStatus,
	newError bool) {
	log.Noticef("handleVolumesSnapshotStatusImpl(%s) state %s error %q", volumesSnapshotStatus.SnapshotID,
		volumesSnapshotStatus.State, volumesSnapshotStatus.Error)
	appInstanceStatus := lookupAppInstanceStatus(ctx, volumesSnapshotStatus.AppUUID.String())
	if appInstanceStatus == nil {
		// handleCreateAppInstanceStatus looks at the snapshots.
		log.Noticef("handleVolumesSnapshotStatusImpl: no AppInstanceStatus for %s", volumesSnapshotStatus.AppUUID)
		return
	}
	if volumesSnapshotStatus.State == types.VolumesSnapshotStateCreated {
		if err := keepSnapshotRecord(ctx, volumesSnapshotStatus); err != nil {
			log.Errorf("handleVolumesSnapshotStatusImpl: no record of snapshot %s: %s",
				volumesSnapshotStatus.SnapshotID, err)
		}
	}
	snapState := &appInstanceStatus.SnapStatus
	if snapState.RollbackInProgress && !snapState.HasRollbackRequest &&
		snapState.ActiveSnapshot == volumesSnapshotStatus.SnapshotID &&
		rollbackAnswered(ctx, volumesSnapshotStatus) {
		reactToSnapshotRollback(ctx, volumesSnapshotStatus)
		return
	}
	if newError {
		appInstanceStatus.Error = volumesSnapshotStatus.Error
		appInstanceStatus.ErrorTime = volumesSnapshotStatus.ErrorTime
	}
	refreshSnapshots(ctx, appInstanceStatus)
	publishAppInstanceStatus(ctx, appInstanceStatus)
	if volumesSnapshotStatus.Busy() {
		return
	}
	updateAIStatusUUID(ctx, volumesSnapshotStatus.AppUUID.String())
}

// handleVolumesSnapshotStatusDelete is how volumemgr says that a snapshot is
// deleted.
func handleVolumesSnapshotStatusDelete(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	volumesSnapshotStatus := statusArg.(types.VolumesSnapshotStatus)
	log.Noticef("handleVolumesSnapshotStatusDelete(%s)", key)
	_ = DeleteSnapshotFiles(volumesSnapshotStatus.SnapshotID)
	appInstanceStatus := lookupAppInstanceStatus(ctx, volumesSnapshotStatus.AppUUID.String())
	if appInstanceStatus == nil {
		return
	}
	refreshSnapshots(ctx, appInstanceStatus)
	publishAppInstanceStatus(ctx, appInstanceStatus)
	updateAIStatusUUID(ctx, volumesSnapshotStatus.AppUUID.String())
}

// handleVolumesSnapshotStatusRestarted is how volumemgr says that it has
// published all snapshots that exist.
func handleVolumesSnapshotStatusRestarted(ctxArg interface{}, restartCounter int) {
	ctx := ctxArg.(*zedmanagerContext)
	log.Noticef("handleVolumesSnapshotStatusRestarted(%d)", restartCounter)
	if restartCounter == 0 || ctx.snapshotsRestored {
		return
	}
	// No app was started so far, and none is before the snapshots allow it.
	restoreSnapshotConfigs(ctx)
	_ = ctx.pubVolumesSnapConfig.SignalRestarted()
	ctx.snapshotsRestored = true
	for _, st := range ctx.pubAppInstanceStatus.GetAll() {
		appInstanceStatus := st.(types.AppInstanceStatus)
		config := lookupAppInstanceConfig(ctx, appInstanceStatus.Key(), true)
		if config == nil {
			continue
		}
		updateSnapshotsInAIStatus(ctx, &appInstanceStatus, *config)
		publishAppInstanceStatus(ctx, &appInstanceStatus)
		updateAIStatusUUID(ctx, appInstanceStatus.Key())
	}
}

/* Helper functions for the VolumesSnapshotStatus handlers */

func serializeSnapshotInstanceStatus(moved *types.SnapshotInstanceStatus) error {
	log.Noticef("serializeSnapshotInstanceStatus")
	snapshotDir := types.GetSnapshotDir(moved.Snapshot.SnapshotID)
	// check that the directory exists (it should exist by this moment)
	if _, err := os.Stat(snapshotDir); err != nil {
		log.Errorf("serializeSnapshotInstanceStatus: Snapshot directory %s not found", snapshotDir)
		return fmt.Errorf("snapshot directory %s not found", snapshotDir)
	}
	snapshotInstanceStatusFilename := types.GetSnapshotInstanceStatusFile(moved.Snapshot.SnapshotID)
	// serialize the SnapshotInstanceStatus into the file (JSON)
	data, err := json.Marshal(moved)
	if err != nil {
		log.Errorf("serializeSnapshotInstanceStatus: Failed to marshal SnapshotInstanceStatus: %s", err)
		return fmt.Errorf("failed to marshal SnapshotInstanceStatus: %s", err)
	}
	err = fileutils.WriteRename(snapshotInstanceStatusFilename, data)
	if err != nil {
		log.Errorf("serializeSnapshotInstanceStatus: Failed to write SnapshotInstanceStatus to file: %s", err)
		return fmt.Errorf("failed to write SnapshotInstanceStatus to file: %s", err)
	}
	return nil
}

func deserializeSnapshotInstanceStatus(snapshotID string) (*types.SnapshotInstanceStatus, error) {
	log.Noticef("deserializeSnapshotInstanceStatus")
	// get the filename
	snapshotInstanceStatusFilename := types.GetSnapshotInstanceStatusFile(snapshotID)

	snapshotInstanceStatus := new(types.SnapshotInstanceStatus)
	err := utils.DeserializeToStruct(snapshotInstanceStatusFilename, snapshotInstanceStatus)
	if err != nil {
		log.Errorf("deserializeSnapshotInstanceStatus: Failed to deserialize SnapshotInstanceStatus: %s", err)
		return nil, fmt.Errorf("failed to deserialize SnapshotInstanceStatus: %s", err)
	}
	return snapshotInstanceStatus, nil
}

func restoreAppInstanceConfigFromSnapshot(ctx *zedmanagerContext, appInstanceStatus *types.AppInstanceStatus, snapshotID string) (*types.AppInstanceConfig, error) {
	log.Noticef("restoreAppInstanceConfigFromSnapshot")

	if lookupSnapshot(appInstanceStatus, snapshotID) == nil {
		return nil, fmt.Errorf("SnapshotInstanceStatus not found for %s", snapshotID)
	}
	// Get the app instance config from the snapshot
	snappedAppInstanceConfig := deserializeAppInstanceConfigFromSnapshot(snapshotID)
	if snappedAppInstanceConfig == nil {
		return nil, fmt.Errorf("failed to read AppInstanceConfig from file for %s", snapshotID)
	}
	config, err := fixupAppInstanceConfig(ctx, appInstanceStatus, snappedAppInstanceConfig)
	if err != nil {
		return config, err
	}
	return config, nil
}

// fixupAppInstanceConfig adds the fixes into the snapped app instance config.
// The fixes are the information that should be taken from the current app instance config, not from the snapshot.
// The fixes should correspond to the fixes done on the controller side. A function name, where it's done maybe
// something like: applyAppInstanceFromSnapshot.
func fixupAppInstanceConfig(ctx *zedmanagerContext, appInstanceStatus *types.AppInstanceStatus, snappedAppInstanceConfig *types.AppInstanceConfig) (*types.AppInstanceConfig, error) {
	// Get the app instance config from the app instance status
	currentAppInstanceConfig := lookupAppInstanceConfig(ctx, appInstanceStatus.Key(), true)
	if currentAppInstanceConfig == nil {
		return nil, fmt.Errorf("AppInstanceConfig not found for %s", appInstanceStatus.Key())
	}
	// Sync the information about available snapshots
	snappedAppInstanceConfig.Snapshot.Snapshots = make([]types.SnapshotDesc, len(currentAppInstanceConfig.Snapshot.Snapshots))
	copy(snappedAppInstanceConfig.Snapshot.Snapshots, currentAppInstanceConfig.Snapshot.Snapshots)
	snappedAppInstanceConfig.Snapshot.MaxSnapshots = currentAppInstanceConfig.Snapshot.MaxSnapshots
	// Restore the restart and purge commands counters
	snappedAppInstanceConfig.PurgeCmd = currentAppInstanceConfig.PurgeCmd
	snappedAppInstanceConfig.LocalPurgeCmd = currentAppInstanceConfig.LocalPurgeCmd
	snappedAppInstanceConfig.RestartCmd = currentAppInstanceConfig.RestartCmd
	snappedAppInstanceConfig.LocalRestartCmd = currentAppInstanceConfig.LocalRestartCmd
	return snappedAppInstanceConfig, nil
}

// deserializeAppInstanceConfigFromSnapshot deserializes the config from a file
func deserializeAppInstanceConfigFromSnapshot(snapshotID string) *types.AppInstanceConfig {
	log.Noticef("deserializeAppInstanceConfigFromSnapshot")
	filename := types.GetSnapshotAppInstanceConfigFile(snapshotID)
	var appInstanceConfig types.AppInstanceConfig
	configFile, err := os.Open(filename)
	if err != nil {
		log.Errorf("deserializeAppInstanceConfigFromSnapshot: Open failed %s", err)
		return nil
	}
	defer configFile.Close()
	jsonParser := json.NewDecoder(configFile)
	if err = jsonParser.Decode(&appInstanceConfig); err != nil {
		log.Errorf("deserializeAppInstanceConfigFromSnapshot: Decode failed %s", err)
		return nil
	}
	return &appInstanceConfig
}

/* Functions to publish/unpublish VolumesSnapshotConfig */

func publishVolumesSnapshotConfig(ctx *zedmanagerContext, t *types.VolumesSnapshotConfig) {
	key := t.Key()
	log.Tracef("publishVolumesSnapshotConfig(%s)", key)
	pub := ctx.pubVolumesSnapConfig
	_ = pub.Publish(key, *t)
}

func unpublishVolumesSnapshotConfig(ctx *zedmanagerContext, t *types.VolumesSnapshotConfig) {
	key := t.Key()
	log.Tracef("unpublishVolumesSnapshotConfig(%s)", key)
	pub := ctx.pubVolumesSnapConfig
	_ = pub.Unpublish(key)
}
