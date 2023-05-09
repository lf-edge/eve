// Copyright (c) 2013-2023 Zededa,
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/volumehandlers"
	"time"
)

func handleVolumesSnapshotCreate(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*volumemgrContext)
	config := configArg.(types.VolumesSnapshotConfig)
	log.Noticef("handleVolumesSnapshotCreate(%s) handles %s", key, config.Action)
	// Check if snapshot snapshotStatus already exists, or it's a new snapshot request
	snapshotStatus := lookupVolumesSnapshotStatus(ctx, config.SnapshotID)
	if snapshotStatus != nil {
		log.Errorf("Snapshot %s already exists", config.SnapshotID)
		return
	}
	// Create a new snapshotStatus
	snapshotStatus = &types.VolumesSnapshotStatus{
		SnapshotID:         config.SnapshotID,
		VolumeSnapshotMeta: make(map[string]interface{}, len(config.VolumeIDs)),
		AppUUID:            config.AppUUID,
		// Save the config UUID and version, so it can be reported later to the controller during the rollback
	}
	if config.Action != types.VolumesSnapshotCreate {
		errDesc := types.ErrorDescription{}
		errDesc.Error = fmt.Sprintf("handleVolumesSnapshotCreate: unexpected action %s", config.Action)
		log.Error(errDesc.Error)
		snapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
		publishVolumesSnapshotStatus(ctx, snapshotStatus)
		return
	}
	// Find the corresponding volume status
	for _, volumeID := range config.VolumeIDs {
		volumeStatus := ctx.lookupVolumeStatusByUUID(volumeID.String())
		if volumeStatus == nil {
			errDesc := types.ErrorDescription{}
			errDesc.Error = fmt.Sprintf("handleVolumesSnapshotCreate: volume %s not found", volumeID.String())
			log.Errorf(errDesc.Error)
			snapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
			publishVolumesSnapshotStatus(ctx, snapshotStatus)
			return
		}
		log.Noticef("handleVolumesSnapshotCreate: volume %s file found %s", volumeID.String(), volumeStatus.FileLocation)
		snapshotMeta, timeCreated, err := createVolumeSnapshot(ctx, volumeStatus)
		if err != nil {
			errDesc := types.ErrorDescription{}
			errDesc.Error = fmt.Sprintf("handleVolumesSnapshotCreate: failed to create snapshot for %s, %s", volumeID.String(), err.Error())
			log.Errorf(errDesc.Error)
			snapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
			publishVolumesSnapshotStatus(ctx, snapshotStatus)
			return
		}
		// Save the snapshot metadata (for example, snapshot file location), so later it can be used for rollback
		snapshotStatus.VolumeSnapshotMeta[volumeID.String()] = snapshotMeta
		// Save the time when the snapshot was created
		snapshotStatus.TimeCreated = timeCreated
	}
	log.Noticef("handleVolumesSnapshotCreate: successfully created snapshot %s", config.SnapshotID)
	publishVolumesSnapshotStatus(ctx, snapshotStatus)
}

func createVolumeSnapshot(ctx *volumemgrContext, volumeStatus *types.VolumeStatus) (interface{}, time.Time, error) {
	volumeHandlers := volumehandlers.GetVolumeHandler(log, ctx, volumeStatus)
	log.Noticef("createVolumeSnapshot: create snapshot for %s", volumeStatus.VolumeID.String())
	snapshotMeta, timeCreated, err := volumeHandlers.CreateSnapshot()
	if err != nil {
		log.Errorf("createVolumeSnapshot: failed to create snapshot for %s, %s", volumeStatus.VolumeID.String(), err.Error())
		return "", timeCreated, err
	}
	log.Noticef("createVolumeSnapshot: successfully created snapshot for %s", volumeStatus.VolumeID.String())
	return snapshotMeta, timeCreated, nil
}

func handleVolumesSnapshotModify(ctxArg interface{}, key string, configArg, _ interface{}) {
	ctx := ctxArg.(*volumemgrContext)
	config := configArg.(types.VolumesSnapshotConfig)
	log.Functionf("handleVolumesSnapshotModify(%s) handles %s", key, config.Action)
	// Check if snapshot status already exists, or it's a new snapshot request
	volumesSnapshotStatus := lookupVolumesSnapshotStatus(ctx, config.SnapshotID)
	if volumesSnapshotStatus == nil {
		// Create a new volumesSnapshotStatus to report an error
		volumesSnapshotStatus = &types.VolumesSnapshotStatus{SnapshotID: config.SnapshotID}
		errDesc := types.ErrorDescription{}
		errDesc.Error = fmt.Sprintf("handleVolumesSnapshotModify: snapshot %s not found", key)
		log.Error(errDesc.Error)
		volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
		publishVolumesSnapshotStatus(ctx, volumesSnapshotStatus)
		return
	}
	if config.Action != types.VolumesSnapshotRollback {
		errDesc := types.ErrorDescription{}
		errDesc.Error = fmt.Sprintf("handleVolumesSnapshotModify: unexpected action %s", config.Action)
		log.Error(errDesc.Error)
		volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
		publishVolumesSnapshotStatus(ctx, volumesSnapshotStatus)
		return
	}
	for volumeID, snapMeta := range volumesSnapshotStatus.VolumeSnapshotMeta {
		volumeStatus := ctx.lookupVolumeStatusByUUID(volumeID)
		if volumeStatus == nil {
			errDesc := types.ErrorDescription{}
			errDesc.Error = fmt.Sprintf("handleVolumesSnapshotModify: volume %s not found", volumeID)
			log.Error(errDesc.Error)
			volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
			publishVolumesSnapshotStatus(ctx, volumesSnapshotStatus)
			return
		}
		volumeHandlers := volumehandlers.GetVolumeHandler(log, ctx, volumeStatus)
		log.Noticef("handleVolumesSnapshotModify: rollback to snapshot %s for volume %s", config.SnapshotID, volumeID)
		err := rollbackToSnapshot(volumeHandlers, snapMeta)
		if err != nil {
			errDesc := types.ErrorDescription{}
			errDesc.Error = fmt.Sprintf("Failed to rollback to snapshot %s for volume %s, %s", config.SnapshotID, volumeID, err.Error())
			log.Error(errDesc.Error)
			volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
			publishVolumesSnapshotStatus(ctx, volumesSnapshotStatus)
			return
		}
		log.Noticef("handleVolumesSnapshotModify: successfully rolled back to snapshot %s for volume %s", config.SnapshotID, volumeID)
	}
	log.Noticef("handleVolumesSnapshotModify: successfully rolled back to snapshot %s", config.SnapshotID)
	publishVolumesSnapshotStatus(ctx, volumesSnapshotStatus)
}

func handleVolumesSnapshotDelete(ctxArg interface{}, keyArg string, configArg interface{}) {
	ctx := ctxArg.(*volumemgrContext)
	config := configArg.(types.VolumesSnapshotConfig)
	log.Noticef("handleVolumesSnapshotDelete(%s)", keyArg)
	volumesSnapshotStatus := lookupVolumesSnapshotStatus(ctx, config.SnapshotID)
	if volumesSnapshotStatus == nil {
		// Create a new volumesSnapshotStatus to report an error
		volumesSnapshotStatus = &types.VolumesSnapshotStatus{SnapshotID: config.SnapshotID}
		errDesc := types.ErrorDescription{}
		errDesc.Error = fmt.Sprintf("handleVolumesSnapshotDelete: snapshot %s not found", keyArg)
		log.Error(errDesc.Error)
		volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
		publishVolumesSnapshotStatus(ctx, volumesSnapshotStatus)
		return
	}
	for volumeUUID, snapMeta := range volumesSnapshotStatus.VolumeSnapshotMeta {
		volumeStatus := ctx.lookupVolumeStatusByUUID(volumeUUID)
		if volumeStatus == nil {
			errDesc := types.ErrorDescription{}
			errDesc.Error = fmt.Sprintf("handleVolumesSnapshotDelete: volume %s not found", volumeUUID)
			log.Error(errDesc.Error)
			volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
			publishVolumesSnapshotStatus(ctx, volumesSnapshotStatus)
			return
		}
		volumeHandlers := volumehandlers.GetVolumeHandler(log, ctx, volumeStatus)
		log.Noticef("handleVolumesSnapshotDelete: delete snapshot %s for volume %s", config.SnapshotID, volumeUUID)
		err := deleteSnapshot(volumeHandlers, snapMeta)
		if err != nil {
			errDesc := types.ErrorDescription{}
			errDesc.Error = fmt.Sprintf("Failed to delete snapshot %s for volume %s, %s", config.SnapshotID, volumeUUID, err.Error())
			log.Error(errDesc.Error)
			volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
			publishVolumesSnapshotStatus(ctx, volumesSnapshotStatus)
			return
		}
		log.Noticef("handleVolumesSnapshotDelete: successfully deleted snapshot %s for volume %s", config.SnapshotID, volumeUUID)
		// Decrement the refcount for the volume, so it can be deleted if needed
		currentVolumeRefConfig := lookupVolumeRefConfig(ctx, volumeStatus.Key())
		newVolumeRefConfig := types.VolumeRefConfig{
			VolumeID:               currentVolumeRefConfig.VolumeID,
			GenerationCounter:      currentVolumeRefConfig.GenerationCounter,
			LocalGenerationCounter: currentVolumeRefConfig.LocalGenerationCounter,
			RefCount:               currentVolumeRefConfig.RefCount - 1,
			MountDir:               currentVolumeRefConfig.MountDir,
			VerifyOnly:             currentVolumeRefConfig.VerifyOnly,
		}
		log.Noticef("handleVolumesSnapshotDelete: decrementing refcount for volume %s to %d", volumeUUID, newVolumeRefConfig.RefCount)
		handleVolumeRefModify(ctx, volumeStatus.Key(), newVolumeRefConfig, *currentVolumeRefConfig)
	}
	unpublishVolumesSnapshotStatus(ctx, volumesSnapshotStatus)
	log.Noticef("handleVolumesSnapshotDelete(%s) done", keyArg)
}

func rollbackToSnapshot(volumeHandlers volumehandlers.VolumeHandler, meta interface{}) error {
	log.Noticef("rollbackToSnapshot: rollback to snapshot")
	err := volumeHandlers.RollbackToSnapshot(meta)
	if err != nil {
		log.Errorf("rollbackToSnapshot: failed to rollback to snapshot")
		return err
	}
	log.Noticef("rollbackToSnapshot: successfully rolled back to snapshot")
	return nil
}

func deleteSnapshot(volumeHandlers volumehandlers.VolumeHandler, meta interface{}) error {
	log.Noticef("deleteSnapshot: delete snapshot")
	err := volumeHandlers.DeleteSnapshot(meta)
	if err != nil {
		log.Errorf("deleteSnapshot: failed to delete snapshot")
		return err
	}
	log.Noticef("deleteSnapshot: successfully deleted snapshot")
	return nil
}

func publishVolumesSnapshotStatus(ctx *volumemgrContext, status *types.VolumesSnapshotStatus) {
	key := status.Key()
	log.Functionf("publishVolumesSnapshotStatus(%s)", key)
	pub := ctx.pubVolumesSnapStatus
	_ = pub.Publish(key, *status)
}

func unpublishVolumesSnapshotStatus(ctx *volumemgrContext, status *types.VolumesSnapshotStatus) {
	key := status.Key()
	log.Functionf("unpublishVolumesSnapshotStatus(%s)", key)
	pub := ctx.pubVolumesSnapStatus
	pub.Unpublish(key)
}

func lookupVolumesSnapshotStatus(ctx *volumemgrContext, key string) *types.VolumesSnapshotStatus {
	sub := ctx.pubVolumesSnapStatus
	st, _ := sub.Get(key)
	if st == nil {
		return nil
	}
	status := st.(types.VolumesSnapshotStatus)
	return &status
}
