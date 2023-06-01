// Copyright (c) 2013-2023 Zededa,
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cmd/zedmanager"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/volumehandlers"
)

func handleVolumesSnapshotCreate(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*volumemgrContext)
	config := configArg.(types.VolumesSnapshotConfig)
	log.Noticef("handleVolumesSnapshotCreate(%s) handles %s", key, config.Action)
	// Check if snapshot snapshotStatus already exists, or it's a new snapshot request
	snapshotStatus := lookupVolumesSnapshotStatus(ctx, config.SnapshotID)
	if snapshotStatus != nil {
		log.Warnf("Snapshot %s already exists", config.SnapshotID)
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
		// Serialize the volume status
		err = serializeVolumeStatus(volumeStatus, config.SnapshotID)
		if err != nil {
			errDesc := types.ErrorDescription{}
			errDesc.Error = fmt.Sprintf("handleVolumesSnapshotCreate: failed to serialize volume status for %s, %s", volumeID.String(), err.Error())
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

func serializeVolumeStatus(status *types.VolumeStatus, snapshotID string) error {
	log.Noticef("serializeVolumeStatus(%s) for %s", snapshotID, status.VolumeID.String())
	// create volume status dir if it doesn't exist
	volumeStatusDir := getVolumeStatusDir(snapshotID)
	if _, err := os.Stat(volumeStatusDir); os.IsNotExist(err) {
		log.Noticef("serializeVolumeStatus(%s) creating volume status dir %s", snapshotID, volumeStatusDir)
		err = os.MkdirAll(volumeStatusDir, 0755)
		if err != nil {
			log.Errorf("serializeVolumeStatus(%s) failed to create volume status dir %s", snapshotID, volumeStatusDir)
			return err
		}
		log.Noticef("serializeVolumeStatus(%s) successfully created volume status dir %s", snapshotID, volumeStatusDir)
	}
	fileName := getVolumeStatusFileName(status.VolumeID.String(), snapshotID)
	// Serialize the volume status
	statusAsBytes, err := json.Marshal(status)
	if err != nil {
		log.Errorf("serializeVolumeStatus(%s) failed to marshal volume status for %s", snapshotID, status.VolumeID.String())
		return err
	}
	// Create the file for storing the volume ref status
	err = fileutils.WriteRename(fileName, statusAsBytes)
	if err != nil {
		log.Errorf("serializeVolumeStatus(%s) failed to write volume status for %s", snapshotID, status.VolumeID.String())
		return err
	}
	return nil
}

func deserializeVolumeStatus(volumeID string, snapshotID string) (*types.VolumeStatus, error) {
	log.Noticef("deserializeVolumeStatus(%s) for %s", snapshotID, volumeID)

	fileName := getVolumeStatusFileName(volumeID, snapshotID)
	// Try to open the file, check weather it exits
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		log.Errorf("Failed to find the volume status file for %s", volumeID)
		return nil, err
	}
	// open the file
	volumeStatusFile, err := os.Open(fileName)
	if err != nil {
		log.Errorf("Failed to open the volume status file for %s", volumeID)
		return nil, err
	}
	defer volumeStatusFile.Close()
	volumeStatus := types.VolumeStatus{}
	// decode the file
	err = json.NewDecoder(volumeStatusFile).Decode(&volumeStatus)
	if err != nil {
		log.Errorf("Failed to decode the volume status file for %s", volumeID)
		return nil, err
	}
	log.Noticef("deserializeVolumeStatus(%s) successfully deserialized volume status for %s", snapshotID, volumeID)
	return &volumeStatus, nil
}

func getVolumeStatusDir(snapshotID string) string {
	return fmt.Sprintf("%s/%s", zedmanager.GetSnapshotDir(snapshotID), types.VolumeStatusDirName)
}

func getVolumeStatusFileName(volumeID string, snapshotID string) string {
	return fmt.Sprintf("%s/%s.json", getVolumeStatusDir(snapshotID), volumeID)
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
		// First try to find the volume status in the active publisher
		volumeStatus := ctx.lookupOrCreateVolumeStatusByUUID(volumeID, config.SnapshotID)
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
	// Increment the refCount to indicate that the snapshot is being used and trigger the modify handler
	volumesSnapshotStatus.RefCount++
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
		volumeStatus := ctx.lookupOrCreateVolumeStatusByUUID(volumeUUID, config.SnapshotID)
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
