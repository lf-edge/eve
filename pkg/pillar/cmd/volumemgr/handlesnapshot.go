// Copyright (c) 2013-2023 Zededa,
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/volumehandlers"
)

func createSnapshot(ctx *volumemgrContext, config *types.VolumesSnapshotConfig) *types.VolumesSnapshotStatus {
	// Check if snapshot volumesSnapshotStatus already exists, or it's a new snapshot request
	volumesSnapshotStatus := lookupVolumesSnapshotStatus(ctx, config.SnapshotID)
	if volumesSnapshotStatus != nil {
		warnMsg := fmt.Sprintf("Snapshot %s already exists", config.SnapshotID)
		log.Warn(warnMsg)
		errDesc := types.ErrorDescription{}
		errDesc.Error = warnMsg
		errDesc.ErrorSeverity = types.ErrorSeverityWarning
		volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
		return volumesSnapshotStatus
	}
	// Create a new volumesSnapshotStatus
	volumesSnapshotStatus = &types.VolumesSnapshotStatus{
		SnapshotID:         config.SnapshotID,
		VolumeSnapshotMeta: make(map[string]interface{}, len(config.VolumeIDs)),
		AppUUID:            config.AppUUID,
	}
	// Find the corresponding volume status
	for _, volumeID := range config.VolumeIDs {
		volumeStatus := ctx.lookupVolumeStatusByUUID(volumeID.String())
		if volumeStatus == nil {
			errDesc := types.ErrorDescription{}
			errDesc.Error = fmt.Sprintf("createSnapshot: volume %s not found", volumeID.String())
			log.Errorf(errDesc.Error)
			volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
			return volumesSnapshotStatus
		}
		volumeHandler := volumehandlers.GetVolumeHandler(log, ctx, volumeStatus)
		snapshotMeta, timeCreated, err := volumeHandler.CreateSnapshot()
		if err != nil {
			errDesc := types.ErrorDescription{}
			errDesc.Error = fmt.Sprintf("createSnapshot: failed to create snapshot for %s, %s", volumeID.String(), err.Error())
			log.Errorf(errDesc.Error)
			volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
			return volumesSnapshotStatus
		}
		// Save the snapshot metadata (for example, snapshot file location), so later it can be used for rollback
		volumesSnapshotStatus.VolumeSnapshotMeta[volumeID.String()] = snapshotMeta
		// Save the time when the snapshot was created
		volumesSnapshotStatus.TimeCreated = timeCreated
	}
	err := serializeVolumesSnapshotStatus(config.SnapshotID, volumesSnapshotStatus)
	if err != nil {
		errDesc := types.ErrorDescription{}
		errDesc.Error = fmt.Sprintf("handleVolumesSnapshotConfigCreate: failed to serialize snapshot status for %s, %s", config.SnapshotID, err.Error())
		log.Errorf(errDesc.Error)
		volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
	}
	return volumesSnapshotStatus
}

func serializeVolumesSnapshotStatus(snapshotID string, status *types.VolumesSnapshotStatus) error {
	// check if the snapshot directory exists
	snapshotDir := types.GetSnapshotDir(snapshotID)
	if _, err := os.Stat(snapshotDir); os.IsNotExist(err) {
		// Create the directory
		err = os.MkdirAll(snapshotDir, 0755)
		if err != nil {
			log.Errorf("serializeVolumesSnapshotStatus: failed to create snapshot directory %s, %s", snapshotDir, err.Error())
			return err
		}
	}
	// marshal to JSON
	statusAsBytes, err := json.Marshal(status)
	if err != nil {
		log.Errorf("serializeVolumesSnapshotStatus: failed to marshal snapshot status for %s, %s", snapshotID, err.Error())
		return err
	}
	// Get the filename for the snapshot status
	volumesSnapshotStatusFile := types.GetVolumesSnapshotStatusFile(snapshotID)
	// Write the status to the file
	err = fileutils.WriteRename(volumesSnapshotStatusFile, statusAsBytes)
	if err != nil {
		log.Errorf("serializeVolumesSnapshotStatus: failed to write snapshot status for %s, %s", snapshotID, err.Error())
		return err
	}
	return nil
}

func deserializeVolumesSnapshotStatus(snapshotID string) (*types.VolumesSnapshotStatus, error) {
	// Get the filename for the snapshot status
	volumesSnapshotStatusFilename := types.GetVolumesSnapshotStatusFile(snapshotID)

	// check if the volumesSnapshotStatusFile exists
	if _, err := os.Stat(volumesSnapshotStatusFilename); os.IsNotExist(err) {
		log.Errorf("deserializeVolumesSnapshotStatus: snapshot status file %s does not exist", volumesSnapshotStatusFilename)
		return nil, err
	}

	// open the file
	volumesSnapshotStatusFile, err := os.Open(volumesSnapshotStatusFilename)
	if err != nil {
		log.Errorf("deserializeVolumesSnapshotStatus: failed to open snapshot status file %s, %s", volumesSnapshotStatusFilename, err.Error())
		return nil, err
	}
	defer volumesSnapshotStatusFile.Close()

	// read the raw data
	data, err := io.ReadAll(volumesSnapshotStatusFile)
	if err != nil {
		log.Errorf("deserializeVolumesSnapshotStatus: failed to read snapshot status for %s, %s", snapshotID, err.Error())
		return nil, err
	}

	// read to an opaque map to check the fields
	var dataMap map[string]interface{}
	err = json.Unmarshal(data, &dataMap)
	if err != nil {
		log.Errorf("deserializeVolumesSnapshotStatus: failed to unmarshal snapshot status for %s, %s", snapshotID, err.Error())
		return nil, err
	}

	// Automatically extract the field names from the struct using reflection.
	var volumeSnapshotStatus types.VolumesSnapshotStatus
	expectedFields := make(map[string]bool)
	v := reflect.ValueOf(volumeSnapshotStatus)
	typeOfVolumesSnapshotStatus := v.Type()
	utils.ExtractFields(typeOfVolumesSnapshotStatus, &expectedFields)

	// Check if there are any unexpected fields
	for k := range dataMap {
		if _, ok := expectedFields[k]; !ok {
			// This is an unexpected field, make warning and ignore
			log.Warnf("deserializeVolumesSnapshotStatus: unexpected field %s in stored volumes snapshot status for %s", k, snapshotID)
		}
	}

	// Check if there are any missing fields
	for k := range expectedFields {
		if _, ok := dataMap[k]; !ok {
			// This is a missing field, check if it is critical
			if types.VolumesSnapshotStatusCriticalFields[k] {
				// This is a missing critical field, return error
				errMsg := fmt.Sprintf("deserializeVolumesSnapshotStatus: critical field %s missing in stored volumes snapshot status for %s", k, snapshotID)
				log.Errorf(errMsg)
				return nil, fmt.Errorf(errMsg)
			}
			// This is a missing non-critical field, make warning and ignore
			log.Warnf("deserializeVolumesSnapshotStatus: missing field %s in stored volumes snapshot status for %s", k, snapshotID)
		}
	}

	// All the checks passed, so it is safe to unmarshal the data into the struct

	// Unmarshal from JSON
	status := types.VolumesSnapshotStatus{}
	err = json.Unmarshal(data, &status)
	if err != nil {
		log.Errorf("deserializeVolumesSnapshotStatus: failed to unmarshal snapshot status for %s, %s", snapshotID, err.Error())
		return nil, err
	}
	log.Noticef("deserializeVolumesSnapshotStatus: successfully deserialized snapshot status for %s", snapshotID)
	return &status, nil
}

func rollbackSnapshot(ctx *volumemgrContext, config *types.VolumesSnapshotConfig) *types.VolumesSnapshotStatus {
	// Check if snapshot status already exists, or it's a new snapshot request
	volumesSnapshotStatus := lookupVolumesSnapshotStatus(ctx, config.SnapshotID)
	if volumesSnapshotStatus == nil {
		// Create a new volumesSnapshotStatus to report an error
		volumesSnapshotStatus = &types.VolumesSnapshotStatus{SnapshotID: config.SnapshotID}
		errDesc := types.ErrorDescription{}
		errDesc.Error = fmt.Sprintf("rollbackSnapshot: snapshot %s not found", config.SnapshotID)
		log.Error(errDesc.Error)
		volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
		return volumesSnapshotStatus
	}
	for volumeID, snapMeta := range volumesSnapshotStatus.VolumeSnapshotMeta {
		volumeStatus := ctx.lookupVolumeStatusByUUID(volumeID)
		if volumeStatus == nil {
			errDesc := types.ErrorDescription{}
			errDesc.Error = fmt.Sprintf("handleVolumesSnapshotConfigModify: volume %s not found", volumeID)
			log.Error(errDesc.Error)
			volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
			return volumesSnapshotStatus
		}
		volumeHandlers := volumehandlers.GetVolumeHandler(log, ctx, volumeStatus)
		log.Noticef("handleVolumesSnapshotConfigModify: rollback to snapshot %s for volume %s", config.SnapshotID, volumeID)
		err := volumeHandlers.RollbackToSnapshot(snapMeta)
		if err != nil {
			errDesc := types.ErrorDescription{}
			errDesc.Error = fmt.Sprintf("Failed to rollback to snapshot %s for volume %s, %s", config.SnapshotID, volumeID, err.Error())
			log.Error(errDesc.Error)
			volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
			return volumesSnapshotStatus
		}
		log.Noticef("handleVolumesSnapshotConfigModify: successfully rolled back to snapshot %s for volume %s", config.SnapshotID, volumeID)
	}
	return volumesSnapshotStatus
}

func deleteSnapshot(ctx *volumemgrContext, config *types.VolumesSnapshotConfig) *types.VolumesSnapshotStatus {
	volumesSnapshotStatus := lookupVolumesSnapshotStatus(ctx, config.SnapshotID)
	if volumesSnapshotStatus == nil {
		// Create a new volumesSnapshotStatus to report an error
		volumesSnapshotStatus = &types.VolumesSnapshotStatus{SnapshotID: config.SnapshotID}
		errDesc := types.ErrorDescription{}
		errDesc.Error = fmt.Sprintf("deleteSnapshot: snapshot %s not found", config.SnapshotID)
		log.Error(errDesc.Error)
		volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
		return volumesSnapshotStatus
	}
	for volumeUUID, snapMeta := range volumesSnapshotStatus.VolumeSnapshotMeta {
		volumeStatus := ctx.lookupVolumeStatusByUUID(volumeUUID)
		if volumeStatus == nil {
			errDesc := types.ErrorDescription{}
			errDesc.Error = fmt.Sprintf("deleteSnapshot: volume %s not found", volumeUUID)
			log.Error(errDesc.Error)
			volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
			return volumesSnapshotStatus
		}
		volumeHandlers := volumehandlers.GetVolumeHandler(log, ctx, volumeStatus)
		log.Noticef("deleteSnapshot: delete snapshot %s for volume %s", config.SnapshotID, volumeUUID)
		err := volumeHandlers.DeleteSnapshot(snapMeta)
		if err != nil {
			errDesc := types.ErrorDescription{}
			errDesc.Error = fmt.Sprintf("deleteSnapshot: failed to delete snapshot %s for volume %s, %s", config.SnapshotID, volumeUUID, err.Error())
			log.Error(errDesc.Error)
			volumesSnapshotStatus.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
			return volumesSnapshotStatus
		}
		log.Noticef("deleteSnapshot: successfully deleted snapshot %s for volume %s", config.SnapshotID, volumeUUID)
	}
	return volumesSnapshotStatus
}

func handleVolumesSnapshotConfigImpl(ctx *volumemgrContext, config types.VolumesSnapshotConfig) {
	log.Noticef("handleVolumesSnapshotConfigImpl(%s) handles %s", config.SnapshotID, config.Action)
	var volumesSnapshotStatus *types.VolumesSnapshotStatus
	switch config.Action {
	case types.VolumesSnapshotCreate:
		volumesSnapshotStatus = createSnapshot(ctx, &config)
		volumesSnapshotStatus.ResultOfAction = types.VolumesSnapshotCreate
		publishVolumesSnapshotStatus(ctx, volumesSnapshotStatus)
	case types.VolumesSnapshotRollback:
		volumesSnapshotStatus = rollbackSnapshot(ctx, &config)
		volumesSnapshotStatus.ResultOfAction = types.VolumesSnapshotRollback
		publishVolumesSnapshotStatus(ctx, volumesSnapshotStatus)
	case types.VolumesSnapshotDelete:
		volumesSnapshotStatus = deleteSnapshot(ctx, &config)
		volumesSnapshotStatus.ResultOfAction = types.VolumesSnapshotDelete
		unpublishVolumesSnapshotStatus(ctx, volumesSnapshotStatus)
	}
	log.Noticef("handleVolumesSnapshotConfigImpl(%s) done", config.SnapshotID)
}

func handleVolumesSnapshotConfigCreate(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*volumemgrContext)
	config := configArg.(types.VolumesSnapshotConfig)
	log.Noticef("handleVolumesSnapshotConfigCreate(%s) handles %s", key, config.Action)
	handleVolumesSnapshotConfigImpl(ctx, config)
}

func handleVolumesSnapshotConfigModify(ctxArg interface{}, key string, configArg, _ interface{}) {
	ctx := ctxArg.(*volumemgrContext)
	config := configArg.(types.VolumesSnapshotConfig)
	log.Noticef("handleVolumesSnapshotConfigModify(%s) handles %s", key, config.Action)
	handleVolumesSnapshotConfigImpl(ctx, config)
}

func handleVolumesSnapshotConfigDelete(ctxArg interface{}, keyArg string, configArg interface{}) {
	ctx := ctxArg.(*volumemgrContext)
	config := configArg.(types.VolumesSnapshotConfig)
	log.Noticef("handleVolumesSnapshotConfigDelete(%s) handles %s", keyArg, config.Action)
	// Change the action to delete, as this handler is called when the config is deleted only
	config.Action = types.VolumesSnapshotDelete
	handleVolumesSnapshotConfigImpl(ctx, config)
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
	// First check if the status is already published
	sub := ctx.pubVolumesSnapStatus
	st, _ := sub.Get(key)
	if st != nil {
		status := st.(types.VolumesSnapshotStatus)
		return &status
	}
	// Does not exist in a published state, check if it exists in the store
	status, err := deserializeVolumesSnapshotStatus(key)
	if err != nil {
		return nil
	}
	return status
}
