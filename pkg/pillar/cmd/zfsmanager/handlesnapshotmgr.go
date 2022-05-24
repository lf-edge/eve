package zfsmanager

import (
	"fmt"
	"strconv"
	"time"

	libzfs "github.com/bicomsystems/go-libzfs"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

// syncSnapshotZfsProperties - synchronizes snapshot information
// between zfsmanager and ZFS
func syncSnapshotZfsProperties(snapshotStatus *types.ZfsSnapshotStatus) (bool, error) {
	if snapshotStatus.CurrentState != types.SnapshotStateCreated {
		return false, nil
	}
	dataset, err := libzfs.DatasetOpen(snapshotStatus.Path())
	if err != nil {
		return false, fmt.Errorf("syncSnapshotZfsProperties: cannot open snapshot: %s", err)
	}
	defer dataset.Close()

	var changed bool
	usedSpaceProp, err := dataset.GetProperty(libzfs.DatasetPropUsed)
	if err != nil {
		return changed, fmt.Errorf("syncSnapshotZfsProperties: get property used for dataset failed: %v", err)
	}
	usedSpace, err := strconv.ParseUint(usedSpaceProp.Value, 10, 64)
	if err != nil {
		return changed, fmt.Errorf("syncSnapshotZfsProperties: convert used value failed: %v", err)
	}
	if usedSpace != snapshotStatus.UsedSpace {
		snapshotStatus.UsedSpace = usedSpace
		changed = true
	}

	referencedProp, err := dataset.GetProperty(libzfs.DatasetPropReferenced)
	if err != nil {
		return changed, fmt.Errorf("syncSnapshotZfsProperties: get property used for dataset failed: %v", err)
	}
	referenced, err := strconv.ParseUint(referencedProp.Value, 10, 64)
	if err != nil {
		return changed, fmt.Errorf("syncSnapshotZfsProperties: convert referenced space value failed: %v", err)
	}
	if referenced != snapshotStatus.Referenced {
		snapshotStatus.Referenced = referenced
		changed = true
	}

	compressratioProp, err := dataset.GetProperty(libzfs.DatasetPropCompressratio)
	if err != nil {
		return changed, fmt.Errorf("syncSnapshotZfsProperties: get property compressratio for dataset failed %v", err)
	}
	compressratio, err := strconv.ParseFloat(compressratioProp.Value, 64)
	if err != nil {
		return changed, fmt.Errorf("syncSnapshotZfsProperties: convert compressratio value failed: %v", err)
	}
	if compressratio != snapshotStatus.Compressratio {
		snapshotStatus.Compressratio = compressratio
		changed = true
	}

	volSizeProp, err := dataset.GetProperty(libzfs.DatasetPropVolsize)
	if err != nil {
		return changed, fmt.Errorf("syncSnapshotZfsProperties: get property volsize for dataset failed %v", err)
	}
	volSize, err := strconv.ParseUint(volSizeProp.Value, 10, 64)
	if err != nil {
		return changed, fmt.Errorf("syncSnapshotZfsProperties: convert volsize value failed: %v", err)
	}
	if volSize != snapshotStatus.VolSize {
		snapshotStatus.VolSize = volSize
		changed = true
	}

	creationTimeProp, err := dataset.GetProperty(libzfs.DatasetPropCreation)
	if err != nil {
		return changed, fmt.Errorf("syncSnapshotZfsProperties: get property creatinonTime for dataset failed: %v", err)
	}
	creationTime, err := strconv.ParseUint(creationTimeProp.Value, 10, 64)
	if err != nil {
		return changed, fmt.Errorf("syncSnapshotZfsProperties: convert creatinonTime value failed: %v", err)
	}
	if creationTime != snapshotStatus.CreationTime {
		snapshotStatus.CreationTime = creationTime
		changed = true
	}

	logicalreferencedProp, err := dataset.GetProperty(libzfs.DatasetPropLogicalreferenced)
	if err != nil {
		return changed, fmt.Errorf("syncSnapshotZfsProperties: get property logicalreferenced for dataset failed: %v", err)
	}
	logicalreferenced, err := strconv.ParseUint(logicalreferencedProp.Value, 10, 64)
	if err != nil {
		return changed, fmt.Errorf("syncSnapshotZfsProperties: convert logicalreferenced space value failed: %v", err)
	}
	if logicalreferenced != snapshotStatus.Logicalreferenced {
		snapshotStatus.Logicalreferenced = logicalreferenced
		changed = true
	}

	return changed, nil
}

// checkAppInstanceIsHaltedState return true if AppInstance is halted
func checkAppInstanceIsHaltedState(ctx *zfsContext, volumeUUID string) bool {
	for _, ap := range ctx.subAppInstanceStatus.GetAll() {
		appStatus := ap.(types.AppInstanceStatus)
		for _, vol := range appStatus.VolumeRefStatusList {
			if vol.VolumeID.String() == volumeUUID {
				if appStatus.State == types.HALTED {
					return true
				}
				return false
			}
		}
	}
	return false
}

// doSnapshotStatusUpdate - updates the status for a snapshot.
// Return true if changed
func doSnapshotStatusUpdate(ctx *zfsContext, snapshotStatus *types.ZfsSnapshotStatus) bool {
	var changed bool
	if snapshotStatus.CurrentState == types.SnapshotStateDeleted {
		return changed
	}

	if snapshotStatus.ZvolPath == "" {
		changed = true
		volumeStatus := getVolumeStatusByUUID(ctx, snapshotStatus.VolumeUUID)
		if volumeStatus == nil {
			log.Errorf("volume %s not found for snapshot %s", snapshotStatus.VolumeUUID, snapshotStatus.UUID)
			return changed
		}
		if volumeStatus.State < types.CREATED_VOLUME {
			return changed
		}
		snapshotStatus.ZvolPath = volumeStatus.ZVolName()
	}

	appInstanceHalted := checkAppInstanceIsHaltedState(ctx, snapshotStatus.VolumeUUID)

	if !zfs.DoesSnapshotExist(snapshotStatus.Path()) {
		changed = true
		if snapshotStatus.CurrentState == types.SnapshotStateCreating {
			// Create a new snapshot. This is the cmd to take the snapshot
			// Before this operation, you should execute the necessary code or
			// make sure that all processes and conditions for creating a
			// snapshot in EVE are created.
			// For example, check if an application instance is halted
			if appInstanceHalted {
				snapshotStatus.Error = fmt.Sprintf(
					"EVE waits for the application instance to change state to halted")
				return changed
			}

			dataset, err := zfs.CreateSnapshotInZfs(snapshotStatus.ZvolPath, snapshotStatus.UUID)
			if err != nil {
				// To report an error
				snapshotStatus.Error = fmt.Sprintf("create snapshot failed: %v", err)
				return changed
			}
			defer dataset.Close()

			snapshotStatus.CurrentState = types.SnapshotStateCreated
			snapshotStatus.Error = ""
			if _, err := syncSnapshotZfsProperties(snapshotStatus); err != nil {
				log.Errorf("snapshotPropertiesFill: %s", err)
			}
		} else if snapshotStatus.CurrentState == types.SnapshotStateCreated {
			snapshotStatus.Error = fmt.Sprintf("snapshot %s not founf in ZFS", snapshotStatus.UUID)
			snapshotStatus.CurrentState = types.SnapshotStateDeleted
		}
	} else {
		if snapshotStatus.CurrentState == types.SnapshotStateCreated {
			// UPDATE status
			snapshotConfigObj, err := ctx.subSnapshotConfig.Get(snapshotStatus.Key())
			if err != nil {
				log.Errorf("cannot get snapshot config for %v", snapshotStatus.Key())
				return changed
			}

			snapshotConfig := snapshotConfigObj.(types.ZfsSnapshotConfig)
			if snapshotConfig.DisplayName != snapshotStatus.DisplayName {
				snapshotStatus.DisplayName = snapshotConfig.DisplayName
				changed = true
			}

			if snapshotStatus.RollbackCounter != snapshotConfig.RollbackCounter {
				changed = true
				if appInstanceHalted {
					snapshotStatus.Error = fmt.Sprintf(
						"EVE waits for the application instance to change state to halted")
					return changed
				}
				if err := zfs.RollbackSnapshotInZfs(snapshotStatus.ZvolPath, snapshotStatus.UUID); err != nil {
					snapshotStatus.Error = fmt.Sprintf("rollback snapshot failed. Err: %v", err)
					return changed
				}
				snapshotStatus.RollbackLastOpsTime = uint64(time.Now().Unix())
				snapshotStatus.RollbackCounter = snapshotConfig.RollbackCounter
				snapshotStatus.Error = ""
			}

		} else if snapshotStatus.CurrentState == types.SnapshotStateDeleting {
			changed = true
			err := zfs.DeleteSnapshotInZfs(snapshotStatus.Path())
			if err != nil {
				snapshotStatus.Error = fmt.Sprintf("delete snapshot failed. Err: %v", err)
				snapshotStatus.CurrentState = types.SnapshotStateDeleting
			} else {
				snapshotStatus.CurrentState = types.SnapshotStateDeleted
			}
		}
	}

	return changed
}

// getVolumeStatusByUUID - returns volume status for provided volumeUUID
func getVolumeStatusByUUID(ctx *zfsContext, volumeUUID string) *types.VolumeStatus {
	for _, vs := range ctx.subVolumeStatus.GetAll() {
		volumeStatus := vs.(types.VolumeStatus)
		if volumeUUID == volumeStatus.VolumeID.String() {
			return &volumeStatus
		}
	}
	return nil
}

// maybeUpdateSnapshotsStatus - check the status of all snapshots for zvol
func maybeUpdateSnapshotsStatus(ctx *zfsContext, volumeUUID string) {
	for _, vc := range ctx.pubSnapshotStatus.GetAll() {
		snapshot := vc.(types.ZfsSnapshotStatus)
		if snapshot.VolumeUUID == volumeUUID {
			if doSnapshotStatusUpdate(ctx, &snapshot) {
				publishSnapshotStatus(ctx, snapshot)
			}
		}
	}
}

// findSnapshotStatusByUUID looks for a snapshot with an snapUUID in a pubSnapshotStatus
func findSnapshotStatusByUUID(ctx *zfsContext, snapUUID string) (
	*types.ZfsSnapshotStatus, error) {
	snapStatusList := ctx.pubSnapshotStatus.GetAll()
	for _, vc := range snapStatusList {
		snapshotStatus := vc.(types.ZfsSnapshotStatus)
		if snapUUID == snapshotStatus.UUID {
			return &snapshotStatus, nil
		}
	}
	return nil, fmt.Errorf("snapshot status with UUID:%s not founf", snapUUID)
}

func handleSnapshotConfigCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleSnapshotConfigImpl(ctxArg, key, configArg, nil)
}

func handleSnapshotConfigModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleSnapshotConfigImpl(ctxArg, key, configArg, oldConfigArg)
}

func handleSnapshotConfigImpl(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	snapConfig := configArg.(types.ZfsSnapshotConfig)
	log.Functionf("handleSnapshotConfigImpl(%s)", key)
	ctx := ctxArg.(*zfsContext)
	cfgSnapUUID := snapConfig.Key()

	snapStatus, err := findSnapshotStatusByUUID(ctx, cfgSnapUUID)
	if err != nil {
		snapStatus = &types.ZfsSnapshotStatus{
			UUID:            cfgSnapUUID,
			VolumeUUID:      snapConfig.VolumeUUID,
			RollbackCounter: snapConfig.RollbackCounter,
			DisplayName:     snapConfig.DisplayName,
			CurrentState:    types.SnapshotStateCreating,
		}
	}
	if doSnapshotStatusUpdate(ctx, snapStatus) {
		publishSnapshotStatus(ctx, *snapStatus)
		maybeUpdateSnapshotsStatus(ctx, snapStatus.VolumeUUID)
	}
}

func handleSnapshotConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	snapConfig := configArg.(types.ZfsSnapshotConfig)
	ctx := ctxArg.(*zfsContext)
	log.Functionf("handleSnapshotConfigDelete(%s)", key)
	snapStatus, err := findSnapshotStatusByUUID(ctx, snapConfig.UUID)
	if err != nil {
		log.Errorf("cannot found snapshot status for %v", snapConfig.UUID)
		return
	}
	if snapStatus.CurrentState != types.SnapshotStateDeleted {
		err = zfs.DeleteSnapshotInZfs(snapStatus.Path())
		if err != nil {
			snapStatus.Error = fmt.Sprintf("delete snapshot failed. Err: %v", err)
			snapStatus.CurrentState = types.SnapshotStateDeleting
			publishSnapshotStatus(ctx, *snapStatus)
			return
		}
	}
	unpublishSnapshotStatus(ctx, snapStatus.UUID)
	log.Functionf("handleSnapshotConfigDelete(%s) DONE", key)
}

func publishSnapshotStatus(ctx *zfsContext,
	status types.ZfsSnapshotStatus) {
	key := status.Key()
	log.Tracef("publishSnapshotStatus(%s)\n", key)
	pub := ctx.pubSnapshotStatus
	pub.Publish(key, status)
	log.Tracef("publishSnapshotStatus(%s) done\n", key)
}

func unpublishSnapshotStatus(ctx *zfsContext, key string) {
	log.Tracef("unpublishSnapshotSattus(%s)\n", key)
	pub := ctx.pubSnapshotStatus
	status, _ := pub.Get(key)
	if status == nil {
		log.Errorf("unpublishSnapshotStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
	log.Tracef("unpublishSnapshotStatus(%s) done\n", key)
}

func handleVolumeStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleVolumeStatusImpl(ctxArg, key, statusArg, nil)
}

func handleVolumeStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleVolumeStatusImpl(ctxArg, key, statusArg, oldStatusArg)
}

func handleVolumeStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	volumeStatus := statusArg.(types.VolumeStatus)
	log.Functionf("handleVolumeStatusImpl(%s)", key)
	ctx := ctxArg.(*zfsContext)
	for _, el := range ctx.pubSnapshotStatus.GetAll() {
		snapshotStatus := el.(types.ZfsSnapshotStatus)
		if snapshotStatus.VolumeUUID == volumeStatus.VolumeID.String() {
			if doSnapshotStatusUpdate(ctx, &snapshotStatus) {
				publishSnapshotStatus(ctx, snapshotStatus)
				maybeUpdateSnapshotsStatus(ctx, snapshotStatus.VolumeUUID)
			}
		}
	}
	log.Tracef("handleVolumeStatusImpl(%s) done\n", key)
}

func handleVolumeStatusDelete(ctxArg interface{},
	key string, statusArg interface{}) {

	status := statusArg.(types.VolumeStatus)
	ctx := ctxArg.(*zfsContext)
	uuidStr := status.VolumeID.String()
	maybeUpdateSnapshotsStatus(ctx, uuidStr)
}

// snapshotPropertiesFill - updates snapshot information and checks states
func snapshotPropertiesFill(ctx *zfsContext) {
	for _, el := range ctx.pubSnapshotStatus.GetAll() {
		snapshotStatus := el.(types.ZfsSnapshotStatus)
		if changed, err := syncSnapshotZfsProperties(&snapshotStatus); err != nil {
			log.Errorf("snapshotPropertiesFill: %s", err)
		} else {
			if changed {
				publishSnapshotStatus(ctx, snapshotStatus)
			}
		}
		if doSnapshotStatusUpdate(ctx, &snapshotStatus) {
			publishSnapshotStatus(ctx, snapshotStatus)
		}
	}
}
