// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	uuid "github.com/satori/go.uuid"
)

// What zedmanager knows about the snapshots of an app is not kept in lists of
// its own. It follows from three things:
//   - the app config, which lists the snapshots the controller wants,
//   - the VolumesSnapshotStatus of volumemgr, which says what exists and what
//     volumemgr does with it,
//   - the VolumesSnapshotConfig, with which zedmanager tells volumemgr that a
//     snapshot is to exist.
//
// A snapshot that is listed and has no status is still to be created, and is
// by publishing its config. One that has a status and is not listed is to be
// deleted, and is by taking its config away. Both wait for the app to be
// down.

// Variables so that tests can do without /persist.
var (
	loadSnapshotRecord  = deserializeSnapshotInstanceStatus
	saveSnapshotRecord  = serializeSnapshotInstanceStatus
	loadVolumesSnapshot = func(snapshotID string) (*types.VolumesSnapshotStatus, error) {
		var st types.VolumesSnapshotStatus
		err := utils.DeserializeToStruct(types.GetVolumesSnapshotStatusFile(snapshotID), &st)
		return &st, err
	}
	listSnapshotRecords = func() []string {
		var snapshotIDs []string
		entries, err := os.ReadDir(types.SnapshotsDirname)
		if err != nil {
			log.Functionf("listSnapshotRecords: %s", err)
			return nil
		}
		for _, entry := range entries {
			if entry.IsDir() {
				snapshotIDs = append(snapshotIDs, entry.Name())
			}
		}
		return snapshotIDs
	}
)

// snapshotsFromRecords returns the snapshots of the app as the records on
// disk have them: that of zedmanager for a snapshot that was created, and
// that of volumemgr, which also tells of an action that failed.
func snapshotsFromRecords(appUUID uuid.UUID) []types.SnapshotInstanceStatus {
	var snapshots []types.SnapshotInstanceStatus
	for _, snapshotID := range listSnapshotRecords() {
		st, stErr := loadVolumesSnapshot(snapshotID)
		record, err := loadSnapshotRecord(snapshotID)
		switch {
		case err == nil && record.AppInstanceID == appUUID:
		case err != nil && stErr == nil && st.AppUUID == appUUID && st.HasError():
			record = &types.SnapshotInstanceStatus{
				Snapshot:      types.SnapshotDesc{SnapshotID: snapshotID},
				AppInstanceID: appUUID,
			}
		default:
			continue
		}
		if stErr == nil && st.HasError() {
			record.Error = st.ErrorDescription
		}
		snapshots = append(snapshots, *record)
	}
	return snapshots
}

// snapshotStatuses returns what volumemgr reports for the snapshots of the
// app, by snapshot ID.
func snapshotStatuses(ctx *zedmanagerContext, appUUID uuid.UUID) map[string]types.VolumesSnapshotStatus {
	statuses := make(map[string]types.VolumesSnapshotStatus)
	for id, st := range ctx.subVolumesSnapStatus.GetAll() {
		status := st.(types.VolumesSnapshotStatus)
		if status.AppUUID == appUUID {
			statuses[id] = status
		}
	}
	return statuses
}

// snapshotConfig returns the config that zedmanager has published for the
// snapshot, if any.
func snapshotConfig(ctx *zedmanagerContext, snapshotID string) *types.VolumesSnapshotConfig {
	c, _ := ctx.pubVolumesSnapConfig.Get(snapshotID)
	if c == nil {
		return nil
	}
	config := c.(types.VolumesSnapshotConfig)
	return &config
}

// snapshotConfigsOfApp returns the configs that zedmanager has published for
// the snapshots of the app.
func snapshotConfigsOfApp(ctx *zedmanagerContext, appUUID uuid.UUID) []types.VolumesSnapshotConfig {
	var configs []types.VolumesSnapshotConfig
	for _, c := range ctx.pubVolumesSnapConfig.GetAll() {
		if config := c.(types.VolumesSnapshotConfig); config.AppUUID == appUUID {
			configs = append(configs, config)
		}
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].SnapshotID < configs[j].SnapshotID })
	return configs
}

// tooManySnapshots tells if the config lists more snapshots than its limit
// allows. Such a config is invalid: nothing is created or deleted for it.
func tooManySnapshots(config types.AppInstanceConfig) bool {
	return len(config.Snapshot.Snapshots) > int(config.Snapshot.MaxSnapshots)
}

// pendingSnapshots returns the snapshots that the config lists and that
// volumemgr knows nothing of. Until volumemgr has told which snapshots exist,
// none is taken for missing.
func pendingSnapshots(ctx *zedmanagerContext, config types.AppInstanceConfig) []types.SnapshotDesc {
	if !ctx.snapshotsRestored || tooManySnapshots(config) {
		return nil
	}
	statuses := snapshotStatuses(ctx, config.UUIDandVersion.UUID)
	var pending []types.SnapshotDesc
	for _, snap := range config.Snapshot.Snapshots {
		if _, ok := statuses[snap.SnapshotID]; !ok {
			pending = append(pending, snap)
		}
	}
	return pending
}

// snapshotsToTake returns the pending snapshots that volumemgr was not asked
// for yet.
func snapshotsToTake(ctx *zedmanagerContext, config types.AppInstanceConfig) []types.SnapshotDesc {
	var toTake []types.SnapshotDesc
	for _, snap := range pendingSnapshots(ctx, config) {
		if snapshotConfig(ctx, snap.SnapshotID) == nil {
			toTake = append(toTake, snap)
		}
	}
	return toTake
}

func snapshotRequestedType(ctx *zedmanagerContext, config types.AppInstanceConfig) types.SnapshotWhen {
	ret := types.NoSnapshotTake
	for _, snap := range snapshotsToTake(ctx, config) {
		switch snap.SnapshotType {
		case types.SnapshotTypeAppUpdate:
			ret = types.SnapshotOnUpgrade
		case types.SnapshotTypeImmediate:
			// Immediate snapshots have precedence over snapshots on upgrade
			return types.SnapshotImmediate
		}
	}
	return ret
}

// snapshotsToDelete returns the snapshots that volumemgr has and that have
// to go: those the config does not list.
// A config that was saved before a snapshot was created does not list it. So
// a snapshot is only deleted once the controller sent a config.
func snapshotsToDelete(ctx *zedmanagerContext, config types.AppInstanceConfig) []string {
	if !ctx.snapshotsRestored || !ctx.configFromController || tooManySnapshots(config) {
		return nil
	}
	var toDelete []string
	for id, st := range snapshotStatuses(ctx, config.UUIDandVersion.UUID) {
		if st.State != types.VolumesSnapshotStateDeleting && !isSnapshotPresentInConfig(config, id) {
			toDelete = append(toDelete, id)
		}
	}
	sort.Strings(toDelete)
	return toDelete
}

// isSnapshotPresentInConfig checks if the snapshot is already present in the list of snapshots
func isSnapshotPresentInConfig(config types.AppInstanceConfig, id string) bool {
	for _, snapDesc := range config.Snapshot.Snapshots {
		if snapDesc.SnapshotID == id {
			return true
		}
	}
	return false
}

// updateSnapshotsInAIStatus takes in a config that may list other snapshots.
func updateSnapshotsInAIStatus(ctx *zedmanagerContext, status *types.AppInstanceStatus,
	config types.AppInstanceConfig) {
	snapState := &status.SnapStatus
	snapState.MaxSnapshots = config.Snapshot.MaxSnapshots
	// A snapshot that is not listed any more is not taken.
	var prepared []types.VolumesSnapshotConfig
	for _, request := range snapState.PreparedVolumesSnapshotConfigs {
		if isSnapshotPresentInConfig(config, request.SnapshotID) {
			prepared = append(prepared, request)
		}
	}
	snapState.PreparedVolumesSnapshotConfigs = prepared
	snapState.SnapshotTakenType = snapshotRequestedType(ctx, config)
	if tooManySnapshots(config) {
		errDesc := types.ErrorDescription{}
		errDesc.Error = fmt.Sprintf("Too many snapshots requested, none is created or deleted. Max allowed: %d",
			snapState.MaxSnapshots)
		log.Warnf("updateSnapshotsInAIStatus: %s", errDesc.Error)
		errDesc.ErrorTime = time.Now()
		errDesc.ErrorSeverity = types.ErrorSeverityWarning
		status.ErrorDescription = errDesc
	}
	refreshSnapshots(ctx, status)
}

// refreshSnapshots rebuilds the list of the snapshots of the app, which is
// what the controller is told, from what volumemgr reports. A snapshot that
// is still being created is not in it. One whose creation, rollback or
// deletion failed is, with the error.
// The controller takes a snapshot that is not reported for deleted. So until
// volumemgr has told which snapshots exist, the list comes from the records
// on disk.
func refreshSnapshots(ctx *zedmanagerContext, status *types.AppInstanceStatus) {
	if !ctx.snapshotsRestored {
		status.SnapStatus.Snapshots = snapshotsFromRecords(status.UUIDandVersion.UUID)
		return
	}
	statuses := snapshotStatuses(ctx, status.UUIDandVersion.UUID)
	ids := make([]string, 0, len(statuses))
	for id, st := range statuses {
		if st.State != types.VolumesSnapshotStateCreating || st.HasError() {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var snapshots []types.SnapshotInstanceStatus
	for _, id := range ids {
		st := statuses[id]
		snap := snapshotRecord(ctx, status, id)
		snap.TimeCreated = st.TimeCreated
		snap.Error = types.ErrorDescription{}
		if st.HasError() {
			snap.Error = st.ErrorDescription
		}
		snapshots = append(snapshots, snap)
	}
	status.SnapStatus.Snapshots = snapshots
}

// snapshotRecord returns what zedmanager knows of the snapshot by itself: from
// the record it saved when the snapshot was created, or else from its config.
func snapshotRecord(ctx *zedmanagerContext, status *types.AppInstanceStatus, snapshotID string) types.SnapshotInstanceStatus {
	if record, err := loadSnapshotRecord(snapshotID); err == nil {
		return *record
	}
	snap := types.SnapshotInstanceStatus{
		Snapshot:      types.SnapshotDesc{SnapshotID: snapshotID},
		AppInstanceID: status.UUIDandVersion.UUID,
	}
	if config := snapshotConfig(ctx, snapshotID); config != nil {
		snap.Snapshot.SnapshotType = config.SnapshotType
		snap.ConfigVersion = config.ConfigVersion
	}
	return snap
}

// lookupSnapshot returns the snapshot from the list that refreshSnapshots
// built.
func lookupSnapshot(status *types.AppInstanceStatus, id string) *types.SnapshotInstanceStatus {
	for i, snap := range status.SnapStatus.Snapshots {
		if snap.Snapshot.SnapshotID == id {
			return &status.SnapStatus.Snapshots[i]
		}
	}
	return nil
}

// keepSnapshotRecord saves what zedmanager knows of a snapshot that was
// created, which is what tells of its type and config version after a reboot.
// An older version takes every record for a snapshot that exists, so there is
// none before that.
func keepSnapshotRecord(ctx *zedmanagerContext, created types.VolumesSnapshotStatus) error {
	config := snapshotConfig(ctx, created.SnapshotID)
	if config == nil || uuid.Equal(config.ConfigVersion.UUID, uuid.Nil) {
		return nil
	}
	if _, err := loadSnapshotRecord(created.SnapshotID); err == nil {
		return nil
	}
	return saveSnapshotRecord(&types.SnapshotInstanceStatus{
		Snapshot: types.SnapshotDesc{
			SnapshotID:   created.SnapshotID,
			SnapshotType: config.SnapshotType,
		},
		Reported:      true,
		TimeTriggered: created.TimeCreated,
		TimeCreated:   created.TimeCreated,
		AppInstanceID: created.AppUUID,
		ConfigVersion: config.ConfigVersion,
	})
}

// restoreSnapshotConfigs publishes a config for every snapshot that volumemgr
// has restored after a boot, whether its app is known yet or not: volumemgr
// deletes a snapshot that has none. A snapshot that is to go loses its config
// when its app is down, see triggerSnapshotDeletion. One that is being deleted
// has none.
func restoreSnapshotConfigs(ctx *zedmanagerContext) {
	for id, s := range ctx.subVolumesSnapStatus.GetAll() {
		st := s.(types.VolumesSnapshotStatus)
		if st.State == types.VolumesSnapshotStateDeleting || snapshotConfig(ctx, id) != nil {
			continue
		}
		config := types.VolumesSnapshotConfig{
			SnapshotID:    id,
			AppUUID:       st.AppUUID,
			RollbackCount: st.RollbackCount,
		}
		for volumeID := range st.VolumeSnapshotMeta {
			if parsed, err := uuid.FromString(volumeID); err == nil {
				config.VolumeIDs = append(config.VolumeIDs, parsed)
			}
		}
		sort.Slice(config.VolumeIDs, func(i, j int) bool {
			return config.VolumeIDs[i].String() < config.VolumeIDs[j].String()
		})
		if record, err := loadSnapshotRecord(id); err == nil {
			config.SnapshotType = record.Snapshot.SnapshotType
			config.ConfigVersion = record.ConfigVersion
		}
		publishVolumesSnapshotConfig(ctx, &config)
		if appConfig := lookupAppInstanceConfig(ctx, st.AppUUID.String(), false); appConfig != nil {
			askForRollbackLeftOver(ctx, *appConfig)
		}
	}
}

// rollbackLeftOver tells if the config asks for a rollback that volumemgr
// has not taken up, which is the case after a reboot that came in between.
// The status of the snapshot has the counter of the last rollback to it.
func rollbackLeftOver(ctx *zedmanagerContext, config types.AppInstanceConfig) bool {
	snapshotID := config.Snapshot.ActiveSnapshot
	if snapshotID == "" || !isSnapshotPresentInConfig(config, snapshotID) {
		return false
	}
	st, ok := snapshotStatuses(ctx, config.UUIDandVersion.UUID)[snapshotID]
	if !ok || !st.RollbackCountKnown || !rollbackPossible(st) {
		// The record of an older version does not tell. Its counter can
		// be of a rollback that was done long ago.
		return false
	}
	return int(config.Snapshot.RollbackCmd.Counter) > st.RollbackCount
}

// askForRollbackLeftOver hands such a rollback to volumemgr. The app is down:
// it is only called before the app is started for the first time.
func askForRollbackLeftOver(ctx *zedmanagerContext, config types.AppInstanceConfig) {
	if !rollbackLeftOver(ctx, config) {
		return
	}
	request := snapshotConfig(ctx, config.Snapshot.ActiveSnapshot)
	if request == nil {
		return
	}
	log.Noticef("askForRollbackLeftOver(%s): rollback %d to snapshot %s was not done before the reboot",
		config.Key(), config.Snapshot.RollbackCmd.Counter, request.SnapshotID)
	request.RollbackCount = int(config.Snapshot.RollbackCmd.Counter)
	publishVolumesSnapshotConfig(ctx, request)
}

// rollbackPossible tells if the snapshot is one that can be rolled back to:
// one that all volumes have. A rollback to it may have failed before.
func rollbackPossible(st types.VolumesSnapshotStatus) bool {
	return st.State == types.VolumesSnapshotStateCreated ||
		st.State == types.VolumesSnapshotStateRollingBack
}

// rollbackAnswered tells if volumemgr is through with the rollback that
// zedmanager asked for. The error of the status tells how it went.
func rollbackAnswered(ctx *zedmanagerContext, st types.VolumesSnapshotStatus) bool {
	request := snapshotConfig(ctx, st.SnapshotID)
	return request != nil && st.RollbackCount >= request.RollbackCount && !st.Busy()
}

// prepareVolumesSnapshotConfigs generates a 'volumesSnapshotConfig' for each snapshot that is to be taken.
// Creating and immediately triggering the 'volumesSnapshotConfig' is not possible due to the following reasons:
// - A snapshot can only be initiated post the application stoppage.
// - Upon application termination, the volumes list within the configuration might have already been modified, leading to inconsistencies.
// Hence, we need this function to prepare the 'volumesSnapshotConfig' with the volumes list that was used when the snapshot was requested.
// oldConfig is the config that the snapshots keep.
func prepareVolumesSnapshotConfigs(ctx *zedmanagerContext, oldConfig, config types.AppInstanceConfig) []types.VolumesSnapshotConfig {
	var volumesSnapshotConfigList []types.VolumesSnapshotConfig
	for _, snapshot := range snapshotsToTake(ctx, config) {
		if snapshot.SnapshotType != types.SnapshotTypeAppUpdate && snapshot.SnapshotType != types.SnapshotTypeImmediate {
			continue
		}
		log.Noticef("Creating volumesSnapshotConfig for snapshot %s", snapshot.SnapshotID)
		volumesSnapshotConfig := types.VolumesSnapshotConfig{
			SnapshotID:    snapshot.SnapshotID,
			AppUUID:       config.UUIDandVersion.UUID,
			SnapshotType:  snapshot.SnapshotType,
			ConfigVersion: oldConfig.UUIDandVersion,
		}
		for _, volumeRefConfig := range oldConfig.VolumeRefConfigList {
			log.Noticef("Adding volume %s to volumesSnapshotConfig", volumeRefConfig.VolumeID)
			volumesSnapshotConfig.VolumeIDs = append(volumesSnapshotConfig.VolumeIDs, volumeRefConfig.VolumeID)
		}
		volumesSnapshotConfigList = append(volumesSnapshotConfigList, volumesSnapshotConfig)
	}
	return volumesSnapshotConfigList
}

// saveAppInstanceConfigForSnapshot saves the config for the snapshots for which the config has been prepared
func saveAppInstanceConfigForSnapshot(status *types.AppInstanceStatus, config types.AppInstanceConfig) error {
	for _, snapshot := range status.SnapStatus.PreparedVolumesSnapshotConfigs {
		// Serialize the old config and store it in a file
		err := serializeAppInstanceConfigToSnapshot(config, snapshot.SnapshotID)
		if err != nil {
			log.Errorf("Failed to serialize the old config for %s, error: %s", config.DisplayName, err)
			return err
		}
	}
	return nil
}

// triggerSnapshots asks volumemgr for the snapshots that were prepared. The
// app has to be down.
func triggerSnapshots(ctx *zedmanagerContext, status *types.AppInstanceStatus) {
	log.Noticef("triggerSnapshots(%s)", status.Key())
	for _, volumesSnapshotConfig := range status.SnapStatus.PreparedVolumesSnapshotConfigs {
		log.Noticef("Triggering snapshot %s", volumesSnapshotConfig.SnapshotID)
		publishVolumesSnapshotConfig(ctx, &volumesSnapshotConfig)
	}
	status.SnapStatus.PreparedVolumesSnapshotConfigs = nil
	publishAppInstanceStatus(ctx, status)
}

// triggerSnapshotDeletion takes away the config of the snapshots that have
// to go, which is how volumemgr is asked to delete them. The app has to be
// down. A deletion that failed is tried again by volumemgr.
func triggerSnapshotDeletion(ctx *zedmanagerContext, config types.AppInstanceConfig) {
	for _, snapshotID := range snapshotsToDelete(ctx, config) {
		if request := snapshotConfig(ctx, snapshotID); request != nil {
			log.Noticef("Deleting snapshot %s", snapshotID)
			unpublishVolumesSnapshotConfig(ctx, request)
		}
	}
}

// snapshotOpInProgress reports whether the app has to stay down for a
// snapshot: QEMU and qemu-img cannot open the same disk image at once.
// That is the case
//   - until volumemgr has told which snapshots exist after a boot,
//   - while volumemgr has not taken up what the configs ask for: a snapshot
//     to create, to roll back to or to delete,
//   - while volumemgr works on a snapshot, which is a state other than
//     Created without an error,
//   - until zedmanager has the error of every volume that the error of a
//     snapshot names.
func snapshotOpInProgress(ctx *zedmanagerContext, appUUID uuid.UUID) bool {
	if !ctx.snapshotsRestored {
		return true
	}
	statuses := snapshotStatuses(ctx, appUUID)
	for id, c := range ctx.pubVolumesSnapConfig.GetAll() {
		request := c.(types.VolumesSnapshotConfig)
		if request.AppUUID != appUUID {
			continue
		}
		st, known := statuses[id]
		if !known {
			return true
		}
		if request.RollbackCount > st.RollbackCount && rollbackPossible(st) {
			return true
		}
	}
	for id, st := range statuses {
		if st.Busy() {
			return true
		}
		if st.State != types.VolumesSnapshotStateDeleting && snapshotConfig(ctx, id) == nil {
			return true
		}
		// The error of a volume comes in the VolumeRefStatus, which can
		// arrive after this status.
		for _, entity := range st.ErrorEntities {
			if entity.EntityType != types.ErrorEntityVolume {
				continue
			}
			vrs := lookupVolumeRefStatus(ctx, entity.EntityID+"#"+appUUID.String())
			if vrs != nil && !vrs.HasError() {
				return true
			}
		}
	}
	return false
}
