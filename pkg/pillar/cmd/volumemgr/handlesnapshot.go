// Copyright (c) 2013-2023 Zededa,
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/volumehandlers"
	"github.com/lf-edge/eve/pkg/pillar/worker"
	uuid "github.com/satori/go.uuid"
	"os"
	"sort"
	"strings"
	"time"
)

const workSnapshot = "snapshot"

// snapshotAction is what volumemgr has to do to a snapshot. It follows from
// the VolumesSnapshotConfig, which says that the snapshot is to exist, and
// from the VolumesSnapshotStatus, see snapshotActionNeeded.
type snapshotAction uint8

const (
	snapshotNothing snapshotAction = iota
	snapshotCreate
	snapshotRollback
	snapshotDelete
	// snapshotDrop forgets a snapshot whose creation has not started
	snapshotDrop
	// snapshotVerify checks the images of a snapshot whose action failed
	// before a reboot, see restoreSnapshotState
	snapshotVerify
)

// imageVerifier is a volume handler whose volume has an image that a failed
// snapshot action can leave damaged.
type imageVerifier interface {
	VerifyImage() error
}

func (action snapshotAction) String() string {
	switch action {
	case snapshotCreate:
		return "create"
	case snapshotRollback:
		return "roll back to"
	case snapshotDelete:
		return "delete"
	case snapshotDrop:
		return "drop"
	case snapshotVerify:
		return "verify the images of"
	default:
		return "do nothing to"
	}
}

// snapshotWork is what the worker needs to create, roll back to or delete a
// snapshot, and where it leaves the outcome.
type snapshotWork struct {
	action  snapshotAction
	appUUID uuid.UUID
	status  types.VolumesSnapshotStatus
	volumes []snapshotVolume
	// sound has the keys of the volumes whose image passed its check in the
	// end. unusable has those whose image could not be repaired or checked,
	// with the error.
	sound    []string
	unusable map[string]string
}

func (d *snapshotWork) noteUnusable(volume *types.VolumeStatus, err error) {
	if !errors.Is(err, diskmetrics.ErrImageNotVerified) {
		return
	}
	if d.unusable == nil {
		d.unusable = make(map[string]string)
	}
	d.unusable[volume.Key()] = fmt.Sprintf("Snapshot %s of volume %s: %s",
		d.status.SnapshotID, volume.DisplayName, err)
}

type snapshotVolume struct {
	status types.VolumeStatus
	// meta is what the volume handler returned when it created the snapshot
	meta interface{}
}

// Variables so that tests can do without real volumes and without /persist.
var (
	getSnapshotVolumeHandler = func(ctx *volumemgrContext, status *types.VolumeStatus) volumehandlers.VolumeHandler {
		return volumehandlers.GetVolumeHandler(log, ctx, status)
	}
	saveVolumesSnapshotStatus   = serializeVolumesSnapshotStatus
	loadVolumesSnapshotStatus   = deserializeVolumesSnapshotStatus
	removeVolumesSnapshotStatus = func(snapshotID string) error {
		err := os.Remove(types.GetVolumesSnapshotStatusFile(snapshotID))
		if os.IsNotExist(err) {
			return nil
		}
		return err
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

// restoreVolumesSnapshotStatuses publishes the snapshots that have a record
// on disk, and then tells zedmanager that it knows them all. What a reboot
// cut off is taken up again, see restoreSnapshotState.
func restoreVolumesSnapshotStatuses(ctx *volumemgrContext) {
	for _, snapshotID := range listSnapshotRecords() {
		status, err := loadVolumesSnapshotStatus(snapshotID)
		if err != nil {
			log.Warnf("restoreVolumesSnapshotStatuses: no record of snapshot %s: %s", snapshotID, err)
			continue
		}
		restoreSnapshotState(status)
		log.Noticef("restoreVolumesSnapshotStatuses: snapshot %s of app %s, %s",
			snapshotID, status.AppUUID, status.State)
		_ = publishVolumesSnapshotStatus(ctx, status)
		if status.Busy() {
			ctx.snapshotsWaiting[snapshotID] = true
		}
	}
	_ = ctx.pubVolumesSnapStatus.SignalRestarted()
}

// restoreSnapshotState turns a record into the status that volumemgr starts
// with. The apps are down then, and zedmanager keeps them down while a
// snapshot is busy.
func restoreSnapshotState(status *types.VolumesSnapshotStatus) {
	// The errors of the volumes are gone with the reboot. An action that
	// failed can have left an image that cannot be used, so the images are
	// checked again before the app may start. A deletion checks them when it
	// is tried again.
	status.ErrorEntities = nil
	status.Verifying = false
	switch status.State {
	case types.VolumesSnapshotStateCreating:
		if !status.HasError() {
			// What the volumes got of it is not known.
			snapshotError(status, "The creation of snapshot %s was interrupted by a reboot",
				status.SnapshotID)
		}
		status.Verifying = true
	case types.VolumesSnapshotStateCreated:
	case types.VolumesSnapshotStateRollingBack:
		// Without an error it was cut off, and goes on once zedmanager
		// has published the config again.
		status.Verifying = status.HasError()
	case types.VolumesSnapshotStateDeleting:
		// Cut off, or failed and due for another attempt.
		status.ClearErrorWithSource()
	default:
		// The record of a version that did not keep the state, which is
		// of a snapshot that was created.
		status.ClearErrorWithSource()
		status.State = types.VolumesSnapshotStateCreated
	}
}

func snapshotError(status *types.VolumesSnapshotStatus, format string, args ...interface{}) {
	errDesc := types.ErrorDescription{}
	errDesc.Error = fmt.Sprintf(format, args...)
	log.Error(errDesc.Error)
	status.SetErrorWithSourceAndDescription(errDesc, types.VolumesSnapshotStatus{})
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

	volumesSnapshotStatus := new(types.VolumesSnapshotStatus)
	err := utils.DeserializeToStruct(volumesSnapshotStatusFilename, volumesSnapshotStatus)
	if err != nil {
		log.Errorf("deserializeVolumesSnapshotStatus: failed to deserialize snapshot status for %s, %s", snapshotID, err.Error())
		return nil, fmt.Errorf("failed to deserialize snapshot status for %s, %s", snapshotID, err.Error())
	}

	return volumesSnapshotStatus, nil

}

// snapshotActionNeeded tells what is to be done to a snapshot that no worker
// is busy with:
//   - a config without a status is a snapshot to create,
//   - a status without a config is a snapshot to delete,
//   - a config with a higher RollbackCount than the status asks for a
//     rollback.
//
// An action that failed leaves the snapshot in its state with the error, and
// is not repeated by itself. A deletion is tried again later, see
// retrySnapshotDeletions.
func snapshotActionNeeded(ctx *volumemgrContext, config *types.VolumesSnapshotConfig,
	status *types.VolumesSnapshotStatus) snapshotAction {
	if status == nil {
		if config != nil {
			return snapshotCreate
		}
		return snapshotNothing
	}
	// Before zedmanager has published its configs after a boot, a missing
	// one says nothing.
	unwanted := config == nil && ctx.snapshotConfigsComplete
	failed := status.HasError()
	if status.Verifying && !unwanted {
		// A deletion ends with a check of the images as well.
		return snapshotVerify
	}
	switch status.State {
	case types.VolumesSnapshotStateCreating:
		switch {
		case unwanted && failed:
			// For what the failed creation left on the volumes.
			return snapshotDelete
		case unwanted:
			return snapshotDrop
		case config != nil && !failed:
			// Waits for a worker.
			return snapshotCreate
		}
	case types.VolumesSnapshotStateCreated:
		switch {
		case unwanted:
			return snapshotDelete
		case config != nil && config.RollbackCount > status.RollbackCount:
			return snapshotRollback
		}
	case types.VolumesSnapshotStateRollingBack:
		switch {
		case unwanted:
			return snapshotDelete
		case config == nil:
		case !failed:
			// Waits for a worker, or was cut off by a reboot.
			return snapshotRollback
		case config.RollbackCount > status.RollbackCount:
			return snapshotRollback
		}
	case types.VolumesSnapshotStateDeleting:
		if !failed {
			return snapshotDelete
		}
	}
	return snapshotNothing
}

// reconcileSnapshot starts what is to be done to the snapshot.
func reconcileSnapshot(ctx *volumemgrContext, snapshotID string) {
	if snapshotInFlight(ctx, snapshotID) {
		// processSnapshotResult comes back here.
		log.Noticef("reconcileSnapshot(%s) waits for the action in the worker", snapshotID)
		return
	}
	// Whether it still has to wait is found out anew.
	delete(ctx.snapshotsWaiting, snapshotID)
	config := lookupVolumesSnapshotConfig(ctx, snapshotID)
	status := lookupVolumesSnapshotStatus(ctx, snapshotID)
	action := snapshotActionNeeded(ctx, config, status)
	// An action that was decided on before only waited for its turn.
	taken := status != nil && status.Busy()
	switch action {
	case snapshotNothing:
		return
	case snapshotDrop:
		if snapshotRetryPending(ctx, status.AppUUID) {
			// zedmanager starts the app when this status is gone.
			ctx.snapshotsWaiting[snapshotID] = true
			return
		}
		log.Noticef("reconcileSnapshot(%s): not wanted any more before its creation started", snapshotID)
		_ = unpublishVolumesSnapshotStatus(ctx, status)
		return
	case snapshotCreate:
		if status == nil {
			status = &types.VolumesSnapshotStatus{
				SnapshotID:         config.SnapshotID,
				VolumeSnapshotMeta: make(map[string]interface{}, len(config.VolumeIDs)),
				AppUUID:            config.AppUUID,
				RollbackCountKnown: true,
			}
		}
		status.State = types.VolumesSnapshotStateCreating
	case snapshotRollback:
		status.State = types.VolumesSnapshotStateRollingBack
		if config.RollbackCount > status.RollbackCount {
			status.RollbackCount = config.RollbackCount
		}
		status.RollbackCountKnown = true
	case snapshotDelete:
		status.State = types.VolumesSnapshotStateDeleting
	case snapshotVerify:
		// The state and the error stay: they are the outcome of the action
		// that failed before the reboot.
		startSnapshotAction(ctx, status, action, config)
		return
	}
	// What is left of an earlier action is not the outcome of this one.
	status.Verifying = false
	status.ClearErrorWithSource()
	_ = publishVolumesSnapshotStatus(ctx, status)
	if !taken {
		retrySnapshotDeletions(ctx, status.AppUUID, snapshotID)
	}
	startSnapshotAction(ctx, status, action, config)
	if !taken {
		// If this action ended at once, what waits for it can go on.
		driveSnapshots(ctx)
	}
}

// retrySnapshotDeletions takes up the deletions that failed for the app. A
// deletion needs the app to be down, which volumemgr cannot tell. It is down
// when zedmanager asks for another action on one of its snapshots, and at
// boot, where restoreSnapshotState does the same.
// They run before the action that sets them off, see snapshotRetryPending:
// zedmanager starts the app once that action is over, and may not have seen
// by then that these are busy.
func retrySnapshotDeletions(ctx *volumemgrContext, appUUID uuid.UUID, exceptSnapshotID string) {
	for snapshotID, st := range ctx.pubVolumesSnapStatus.GetAll() {
		status := st.(types.VolumesSnapshotStatus)
		if snapshotID == exceptSnapshotID || status.AppUUID != appUUID ||
			status.State != types.VolumesSnapshotStateDeleting || !status.HasError() {
			continue
		}
		log.Noticef("retrySnapshotDeletions: snapshot %s: %s", snapshotID, status.Error)
		status.ClearErrorWithSource()
		_ = publishVolumesSnapshotStatus(ctx, &status)
		ctx.snapshotsWaiting[snapshotID] = true
		ctx.snapshotDeletionRetries[snapshotID] = true
	}
}

// snapshotRetryPending tells if a deletion that retrySnapshotDeletions took
// up for the app is not over yet.
func snapshotRetryPending(ctx *volumemgrContext, appUUID uuid.UUID) bool {
	pending := false
	for snapshotID := range ctx.snapshotDeletionRetries {
		status := lookupVolumesSnapshotStatus(ctx, snapshotID)
		if status == nil || !status.Busy() {
			delete(ctx.snapshotDeletionRetries, snapshotID)
			continue
		}
		if status.AppUUID == appUUID {
			pending = true
		}
	}
	return pending
}

// snapshotVolumes returns the volumes that the action works on. wait is set
// if they are not all there yet, which is the case after a boot.
func snapshotVolumes(ctx *volumemgrContext, status *types.VolumesSnapshotStatus,
	action snapshotAction, config *types.VolumesSnapshotConfig) (volumes []snapshotVolume, wait bool, err error) {
	metas := make(map[string]interface{})
	if action == snapshotCreate {
		for _, volumeID := range config.VolumeIDs {
			metas[volumeID.String()] = nil
		}
	} else {
		for volumeID, snapMeta := range status.VolumeSnapshotMeta {
			metas[volumeID] = snapMeta
		}
	}
	for volumeID, snapMeta := range metas {
		volumeStatus := lookupSnapshotVolume(ctx, volumeID)
		// A volume that is not created has no image, unless an error is
		// what kept volumemgr from taking it up. It is not waited for:
		// zedmanager does not ask for it while a snapshot is busy.
		notCreated := volumeStatus != nil && volumeStatus.State < types.CREATED_VOLUME
		gone := volumeStatus == nil || (notCreated && !volumeStatus.HasError())
		// A volume that is being destroyed, or will be once a worker is
		// done with it, takes its snapshots along.
		leaving := volumeStatus != nil && (volumeStatus.SubState == types.VolumeSubStateDeleting ||
			ctx.volumesAwaitingSnapshot[volumeStatus.Key()])
		switch {
		case volumeStatus == nil && !ctx.signalledRestartedStatus:
			// zedagent has not published the volumes yet.
			return nil, true, nil
		case (gone || leaving) && action == snapshotDelete:
			// The snapshot goes with the image.
			log.Noticef("snapshotVolumes: snapshot %s: volume %s is gone", status.SnapshotID, volumeID)
			delete(status.VolumeSnapshotMeta, volumeID)
			continue
		case (gone || leaving || notCreated) && action == snapshotVerify:
			// No image to check.
			continue
		case gone:
			return nil, false, fmt.Errorf("volume %s not found", volumeID)
		case notCreated:
			return nil, false, fmt.Errorf("volume %s is not created: %s", volumeID, volumeStatus.Error)
		}
		volumes = append(volumes, snapshotVolume{status: *volumeStatus, meta: snapMeta})
	}
	return volumes, false, nil
}

// startSnapshotAction hands the work to the worker pool. The work stays with
// the published state if it cannot start yet: only one snapshot action runs
// per app at a time, as they use the same disk images, the pool can be full,
// and after a boot the volumes take a moment. driveSnapshots takes it up
// again.
func startSnapshotAction(ctx *volumemgrContext, status *types.VolumesSnapshotStatus,
	action snapshotAction, config *types.VolumesSnapshotConfig) {
	if !ctx.snapshotDeletionRetries[status.SnapshotID] && snapshotRetryPending(ctx, status.AppUUID) {
		log.Noticef("startSnapshotAction(%s) %s waits for the deletions that are tried again",
			status.SnapshotID, action)
		ctx.snapshotsWaiting[status.SnapshotID] = true
		return
	}
	if snapshotID, busy := ctx.snapshotOpInFlight[status.AppUUID]; busy {
		log.Noticef("startSnapshotAction(%s) %s waits for snapshot %s of the app",
			status.SnapshotID, action, snapshotID)
		ctx.snapshotsWaiting[status.SnapshotID] = true
		return
	}
	volumes, wait, err := snapshotVolumes(ctx, status, action, config)
	if wait {
		log.Noticef("startSnapshotAction(%s) %s waits for the volumes", status.SnapshotID, action)
		ctx.snapshotsWaiting[status.SnapshotID] = true
		return
	}
	if err != nil {
		snapshotError(status, "Failed to %s snapshot %s: %s", action, status.SnapshotID, err)
		_ = publishVolumesSnapshotStatus(ctx, status)
		return
	}
	work := snapshotWork{action: action, appUUID: status.AppUUID, status: *status, volumes: volumes}
	// The worker counts a job as pending a moment longer than it takes to
	// deliver its result, so every job needs a key of its own.
	ctx.snapshotWorkCount++
	key := fmt.Sprintf("snapshot:%s#%d", status.SnapshotID, ctx.snapshotWorkCount)
	w := worker.Work{Kind: workSnapshot, Key: key, Description: work}
	if _, err := trySubmitWork(ctx, w); err != nil {
		var poolFull *worker.PoolFullError
		if errors.As(err, &poolFull) {
			log.Noticef("startSnapshotAction(%s) %s waits for a free worker",
				status.SnapshotID, action)
			ctx.snapshotsWaiting[status.SnapshotID] = true
			return
		}
		snapshotError(status, "Failed to %s snapshot %s: %s", action, status.SnapshotID, err)
		_ = publishVolumesSnapshotStatus(ctx, status)
		return
	}
	ctx.snapshotOpInFlight[status.AppUUID] = status.SnapshotID
	if ctx.snapshotVolumesInFlight == nil {
		ctx.snapshotVolumesInFlight = make(map[string]string)
	}
	for _, volume := range volumes {
		ctx.snapshotVolumesInFlight[volume.status.Key()] = status.SnapshotID
	}
}

// lookupSnapshotVolume returns the VolumeStatus that the volume of a
// snapshot stands for. The snapshot knows the volume by its UUID only, and a
// purge has two generations of it for a while: the one with an image is
// meant. Returns nil if volumemgr knows no generation of the volume.
func lookupSnapshotVolume(ctx *volumemgrContext, volumeID string) *types.VolumeStatus {
	var withImage, withError, other *types.VolumeStatus
	for _, st := range ctx.pubVolumeStatus.GetAll() {
		status := st.(types.VolumeStatus)
		if status.VolumeID.String() != volumeID {
			continue
		}
		switch {
		case status.State >= types.CREATED_VOLUME && status.SubState != types.VolumeSubStateDeleting:
			if withImage == nil || status.Key() > withImage.Key() {
				withImage = &status
			}
		case status.HasError():
			if withError == nil || status.Key() > withError.Key() {
				withError = &status
			}
		default:
			if other == nil || status.Key() > other.Key() {
				other = &status
			}
		}
	}
	switch {
	case withImage != nil:
		return withImage
	case withError != nil:
		return withError
	default:
		return other
	}
}

// deferDestroyForSnapshot tells if the volume cannot be destroyed yet, as a
// worker has its image in use for a snapshot. processSnapshotResult takes the
// destruction up again.
func deferDestroyForSnapshot(ctx *volumemgrContext, status *types.VolumeStatus) bool {
	snapshotID, busy := ctx.snapshotVolumesInFlight[status.Key()]
	if !busy {
		return false
	}
	log.Noticef("deferDestroyForSnapshot: volume %s waits for the work on snapshot %s",
		status.Key(), snapshotID)
	if ctx.volumesAwaitingSnapshot == nil {
		ctx.volumesAwaitingSnapshot = make(map[string]bool)
	}
	ctx.volumesAwaitingSnapshot[status.Key()] = true
	return true
}

// destroyVolumesAfterSnapshot destroys the volumes that waited for the work
// on the snapshot, unless something refers to them again.
func destroyVolumesAfterSnapshot(ctx *volumemgrContext, snapshotID string) {
	var keys []string
	for key, inFlight := range ctx.snapshotVolumesInFlight {
		if inFlight != snapshotID {
			continue
		}
		delete(ctx.snapshotVolumesInFlight, key)
		if ctx.volumesAwaitingSnapshot[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		delete(ctx.volumesAwaitingSnapshot, key)
		if vs := ctx.LookupVolumeStatus(key); vs != nil {
			maybeDeleteVolume(ctx, vs)
		}
	}
}

// snapshotWorker implementation of worker.WorkFunction that creates, rolls
// back to or deletes a snapshot of volumes. It runs outside the main loop:
// it must not touch ctx beyond handing it to the volume handlers.
func snapshotWorker(ctxPtr interface{}, w worker.Work) worker.WorkResult {
	ctx := ctxPtr.(*volumemgrContext)
	d := w.Description.(snapshotWork)
	snapshotID := d.status.SnapshotID
	var failures []string
	for i, volume := range d.volumes {
		volumeID := volume.status.VolumeID.String()
		volumeHandler := getSnapshotVolumeHandler(ctx, &volume.status)
		log.Noticef("snapshotWorker: %s snapshot %s for volume %s", d.action, snapshotID, volumeID)
		var err error
		switch d.action {
		case snapshotCreate:
			var snapshotMeta interface{}
			var timeCreated time.Time
			snapshotMeta, timeCreated, err = volumeHandler.CreateSnapshot()
			if err == nil {
				d.status.TimeCreated = timeCreated
			}
			// A handler that failed returns the meta of what it may have
			// left on the volume.
			if err == nil || (snapshotMeta != nil && snapshotMeta != "") {
				d.status.VolumeSnapshotMeta[volumeID] = snapshotMeta
			}
		case snapshotRollback:
			err = volumeHandler.RollbackToSnapshot(volume.meta)
		case snapshotDelete:
			err = volumeHandler.DeleteSnapshot(volume.meta)
		case snapshotVerify:
			if verifier, ok := volumeHandler.(imageVerifier); ok {
				err = verifier.VerifyImage()
			}
		}
		// A command that failed on an image which then passed its check
		// says as much about the image as one that worked.
		var sound *diskmetrics.SoundImageError
		if err == nil || errors.As(err, &sound) {
			d.sound = append(d.sound, volume.status.Key())
		}
		if err == nil {
			log.Noticef("snapshotWorker: %s snapshot %s for volume %s done", d.action, snapshotID, volumeID)
			if d.action == snapshotDelete {
				// Not every handler takes a second deletion.
				delete(d.status.VolumeSnapshotMeta, volumeID)
			}
			continue
		}
		d.noteUnusable(&volume.status, err)
		failure := fmt.Sprintf("volume %s, %s", volumeID, err)
		if d.action == snapshotRollback && i > 0 {
			failure += fmt.Sprintf(" (%d of %d volumes are rolled back)", i, len(d.volumes))
		}
		failures = append(failures, failure)
		if d.action != snapshotDelete {
			break
		}
		// Go on: every volume that loses the snapshot frees space.
	}
	if len(failures) > 0 && d.action != snapshotVerify {
		snapshotError(&d.status, "Failed to %s snapshot %s for %s",
			d.action, snapshotID, strings.Join(failures, "; "))
		if d.action == snapshotCreate {
			removePartialSnapshot(ctx, &d)
		}
	}
	return worker.WorkResult{Key: w.Key, Description: d}
}

// removePartialSnapshot deletes what a failed creation left on the volumes:
// nothing is going to refer to it.
func removePartialSnapshot(ctx *volumemgrContext, d *snapshotWork) {
	for _, volume := range d.volumes {
		volumeID := volume.status.VolumeID.String()
		meta, ok := d.status.VolumeSnapshotMeta[volumeID]
		if !ok {
			continue
		}
		if _, unusable := d.unusable[volume.status.Key()]; unusable {
			// Not the image to work on some more. The deletion of the
			// snapshot gets to it.
			continue
		}
		if err := getSnapshotVolumeHandler(ctx, &volume.status).DeleteSnapshot(meta); err != nil {
			log.Errorf("removePartialSnapshot: snapshot %s stays on volume %s: %s",
				d.status.SnapshotID, volumeID, err)
			d.noteUnusable(&volume.status, err)
			// Stays known, so that the deletion of the snapshot tries again.
			continue
		}
		delete(d.status.VolumeSnapshotMeta, volumeID)
	}
}

// processSnapshotResult publishes the outcome of a snapshot action and takes
// up the snapshots that had to wait.
func processSnapshotResult(ctxPtr interface{}, res worker.WorkResult) error {
	ctx := ctxPtr.(*volumemgrContext)
	ctx.worker.Pop(res.Key)
	d := res.Description.(snapshotWork)
	snapshotID := d.status.SnapshotID
	delete(ctx.snapshotOpInFlight, d.appUUID)
	destroyVolumesAfterSnapshot(ctx, snapshotID)
	applyVolumeErrors(ctx, &d)
	finishSnapshotAction(ctx, &d.status, d.action)
	// The config can have changed while the worker was busy.
	reconcileSnapshot(ctx, snapshotID)
	driveSnapshots(ctx)
	// See processVolumeWorkResult: this frees a slot in the shared pool.
	reevaluatePendingVolumes(ctx)
	reevaluatePendingContentTrees(ctx, types.VERIFIED)
	return nil
}

// finishSnapshotAction tells zedmanager how the action ended. An action that
// failed leaves the snapshot in its state, with the error. A deletion that
// worked takes the status away.
func finishSnapshotAction(ctx *volumemgrContext, status *types.VolumesSnapshotStatus, action snapshotAction) {
	log.Noticef("finishSnapshotAction(%s): %s done, error: %q", status.SnapshotID, action, status.Error)
	if action == snapshotVerify {
		// The error is the one of the action that failed before the reboot.
		status.Verifying = false
		_ = publishVolumesSnapshotStatus(ctx, status)
		return
	}
	if status.HasError() {
		_ = publishVolumesSnapshotStatus(ctx, status)
		return
	}
	if action == snapshotDelete {
		_ = unpublishVolumesSnapshotStatus(ctx, status)
		return
	}
	previous := status.State
	status.State = types.VolumesSnapshotStateCreated
	if err := publishVolumesSnapshotStatus(ctx, status); err != nil && action == snapshotCreate {
		// It would be gone after a reboot, with its data left on the volumes.
		status.State = previous
		snapshotError(status, "Failed to save the record of snapshot %s, %s", status.SnapshotID, err)
		_ = publishVolumesSnapshotStatus(ctx, status)
	}
}

// applyVolumeErrors puts an error on the volumes whose image could not be
// repaired or checked, which keeps their app from starting, and takes it off
// those that passed the check. The error of the snapshot names the volumes of
// the snapshot that have such an error: the volumes are published apart from
// the snapshot, and zedmanager has to wait for them.
func applyVolumeErrors(ctx *volumemgrContext, d *snapshotWork) {
	for _, key := range d.sound {
		vs := ctx.LookupVolumeStatus(key)
		if vs == nil || !vs.IsErrorSource(types.VolumesSnapshotStatus{}) {
			continue
		}
		log.Noticef("applyVolumeErrors: volume %s can be used again", key)
		vs.ClearErrorWithSource()
		publishVolumeStatus(ctx, vs)
		updateVolumeRefStatus(ctx, vs)
		forgetVolumeError(ctx, d.status.SnapshotID, key)
	}
	for key, errStr := range d.unusable {
		vs := ctx.LookupVolumeStatus(key)
		if vs == nil {
			continue
		}
		log.Errorf("applyVolumeErrors: %s", errStr)
		vs.SetErrorWithSource(errStr, types.VolumesSnapshotStatus{}, time.Now())
		publishVolumeStatus(ctx, vs)
		updateVolumeRefStatus(ctx, vs)
	}
	if !d.status.HasError() {
		return
	}
	// That includes the volumes that this action did not get to.
	var keys []string
	for _, volume := range d.volumes {
		vs := ctx.LookupVolumeStatus(volume.status.Key())
		if vs != nil && vs.IsErrorSource(types.VolumesSnapshotStatus{}) {
			keys = append(keys, vs.Key())
		}
	}
	sort.Strings(keys)
	d.status.ErrorEntities = nil
	for _, key := range keys {
		d.status.ErrorEntities = append(d.status.ErrorEntities,
			&types.ErrorEntity{EntityType: types.ErrorEntityVolume, EntityID: key})
	}
}

// forgetVolumeError removes the volume from the errors of the other
// snapshots: zedmanager would wait for an error that is gone.
func forgetVolumeError(ctx *volumemgrContext, exceptSnapshotID string, volumeKey string) {
	for _, st := range ctx.pubVolumesSnapStatus.GetAll() {
		status := st.(types.VolumesSnapshotStatus)
		if status.SnapshotID == exceptSnapshotID {
			continue
		}
		var kept []*types.ErrorEntity
		for _, entity := range status.ErrorEntities {
			if entity.EntityType != types.ErrorEntityVolume || entity.EntityID != volumeKey {
				kept = append(kept, entity)
			}
		}
		if len(kept) != len(status.ErrorEntities) {
			status.ErrorEntities = kept
			_ = publishVolumesSnapshotStatus(ctx, &status)
		}
	}
}

// driveSnapshots takes up the snapshots that wait for another one of their
// app, for a free worker or for their volumes.
func driveSnapshots(ctx *volumemgrContext) {
	var waiting []string
	for snapshotID := range ctx.snapshotsWaiting {
		waiting = append(waiting, snapshotID)
	}
	sort.Strings(waiting)
	for _, snapshotID := range waiting {
		reconcileSnapshot(ctx, snapshotID)
	}
}

func snapshotInFlight(ctx *volumemgrContext, snapshotID string) bool {
	for _, inFlight := range ctx.snapshotOpInFlight {
		if inFlight == snapshotID {
			return true
		}
	}
	return false
}

func handleVolumesSnapshotConfigCreate(ctxArg interface{}, key string, _ interface{}) {
	ctx := ctxArg.(*volumemgrContext)
	log.Noticef("handleVolumesSnapshotConfigCreate(%s)", key)
	reconcileSnapshot(ctx, key)
}

func handleVolumesSnapshotConfigModify(ctxArg interface{}, key string, _, _ interface{}) {
	ctx := ctxArg.(*volumemgrContext)
	log.Noticef("handleVolumesSnapshotConfigModify(%s)", key)
	reconcileSnapshot(ctx, key)
}

func handleVolumesSnapshotConfigDelete(ctxArg interface{}, key string, _ interface{}) {
	ctx := ctxArg.(*volumemgrContext)
	log.Noticef("handleVolumesSnapshotConfigDelete(%s)", key)
	reconcileSnapshot(ctx, key)
}

// handleVolumesSnapshotConfigRestarted is how zedmanager says that it has
// published a config for every snapshot it wants to keep. A snapshot without
// one is to be deleted from here on.
func handleVolumesSnapshotConfigRestarted(ctxArg interface{}, restartCounter int) {
	ctx := ctxArg.(*volumemgrContext)
	log.Noticef("handleVolumesSnapshotConfigRestarted(%d)", restartCounter)
	if restartCounter == 0 || ctx.snapshotConfigsComplete {
		return
	}
	ctx.snapshotConfigsComplete = true
	var snapshotIDs []string
	for snapshotID := range ctx.pubVolumesSnapStatus.GetAll() {
		snapshotIDs = append(snapshotIDs, snapshotID)
	}
	sort.Strings(snapshotIDs)
	for _, snapshotID := range snapshotIDs {
		reconcileSnapshot(ctx, snapshotID)
	}
}

func lookupVolumesSnapshotConfig(ctx *volumemgrContext, key string) *types.VolumesSnapshotConfig {
	c, _ := ctx.subVolumesSnapConfig.Get(key)
	if c == nil {
		return nil
	}
	config := c.(types.VolumesSnapshotConfig)
	return &config
}

// publishVolumesSnapshotStatus publishes the status and saves it as the
// record of the snapshot, which is what is known of it after a reboot.
func publishVolumesSnapshotStatus(ctx *volumemgrContext, status *types.VolumesSnapshotStatus) error {
	key := status.Key()
	log.Functionf("publishVolumesSnapshotStatus(%s)", key)
	pub := ctx.pubVolumesSnapStatus
	_ = pub.Publish(key, *status)
	err := saveVolumesSnapshotStatus(key, status)
	if err != nil {
		log.Errorf("publishVolumesSnapshotStatus(%s): no record: %s", key, err)
	}
	return err
}

// unpublishVolumesSnapshotStatus takes away the status of a snapshot that is
// gone, and its record. If the record stays, so does the status: the snapshot
// would be back after a reboot.
func unpublishVolumesSnapshotStatus(ctx *volumemgrContext, status *types.VolumesSnapshotStatus) error {
	key := status.Key()
	log.Functionf("unpublishVolumesSnapshotStatus(%s)", key)
	if err := removeVolumesSnapshotStatus(key); err != nil {
		status.State = types.VolumesSnapshotStateDeleting
		snapshotError(status, "Failed to remove the record of snapshot %s, %s", key, err)
		_ = publishVolumesSnapshotStatus(ctx, status)
		return err
	}
	pub := ctx.pubVolumesSnapStatus
	pub.Unpublish(key)
	return nil
}

func lookupVolumesSnapshotStatus(ctx *volumemgrContext, key string) *types.VolumesSnapshotStatus {
	st, _ := ctx.pubVolumesSnapStatus.Get(key)
	if st == nil {
		return nil
	}
	status := st.(types.VolumesSnapshotStatus)
	return &status
}
