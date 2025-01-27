// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	uuid "github.com/satori/go.uuid"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Update this AppInstanceStatus generate config updates to
// the microservices
func updateAIStatusUUID(ctx *zedmanagerContext, uuidStr string) {

	log.Functionf("updateAIStatusUUID(%s)", uuidStr)
	status := lookupAppInstanceStatus(ctx, uuidStr)
	if status == nil {
		log.Functionf("updateAIStatusUUID for %s: Missing AppInstanceStatus",
			uuidStr)
		return
	}
	config := lookupAppInstanceConfig(ctx, uuidStr, true)
	if config == nil || (status.PurgeInprogress == types.BringDown) {
		removeAIStatus(ctx, status)
		return
	}
	changed := doUpdate(ctx, *config, status)
	if changed {
		log.Functionf("updateAIStatusUUID status change %d for %s",
			status.State, uuidStr)
		publishAppInstanceStatus(ctx, status)
		publishAppInstanceSummary(ctx)
	}
}

// Activate this AppInstanceStatus generate config updates to
// the microservices
func activateAIStatusUUID(ctx *zedmanagerContext, uuidStr string) {

	log.Functionf("activateAIStatusUUID(%s)", uuidStr)
	status := lookupAppInstanceStatus(ctx, uuidStr)
	if status == nil {
		log.Functionf("activateAIStatusUUID for %s: Missing AppInstanceStatus",
			uuidStr)
		return
	}
	config := lookupAppInstanceConfig(ctx, uuidStr, true)
	if config == nil || (status.PurgeInprogress == types.BringDown) {
		removeAIStatus(ctx, status)
		return
	}
	doActivate(ctx, uuidStr, *config, status)

	log.Functionf("activateAIStatusUUID status %d for %s",
		status.State, uuidStr)
	publishAppInstanceStatus(ctx, status)
	publishAppInstanceSummary(ctx)

}

// Remove this AppInstanceStatus and generate config removes for
// the microservices
func removeAIStatusUUID(ctx *zedmanagerContext, uuidStr string) {

	log.Functionf("removeAIStatusUUID(%s)", uuidStr)
	status := lookupAppInstanceStatus(ctx, uuidStr)
	if status == nil {
		log.Functionf("removeAIStatusUUID for %s: Missing AppInstanceStatus",
			uuidStr)
		return
	}
	removeAIStatus(ctx, status)
}

func removeAIStatus(ctx *zedmanagerContext, status *types.AppInstanceStatus) {
	uuidStr := status.Key()
	uninstall := (status.PurgeInprogress != types.BringDown)

	domainStatus := lookupDomainStatus(ctx, uuidStr)
	// The VM has been just shutdown in a result of the purge&update command coming from the controller.
	if !uninstall && domainStatus != nil && !domainStatus.Activated {
		// We should do it before the doRemove is called, so that all the volumes are still available.
		if status.SnapStatus.SnapshotOnUpgrade && len(status.SnapStatus.PreparedVolumesSnapshotConfigs) > 0 {
			// Check whether there are snapshots to be deleted first (not to exceed the maximum number of snapshots).
			if len(status.SnapStatus.SnapshotsToBeDeleted) > 0 {
				triggerSnapshotDeletion(status.SnapStatus.SnapshotsToBeDeleted, ctx, status)
			}
			triggerSnapshots(ctx, status)
		}
	}

	changed, done := doRemove(ctx, status, uninstall)
	if changed {
		log.Functionf("removeAIStatus status change for %s",
			uuidStr)
		publishAppInstanceStatus(ctx, status)
	}
	if !done {
		if uninstall {
			log.Functionf("removeAIStatus(%s) waiting for removal",
				status.Key())
		} else {
			log.Functionf("removeAIStatus(%s): PurgeInprogress waiting for removal",
				status.Key())
		}
		return
	}

	if uninstall {
		log.Functionf("removeAIStatus(%s) remove done", uuidStr)
		// Write out what we modified to AppInstanceStatus aka delete
		unpublishAppInstanceStatus(ctx, status)
		return
	}
	log.Functionf("removeAIStatus(%s): PurgeInprogress RecreateVolumes",
		status.Key())
	status.PurgeInprogress = types.RecreateVolumes
	publishAppInstanceStatus(ctx, status)
	config := lookupAppInstanceConfig(ctx, uuidStr, true)
	if config != nil {
		changed := purgeCmdDone(ctx, *config, status)
		if changed {
			publishAppInstanceStatus(ctx, status)
		}
		changed = doUpdate(ctx, *config, status)
		if changed {
			publishAppInstanceStatus(ctx, status)
			publishAppInstanceSummary(ctx)
		}
	} else {
		log.Errorf("removeAIStatus(%s): PurgeInprogress no config!",
			status.Key())
	}
}

// doUpdate will set checkFreedResources in context if some resources
// might have been freed up.
func doUpdate(ctx *zedmanagerContext,
	config types.AppInstanceConfig,
	status *types.AppInstanceStatus) bool {

	uuidStr := status.Key()
	changed := false
	done := false

	log.Functionf("doUpdate: UUID:%s, Name", uuidStr)

	// Manage events necessitating VM shutdown (such as snapshot removal, rollback).
	// This is different from instances where the VM is deactivated due to a purge&update
	// command from the controller, which is taken care of in the removeAIStatus function.
	domainStatus := lookupDomainStatus(ctx, uuidStr)
	// Is the VM already shutdown?
	if domainStatus != nil && !domainStatus.Activated {
		// Trigger snapshot removal
		// Note, that we do not restart the VM explicitly for the snapshot removal, we just wait for the next restart,
		// which ends in this line of code.
		if len(status.SnapStatus.SnapshotsToBeDeleted) > 0 {
			triggerSnapshotDeletion(status.SnapStatus.SnapshotsToBeDeleted, ctx, status)
		}

		// Trigger the rollback process
		if status.SnapStatus.HasRollbackRequest {
			err := triggerRollback(ctx, status)
			if err != nil {
				errDesc := types.ErrorDescription{}
				errDesc.ErrorTime = time.Now()
				errStr := fmt.Sprintf("doUpdate(%s) triggerRollback failed: %s", uuidStr, err)
				errDesc.Error = errStr
				log.Error(errStr)
				status.SnapStatus.HasRollbackRequest = false
				errDesc.ErrorSeverity = types.ErrorSeverityWarning
				setSnapshotStatusError(status, status.SnapStatus.ActiveSnapshot, errDesc)
				status.SetErrorWithSourceAndDescription(errDesc, types.AppInstanceStatus{})
				publishAppInstanceStatus(ctx, status)
				return true
			}
			status.SnapStatus.HasRollbackRequest = false
			publishAppInstanceStatus(ctx, status)
			return true
		}
	}
	// The existence of Config is interpreted to mean the
	// AppInstance should be INSTALLED. Activate is checked separately.
	changed, done = doInstall(ctx, config, status)
	if !done {
		return changed
	}

	// Are we doing a purge?
	if status.PurgeInprogress == types.DownloadAndVerify {
		log.Functionf("PurgeInprogress(%s) volumemgr done",
			status.Key())
		status.PurgeInprogress = types.BringDown
		status.State = types.HALTING
		changed = true
		// Keep the old volumes in place
		_, done := doRemove(ctx, status, false)
		if !done {
			log.Functionf("PurgeInprogress(%s) waiting for removal",
				status.Key())
			return changed
		}
		log.Functionf("PurgeInprogress(%s) bringing it up",
			status.Key())
	}

	if status.PurgeInprogress == types.RecreateVolumes {
		status.PurgeInprogress = types.BringUp
		changed = true
	}

	c, done := doPrepare(ctx, config, status)
	changed = changed || c
	if !done {
		return changed
	}

	// Check if we are still rolling back. Should not activate in that case.
	if status.SnapStatus.RollbackInProgress {
		log.Functionf("Rollback in progress for %s", uuidStr)
		return changed
	}

	effectiveActivate := effectiveActivateCombined(config, ctx)

	if !effectiveActivate {
		if status.Activated || status.ActivateInprogress {
			c := doInactivateHalt(ctx, config, status)
			changed = changed || c
		}
		// Activated and ActivateInprogress flags may be changed during doInactivateHalt call
		if !status.Activated && !status.ActivateInprogress {
			// Since we are not activating we set the state to
			// HALTED to indicate it is not running since it
			// might have been halted before the device was rebooted
			if status.State == types.INSTALLED || status.State == types.START_DELAYED {
				status.State = types.HALTED
				changed = true
			}
		}
		log.Functionf("Waiting for config.Activate for %s", uuidStr)
		return changed
	}
	log.Functionf("Have config.Activate for %s", uuidStr)
	c = doActivate(ctx, uuidStr, config, status)
	changed = changed || c
	log.Functionf("doUpdate done for %s", uuidStr)
	return changed
}

func triggerSnapshots(ctx *zedmanagerContext, status *types.AppInstanceStatus) {
	log.Noticef("triggerSnapshots(%s)", status.Key())
	timeTriggered := time.Now()
	// Set time triggered for snapshots that are not triggered by time
	for _, snapshot := range status.SnapStatus.RequestedSnapshots {
		if snapshot.Snapshot.SnapshotType == types.SnapshotTypeAppUpdate && snapshot.TimeTriggered.IsZero() {
			log.Noticef("Setting snapshot %s timeTriggered to %v", snapshot.Snapshot.SnapshotID, timeTriggered)
			snapshot.TimeTriggered = timeTriggered
		}
	}
	// trigger the snapshots. Use the list of prepared VolumeSnapshotConfigs for that
	for _, volumesSnapshotConfig := range status.SnapStatus.PreparedVolumesSnapshotConfigs {
		log.Noticef("Triggering snapshot %s", volumesSnapshotConfig.SnapshotID)
		publishVolumesSnapshotConfig(ctx, &volumesSnapshotConfig)
		removePreparedVolumesSnapshotConfig(status, volumesSnapshotConfig.SnapshotID)
	}
	publishAppInstanceStatus(ctx, status)
}

// triggerRollback triggers the rollback process. It also restores the volumeRefStatuses from the snapshot config and
// updates the list of volumeRefConfigs. It returns the config of the app instance to be rolled back to.
func triggerRollback(ctx *zedmanagerContext, status *types.AppInstanceStatus) error {
	log.Noticef("Triggering rollback with snapshot %s", status.SnapStatus.ActiveSnapshot)
	// lookup for VolumesSnapshotConfig in the channel
	volumesSnapshotConfig := lookupVolumesSnapshotConfig(ctx, status.SnapStatus.ActiveSnapshot)
	if volumesSnapshotConfig != nil {
		// We have found the VolumesSnapshotConfig in the channel
		// Switch the action to rollback
		volumesSnapshotConfig.Action = types.VolumesSnapshotRollback
		publishVolumesSnapshotConfig(ctx, volumesSnapshotConfig)
		return nil
	}
	// We have not found the VolumesSnapshotConfig in the channel, maybe the system was rebooted
	// Create a new one and publish it
	volumesSnapshotConfig = &types.VolumesSnapshotConfig{
		SnapshotID: status.SnapStatus.ActiveSnapshot,
		VolumeIDs:  make([]uuid.UUID, 0),
		Action:     types.VolumesSnapshotRollback,
		AppUUID:    status.UUIDandVersion.UUID,
	}
	for _, volumeRefConfig := range status.VolumeRefStatusList {
		volumesSnapshotConfig.VolumeIDs = append(volumesSnapshotConfig.VolumeIDs, volumeRefConfig.VolumeID)
	}
	publishVolumesSnapshotConfig(ctx, volumesSnapshotConfig)
	return nil
}

func triggerSnapshotDeletion(snapshotsToBeDeleted []types.SnapshotDesc, ctx *zedmanagerContext, status *types.AppInstanceStatus) {
	for _, snapshot := range snapshotsToBeDeleted {
		log.Noticef("Deleting snapshot %s", snapshot.SnapshotID)
		volumesSnapshotConfig := lookupVolumesSnapshotConfig(ctx, snapshot.SnapshotID)
		if volumesSnapshotConfig != nil {
			// The snapshot has already been triggered, so we need to delete the config and notify volumemanager
			log.Noticef("It has already been triggered, so deleting the config and notifying volumemanager")
			volumesSnapshotConfig.Action = types.VolumesSnapshotDelete
			unpublishVolumesSnapshotConfig(ctx, volumesSnapshotConfig)
			// Remove the snapshot from the list of snapshots to be deleted and publish the status
			removeSnapshotDescFromSlice(&status.SnapStatus.SnapshotsToBeDeleted, snapshot.SnapshotID)
			publishAppInstanceStatus(ctx, status)
		}
	}
}

func doInstall(ctx *zedmanagerContext,
	config types.AppInstanceConfig,
	status *types.AppInstanceStatus) (bool, bool) {

	uuidStr := status.Key()

	log.Functionf("doInstall: UUID: %s", uuidStr)
	allErrors := ""
	var errorSource interface{}
	var errorTime time.Time
	var entities []*types.ErrorEntity
	var severity types.ErrorSeverity
	var retryCondition string //propagate only one
	changed := false

	if len(config.VolumeRefConfigList) != len(status.VolumeRefStatusList) {
		errString := fmt.Sprintf("Mismatch in volumeRefConfig vs. Status length: %d vs %d",
			len(config.VolumeRefConfigList),
			len(status.VolumeRefStatusList))
		if status.PurgeInprogress == types.NotInprogress {
			log.Errorln(errString)
			status.SetError(errString, time.Now())
			return true, false
		}
		log.Warnln(errString)
	}

	// Removing VolumeRefConfig which are removed from the AppInstanceConfig
	// and not used by any domain while purging. VolumeRefConfig which are
	// not in AppInstanceConfig but used by some running domain will be
	// removed as part of purgeCmdDone.
	if status.PurgeInprogress == types.DownloadAndVerify {
		domainVolMap := make(map[string]bool)
		domainConfig := lookupDomainConfig(ctx, status.Key())
		if domainConfig != nil {
			for _, dc := range domainConfig.DiskConfigList {
				domainVolMap[dc.VolumeKey] = true
			}
		}
		removed := false
		newVrs := []types.VolumeRefStatus{}
		for i := range status.VolumeRefStatusList {
			vrs := &status.VolumeRefStatusList[i]
			_, ok := domainVolMap[vrs.VolumeKey()]
			vrc := getVolumeRefConfigFromAIConfig(&config, *vrs)
			if vrc != nil || ok {
				newVrs = append(newVrs, *vrs)
				continue
			}
			log.Functionf("Removing potentially bad VolumeRefStatus %v",
				vrs)
			if status.IsErrorSource(vrs.ErrorSourceType) {
				log.Functionf("Removing error %s", status.Error)
				status.ClearErrorWithSource()
			}
			MaybeRemoveVolumeRefConfig(ctx, config.UUIDandVersion.UUID,
				vrs.VolumeID, vrs.GenerationCounter, vrs.LocalGenerationCounter)
			if !vrs.PendingAdd {
				vrs.PendingAdd = true
				// Keep in VolumeRefStatus until we get an update
				// from volumemgr
				newVrs = append(newVrs, *vrs)
				removed = true
			}
		}
		log.Functionf("purge inactive (%s) volumeRefStatus from %d to %d",
			config.Key(), len(status.VolumeRefStatusList), len(newVrs))
		status.VolumeRefStatusList = newVrs
		if removed {
			log.Functionf("Waiting for bad VolumeRefStatus to go away for AppInst %s",
				status.Key())
			return removed, false
		}
	}

	// Any VolumeRefStatus to add?
	for _, vrc := range config.VolumeRefConfigList {
		vrs := getVolumeRefStatusFromAIStatus(status, vrc)
		if vrs != nil {
			continue
		}
		if status.PurgeInprogress == types.NotInprogress {
			errString := fmt.Sprintf(
				"New volumeRefConfig (VolumeID: %s, GenerationCounter: %d, "+
					"LocalGenerationCounter: %d) found. "+
					"New Storage configs are not allowed unless purged",
				vrc.VolumeID, vrc.GenerationCounter, vrc.LocalGenerationCounter)
			log.Error(errString)
			status.SetError(errString, time.Now())
			return true, false
		}
		newVrs := types.VolumeRefStatus{
			VolumeID:               vrc.VolumeID,
			GenerationCounter:      vrc.GenerationCounter,
			LocalGenerationCounter: vrc.LocalGenerationCounter,
			AppUUID:                vrc.AppUUID,
			PendingAdd:             true,
			State:                  types.INITIAL,
			VerifyOnly:             vrc.VerifyOnly,
		}
		log.Functionf("Adding new VolumeRefStatus %v", newVrs)
		status.VolumeRefStatusList = append(status.VolumeRefStatusList, newVrs)
		changed = true
	}

	if status.PurgeInprogress == types.NotInprogress || status.PurgeInprogress == types.RecreateVolumes {
		for i := range config.VolumeRefConfigList {
			vrc := &config.VolumeRefConfigList[i]
			vrsPubSub := lookupVolumeRefStatus(ctx, vrc.Key())
			if vrsPubSub == nil {
				continue
			}
			if vrsPubSub.VerifyOnly && vrsPubSub.State == types.LOADED {
				vrc.VerifyOnly = false
				publishVolumeRefConfig(ctx, vrc)
			}
		}
	}

	for i := range status.VolumeRefStatusList {
		vrs := &status.VolumeRefStatusList[i]
		// install volume ref again if we had an error
		if status.State < types.CREATED_VOLUME || status.PurgeInprogress != types.NotInprogress || vrs.HasError() {
			c := doInstallVolumeRef(ctx, config, status, vrs)
			if c {
				changed = true
			}
		}
	}
	// Determine minimum state and errors across all of VolumeRefStatus
	minState := types.MAXSTATE
	for _, vrs := range status.VolumeRefStatusList {
		if vrs.State < minState {
			minState = vrs.State
		}
		if vrs.HasError() {
			errorSource = vrs.ErrorSourceType
			errorTime = vrs.ErrorTime
			allErrors = appendError(allErrors, vrs.Error)
			entities = append(entities, &types.ErrorEntity{EntityID: vrs.VolumeID.String(), EntityType: types.ErrorEntityVolume})
			if vrs.ErrorSeverity > severity {
				severity = vrs.ErrorSeverity
			}
			if vrs.ErrorRetryCondition != "" {
				retryCondition = vrs.ErrorRetryCondition
			}
		}
	}
	if minState == types.MAXSTATE {
		// No VolumeRefStatus
		minState = types.INITIAL
	}
	if status.State >= types.BOOTING {
		// Leave unchanged
	} else {
		status.State = minState
		changed = true
	}

	if allErrors == "" {
		status.ClearErrorWithSource()
	} else if errorSource == nil {
		status.SetError(allErrors, errorTime)
	} else {
		if retryCondition == "" {
			// if no retry condition it is an error
			severity = types.ErrorSeverityError
		}
		description := types.ErrorDescription{
			Error:               allErrors,
			ErrorEntities:       entities,
			ErrorSeverity:       severity,
			ErrorRetryCondition: retryCondition,
			ErrorTime:           errorTime,
		}
		status.SetErrorWithSourceAndDescription(description, errorSource)
	}
	if allErrors != "" {
		log.Errorf("Volumemgr error for %s: %s", uuidStr, allErrors)
		return changed, false
	}

	if status.PurgeInprogress != types.DownloadAndVerify && status.PurgeInprogress != types.BringDown && minState < types.CREATED_VOLUME {
		log.Functionf("Waiting for all new volumes for %s", uuidStr)
		return changed, false
	}

	if status.PurgeInprogress == types.DownloadAndVerify && minState < types.LOADED {
		log.Functionf("Waiting for all volumes to be loaded for %s", uuidStr)
		return changed, false
	}

	log.Functionf("Done with volumes for %s", uuidStr)
	log.Functionf("doInstall done for %s", uuidStr)
	return changed, true
}

// If VolumeRefStatus was updated we return true
func doInstallVolumeRef(ctx *zedmanagerContext, config types.AppInstanceConfig,
	status *types.AppInstanceStatus, vrs *types.VolumeRefStatus) bool {

	changed := false
	vrc := getVolumeRefConfigFromAIConfig(&config, *vrs)
	if vrc == nil {
		log.Functionf("doInstallVolumeRef: VolumeRefConfig not found. key: %s", vrs.Key())
		return changed
	}

	if vrs.PendingAdd {
		MaybeAddVolumeRefConfig(ctx, config.UUIDandVersion.UUID,
			vrs.VolumeID, vrs.GenerationCounter, vrs.LocalGenerationCounter,
			vrc.MountDir, vrs.VerifyOnly)
		vrs.PendingAdd = false
		changed = true
	}
	log.Functionf("doInstallVolumeRef: VolumeRefStatus volumeID %s, "+
		"generationCounter %d, localGenerationCounter %d",
		vrs.VolumeID, vrs.GenerationCounter, vrs.LocalGenerationCounter)

	// VolumeRefStatus in app instance status is updated with the volume
	// ref status published from the volumemgr if status gets changed
	pubsubVrs := lookupVolumeRefStatus(ctx, vrs.Key())
	if pubsubVrs == nil {
		log.Functionf("doInstallVolumeRef: Volumemgr VolumeRefStatus not found. key: %s", vrs.Key())
		return changed
	}
	if !cmp.Equal(vrs, pubsubVrs) {
		*vrs = *pubsubVrs
		changed = true
		log.Functionf("VolumeRefStatus updated for %s", vrs.Key())
	}
	return changed
}

func doPrepare(ctx *zedmanagerContext,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) (bool, bool) {

	uuidStr := status.Key()
	log.Functionf("doPrepare for %s", uuidStr)
	changed := false

	// Automatically move from VERIFIED to INSTALLED
	if status.State >= types.BOOTING {
		// Leave unchanged
	} else {
		status.State = types.INSTALLED
		changed = true
	}
	changed = true
	log.Functionf("doPrepare done for %s", uuidStr)
	return changed, true
}

// doActivate - Returns if the status has changed. Doesn't publish any changes.
// It is caller's responsibility to publish.
func doActivate(ctx *zedmanagerContext, uuidStr string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) bool {

	log.Functionf("doActivate for %s", uuidStr)
	changed := false

	// Are we doing a restart and it came down?
	switch status.RestartInprogress {
	case types.BringDown:
		// If !status.Activated e.g, due to error, then
		// need to bring down first.
		ds := lookupDomainStatus(ctx, config.Key())
		if ds != nil {
			if status.DomainName != ds.DomainName {
				status.DomainName = ds.DomainName
				changed = true
			}
			if status.BootTime != ds.BootTime {
				log.Functionf("Update boottime to %s for %s",
					ds.BootTime.Format(time.RFC3339Nano),
					status.Key())
				status.BootTime = ds.BootTime
				changed = true
			}
			c := updateVifUsed(status, *ds)
			if c {
				changed = true
			}
			if !ds.Activated && !ds.HasError() {
				log.Functionf("RestartInprogress(%s) came down - set bring up",
					status.Key())
				status.RestartInprogress = types.BringUp
				changed = true
			}
		}
	}

	// Check that if we have sufficient memory
	if !status.ActivateInprogress && !status.Activated &&
		!ctx.globalConfig.GlobalValueBool(types.IgnoreMemoryCheckForApps) {

		// If we have not yet calculated memory overhead - do it now
		if status.MemOverhead == 0 {
			// Get hypervisor
			hyp, err := hypervisor.GetHypervisor(*ctx.hypervisorPtr)
			if err != nil {
				log.Fatalf("Cannot get hypervisor: %s", err)
			}

			status.MemOverhead, err = hyp.CountMemOverhead(status.DomainName, config.UUIDandVersion.UUID,
				int64(config.FixedResources.Memory), int64(config.FixedResources.VMMMaxMem),
				int64(config.FixedResources.MaxCpus), int64(config.FixedResources.VCpus), config.IoAdapterList,
				ctx.assignableAdapters, ctx.globalConfig)
			// We have to publish the status here, because we need to save the memory overhead value, it's used in getRemainingMemory
			publishAppInstanceStatus(ctx, status)
		}

		remaining, latent, halting, err := getRemainingMemory(ctx)
		if err != nil {
			errStr := fmt.Sprintf("getRemainingMemory failed: %s\n",
				err)
			log.Errorf("doActivate(%s) failed: %s",
				status.Key(), errStr)
			description := types.ErrorDescription{
				Error:               errStr,
				ErrorSeverity:       types.ErrorSeverityNotice,
				ErrorRetryCondition: "Will retry when information about memory will be available in zedmanager",
			}
			status.SetErrorWithSourceAndDescription(description,
				types.AppInstanceConfig{})
			status.MissingMemory = true
			changed = true
			return changed
		}
		need := uint64(config.FixedResources.Memory)<<10 + status.MemOverhead
		if remaining < need {
			var errStr string
			var entities []*types.ErrorEntity
			errSeverity := types.ErrorSeverityError
			if remaining+halting < need {
				errStr = fmt.Sprintf("Remaining memory bytes %d app instance needs %d",
					remaining, need)
			} else {
				errStr = fmt.Sprintf("App instance needs %d bytes but only have %d; waiting for one or more halting app instances to free up %d bytes",
					need, remaining, halting)
				errSeverity = types.ErrorSeverityNotice
			}
			for _, st := range ctx.pubAppInstanceStatus.GetAll() {
				status := st.(types.AppInstanceStatus)
				if status.Activated || status.ActivateInprogress {
					entities = append(entities, &types.ErrorEntity{EntityID: status.UUIDandVersion.UUID.String(), EntityType: types.ErrorEntityAppInstance})
				}
			}
			retryCondition := ""
			if len(entities) > 0 {
				if errSeverity == types.ErrorSeverityError {
					//reduce error severity due to domains with status.Activated || status.ActivateInprogress
					errSeverity = types.ErrorSeverityWarning
				}
				retryCondition = "Retry will be triggered when one or more apps will shutdown"
			}
			log.Errorf("doActivate(%s) failed: %s",
				status.Key(), errStr)
			description := types.ErrorDescription{
				Error:               errStr,
				ErrorSeverity:       errSeverity,
				ErrorRetryCondition: retryCondition,
				ErrorEntities:       entities,
			}
			status.SetErrorWithSourceAndDescription(description, types.AppInstanceConfig{})
			status.MissingMemory = true
			changed = true
			return changed
		}
		if remaining < latent+need {
			log.Warnf("Deploying %s memory %d kB remaining %d kB but latent memory use %d kB",
				config.DisplayName, config.FixedResources.Memory,
				remaining>>10, latent>>10)
		} else {
			log.Functionf("Deploying %s memory %d kB remaining %d kB latent %d kB",
				config.DisplayName, config.FixedResources.Memory,
				remaining>>10, latent>>10)
		}
	}
	// Commit that we will be using memory and
	// Track that we have cleanup work in case something fails
	status.ActivateInprogress = true

	// Make sure we have an AppNetworkConfig
	MaybeAddAppNetworkConfig(ctx, config, status)

	// Check AppNetworkStatus
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns == nil {
		log.Functionf("Waiting for AppNetworkStatus for %s", uuidStr)
		return changed
	}
	if ns.Pending() {
		log.Functionf("Waiting for AppNetworkStatus !Pending for %s", uuidStr)
		return changed
	}
	if ns.HasError() {
		log.Errorf("Received error from zedrouter for %s: %s",
			uuidStr, ns.Error)
		status.SetErrorWithSource(ns.Error, types.AppNetworkStatus{},
			ns.ErrorTime)
		changed = true
		return changed
	}
	if ns.AwaitNetworkInstance {
		log.Functionf("Waiting for required network instances to arrive for %s", uuidStr)
		status.State = types.AWAITNETWORKINSTANCE
		changed = true
		return changed
	}
	updateAppNetworkStatus(status, ns)
	if !ns.Activated {
		log.Functionf("Waiting for AppNetworkStatus Activated for %s", uuidStr)
		return changed
	}
	if status.IsErrorSource(types.AppNetworkStatus{}) {
		log.Functionf("Clearing zedrouter error %s", status.Error)
		status.ClearErrorWithSource()
		changed = true
	}
	log.Tracef("Done with AppNetworkStatus for %s", uuidStr)

	// Do we try to activate an application earlier than it's configured to start?
	if time.Now().Before(status.StartTime) {
		// Check that we delay a not yet active VM or a VM in the bring-up state after restarting/purging
		if !status.Activated || status.RestartInprogress == types.BringUp || status.PurgeInprogress == types.BringUp {
			// If we try to activate it for the first time - mark is with the corresponding state
			if status.State != types.START_DELAYED {
				status.State = types.START_DELAYED
				return true
			}
			// if the VM is already in the START_DELAYED state - just return from the doActivate now
			return changed
		}
		// if the VM already active or in restarting/purging state - continue with the doActivate logic
	}

	// delay this if referencename is not set
	if ctx.hvTypeKube && config.FixedResources.VirtualizationMode == types.NOHYPER {
		var findcontainer bool
		for _, vrc := range config.VolumeRefConfigList {
			vrs := lookupVolumeRefStatus(ctx, vrc.Key())
			if vrs == nil || !vrs.IsContainer() {
				continue
			}
			findcontainer = true
			if vrs.ReferenceName == "" {
				log.Noticef("doActivate: waiting for referencename ")
				if status.State != types.START_DELAYED {
					status.State = types.START_DELAYED
					return true
				}
				return changed
			}
		}
		if !findcontainer {
			log.Noticef("doActivate: no container found, wait")
			if status.State != types.START_DELAYED {
				status.State = types.START_DELAYED
				return true
			}
			return changed
		}
	}

	// Make sure we have a DomainConfig
	// We modify it below and then publish it
	dc, err := MaybeAddDomainConfig(ctx, config, *status, ns)
	if err != nil {
		log.Errorf("Error from MaybeAddDomainConfig for %s: %s",
			uuidStr, err)
		status.SetErrorWithSource(err.Error(), types.DomainStatus{},
			time.Now())
		changed = true
		log.Functionf("Waiting for DomainStatus Activated for %s",
			uuidStr)
		if dc != nil {
			publishDomainConfig(ctx, dc)
		}
		return changed
	}

	// Check DomainStatus; update AppInstanceStatus if error
	ds := lookupDomainStatus(ctx, uuidStr)
	if ds == nil {
		log.Functionf("Waiting for DomainStatus for %s", uuidStr)
		publishDomainConfig(ctx, dc)
		return changed
	}
	if status.DomainName != ds.DomainName {
		status.DomainName = ds.DomainName
		changed = true
	}
	if status.BootTime != ds.BootTime {
		log.Functionf("Update boottime to %s for %s",
			ds.BootTime.Format(time.RFC3339Nano), status.Key())
		status.BootTime = ds.BootTime
		changed = true
	}
	c := updateVifUsed(status, *ds)
	if c {
		changed = true
	}
	// Are we doing a restart?
	if status.RestartInprogress == types.BringDown {
		if dc.Activate {
			log.Functionf("RestartInprogress(%s) Clear Activate",
				status.Key())
			dc.Activate = false
		} else if !ds.Activated {
			log.Functionf("RestartInprogress(%s) Set Activate",
				status.Key())
			status.RestartInprogress = types.BringUp
			changed = true
			dc.Activate = true
		} else {
			log.Functionf("RestartInprogress(%s) waiting for domain down",
				status.Key())
		}
	}
	publishDomainConfig(ctx, dc)
	// Look for xen errors. Ignore if we are going down
	if status.RestartInprogress != types.BringDown {
		if ds.HasError() {
			log.Errorf("Received error from domainmgr for %s: %s",
				uuidStr, ds.Error)
			status.SetErrorWithSourceAndDescription(ds.ErrorDescription, types.DomainStatus{})
			changed = true
		} else if status.IsErrorSource(types.DomainStatus{}) {
			log.Functionf("Clearing domainmgr error %s", status.Error)
			status.ClearErrorWithSource()
			changed = true
		}
	} else {
		if ds.HasError() {
			log.Warnf("bringDown sees error from domainmgr for %s: %s",
				uuidStr, ds.Error)
		}
		if status.IsErrorSource(types.DomainStatus{}) {
			log.Functionf("Clearing domainmgr error %s", status.Error)
			status.ClearErrorWithSource()
			changed = true
		}
	}
	if ds.State != status.State {
		log.Functionf("Set State from DomainStatus from %d to %d",
			status.State, ds.State)
		status.State = ds.State
		changed = true
	}
	// XXX compare with equal before setting changed?
	status.IoAdapterList = ds.IoAdapterList
	changed = true
	if ds.State < types.BOOTING {
		log.Functionf("Waiting for DomainStatus to BOOTING for %s",
			uuidStr)
		return changed
	}
	if ds.Pending() {
		log.Functionf("Waiting for DomainStatus !Pending for %s", uuidStr)
		return changed
	}
	log.Functionf("Done with DomainStatus for %s", uuidStr)

	if !status.Activated {
		status.Activated = true
		status.ActivateInprogress = false
		changed = true
	}
	// Are we doing a restart?
	if status.RestartInprogress == types.BringUp {
		if ds.Activated {
			log.Functionf("RestartInprogress(%s) activated",
				status.Key())
			status.RestartInprogress = types.NotInprogress
			status.State = types.RUNNING
			changed = true
		} else {
			log.Functionf("RestartInprogress(%s) waiting for Activated",
				status.Key())
		}
	}
	if status.PurgeInprogress == types.BringUp {
		if ds.Activated {
			log.Functionf("PurgeInprogress(%s) activated",
				status.Key())
			status.PurgeInprogress = types.NotInprogress
			status.State = types.RUNNING
			changed = true
		} else {
			log.Functionf("PurgeInprogress(%s) waiting for Activated",
				status.Key())
		}
	}
	log.Functionf("doActivate done for %s", uuidStr)
	return changed
}

// Check if VifUsed has changed and return true if it has
func updateVifUsed(statusPtr *types.AppInstanceStatus, ds types.DomainStatus) bool {
	changed := false
	for i := range statusPtr.AppNetAdapters {
		adapterStatus := &statusPtr.AppNetAdapters[i]
		net := ds.VifInfoByVif(adapterStatus.Vif)
		if net != nil && net.VifUsed != adapterStatus.VifUsed {
			log.Functionf("Found VifUsed %s for Vif %s", net.VifUsed, adapterStatus.Vif)
			adapterStatus.VifUsed = net.VifUsed
			changed = true
		}
	}
	return changed
}

func purgeCmdDone(ctx *zedmanagerContext, config types.AppInstanceConfig,
	status *types.AppInstanceStatus) bool {

	log.Functionf("purgeCmdDone(%s) for %s", config.Key(), config.DisplayName)

	changed := false
	// Process the StorageStatusList items which are not in StorageConfigList
	newVrs := []types.VolumeRefStatus{}
	for i := range status.VolumeRefStatusList {
		vrs := &status.VolumeRefStatusList[i]
		vrc := getVolumeRefConfigFromAIConfig(&config, *vrs)
		if vrc != nil {
			newVrs = append(newVrs, *vrs)
			continue
		}
		log.Functionf("purgeCmdDone(%s) unused volume ref %s "+
			"generationCounter %d localGenerationCounter %d",
			config.Key(), vrs.VolumeID, vrs.GenerationCounter, vrs.LocalGenerationCounter)
		MaybeRemoveVolumeRefConfig(ctx, config.UUIDandVersion.UUID,
			vrs.VolumeID, vrs.GenerationCounter, vrs.LocalGenerationCounter)
		changed = true
	}
	log.Functionf("purgeCmdDone(%s) volumeRefStatus from %d to %d",
		config.Key(), len(status.VolumeRefStatusList), len(newVrs))
	status.VolumeRefStatusList = newVrs
	// Update persistent counter
	mapKey := types.UuidToNumKey{UUID: config.UUIDandVersion.UUID}
	purgeCounter := int(config.PurgeCmd.Counter + config.LocalPurgeCmd.Counter)
	err := ctx.appToPurgeCounterMap.Assign(mapKey, purgeCounter, false)
	if err != nil {
		log.Errorf("Failed to update persisted purge counter for app %s-%s: %v",
			config.DisplayName, config.UUIDandVersion.UUID, err)
	}
	return changed
}

func doRemove(ctx *zedmanagerContext,
	status *types.AppInstanceStatus, uninstall bool) (bool, bool) {

	appInstID := status.UUIDandVersion.UUID
	uuidStr := appInstID.String()
	log.Functionf("doRemove for %s uninstall %t", appInstID, uninstall)

	changed := false
	done := false
	c, done := doInactivate(ctx, appInstID, status)
	changed = changed || c
	if !done {
		log.Functionf("doRemove waiting for inactivate for %s", uuidStr)
		return changed, done
	}
	if !status.Activated {
		c := doUnprepare(ctx, uuidStr, status)
		changed = changed || c
		if uninstall {
			c, d := doUninstall(ctx, appInstID, status)
			changed = changed || c
			done = done || d
		} else {
			done = true
		}
	}
	log.Functionf("doRemove done for %s", uuidStr)
	return changed, done
}

func doInactivate(ctx *zedmanagerContext, appInstID uuid.UUID,
	status *types.AppInstanceStatus) (bool, bool) {

	uuidStr := appInstID.String()
	log.Functionf("doInactivate for %s", uuidStr)
	changed := false
	done := false
	uninstall := (status.PurgeInprogress != types.BringDown)

	if uninstall {
		log.Functionf("doInactivate uninstall for %s", uuidStr)
		// First halt the domain by deleting
		if lookupDomainConfig(ctx, uuidStr) != nil {
			unpublishDomainConfig(ctx, uuidStr)
		}

	} else {
		log.Functionf("doInactivate NOT uninstall for %s", uuidStr)
		// First half the domain by clearing Activate
		dc := lookupDomainConfig(ctx, uuidStr)
		if dc == nil {
			log.Warnf("doInactivate: No DomainConfig for %s",
				uuidStr)
		} else if dc.Activate {
			log.Functionf("doInactivate: Clearing Activate for DomainConfig for %s",
				uuidStr)
			dc.Activate = false
			publishDomainConfig(ctx, dc)
		}
	}
	// Check if DomainStatus !Activated; update AppInstanceStatus if error
	ds := lookupDomainStatus(ctx, uuidStr)
	if ds != nil && (uninstall || ds.Activated) {
		if uninstall {
			log.Functionf("Waiting for DomainStatus removal for %s",
				uuidStr)
		} else {
			log.Functionf("Waiting for DomainStatus !Activated for %s",
				uuidStr)
		}
		// Update state
		if status.DomainName != ds.DomainName {
			status.DomainName = ds.DomainName
			changed = true
		}
		if status.BootTime != ds.BootTime {
			log.Functionf("Update boottime to %v for %s",
				ds.BootTime.Format(time.RFC3339Nano),
				status.Key())
			status.BootTime = ds.BootTime
			changed = true
		}
		c := updateVifUsed(status, *ds)
		if c {
			changed = true
		}
		// Look for errors
		if ds.HasError() {
			log.Errorf("Received error from domainmgr for %s: %s",
				uuidStr, ds.Error)
			status.SetErrorWithSource(ds.Error, types.DomainStatus{},
				ds.ErrorTime)
			changed = true
		} else if status.IsErrorSource(types.DomainStatus{}) {
			log.Functionf("Clearing domainmgr error %s",
				status.Error)
			status.ClearErrorWithSource()
			changed = true
		}
		return changed, done
	}
	log.Functionf("Done with DomainStatus removal/deactivate for %s", uuidStr)

	if uninstall {
		if lookupAppNetworkConfig(ctx, uuidStr) != nil {
			unpublishAppNetworkConfig(ctx, uuidStr)
		}
	} else {
		m := lookupAppNetworkConfig(ctx, status.Key())
		if m == nil {
			log.Warnf("doInactivate: No AppNetworkConfig for %s",
				uuidStr)
		} else if m.Activate {
			log.Functionf("doInactivate: Clearing Activate for AppNetworkConfig for %s",
				uuidStr)
			m.Activate = false
			publishAppNetworkConfig(ctx, m)
		}
	}
	// Check if AppNetworkStatus gone or !Activated
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns != nil && (uninstall || ns.Activated) {
		if uninstall {
			log.Functionf("Waiting for AppNetworkStatus removal for %s",
				uuidStr)
		} else {
			log.Functionf("Waiting for AppNetworkStatus !Activated for %s",
				uuidStr)
		}
		if ns.HasError() {
			log.Errorf("Received error from zedrouter for %s: %s",
				uuidStr, ns.Error)
			status.SetErrorWithSource(ns.Error, types.AppNetworkStatus{},
				ns.ErrorTime)
			changed = true
		} else if status.IsErrorSource(types.AppNetworkStatus{}) {
			log.Functionf("Clearing zedrouter error %s", status.Error)
			status.ClearErrorWithSource()
			changed = true
		}
		return changed, done
	}
	log.Functionf("Done with AppNetworkStatus removal/deactivate for %s", uuidStr)
	done = true
	status.Activated = false
	status.ActivateInprogress = false
	ctx.checkFreedResources = true
	log.Functionf("doInactivate done for %s", uuidStr)
	return changed, done
}

func doUnprepare(ctx *zedmanagerContext, uuidStr string,
	status *types.AppInstanceStatus) bool {

	log.Functionf("doUnprepare for %s", uuidStr)
	changed := false

	log.Functionf("doUnprepare done for %s", uuidStr)
	return changed
}

func doUninstall(ctx *zedmanagerContext, appInstID uuid.UUID,
	status *types.AppInstanceStatus) (bool, bool) {

	log.Functionf("doUninstall for %s", appInstID)
	changed := false
	del := false

	// Clean the snapshot files related to this app instance
	for _, snap := range status.SnapStatus.AvailableSnapshots {
		log.Noticef("doUninstall: DeleteSnapshotFiles(%s)", snap.Snapshot.SnapshotID)
		if err := DeleteSnapshotFiles(snap.Snapshot.SnapshotID); err != nil {
			log.Warnf("doUninstall: DeleteSnapshotFiles(%s) failed: %s", snap.Snapshot.SnapshotID, err)
		}
	}

	for i := range status.VolumeRefStatusList {
		vrs := &status.VolumeRefStatusList[i]
		MaybeRemoveVolumeRefConfig(ctx, appInstID,
			vrs.VolumeID, vrs.GenerationCounter, vrs.LocalGenerationCounter)
		changed = true
	}
	log.Tracef("Done with all volume refs removes for %s",
		appInstID)

	del = true
	log.Functionf("doUninstall done for %s", appInstID)
	return changed, del
}

// Handle Activate=false which is different than doInactivate
// Keep DomainConfig around so the vdisks stay around
// Keep AppInstanceConfig around and with Activate set.
func doInactivateHalt(ctx *zedmanagerContext,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) bool {

	uuidStr := status.Key()
	log.Functionf("doInactivateHalt for %s", uuidStr)
	changed := false

	// Check AppNetworkStatus
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns == nil {
		log.Functionf("Waiting for AppNetworkStatus for %s", uuidStr)
		return changed
	}
	updateAppNetworkStatus(status, ns)
	if ns.Pending() {
		log.Functionf("Waiting for AppNetworkStatus !Pending for %s", uuidStr)
		return changed
	}
	// XXX should we make it not Activated?
	if ns.HasError() {
		log.Errorf("Received error from zedrouter for %s: %s",
			uuidStr, ns.Error)
		status.SetErrorWithSource(ns.Error, types.AppNetworkStatus{},
			ns.ErrorTime)
		changed = true
		return changed
	} else if status.IsErrorSource(types.AppNetworkStatus{}) {
		log.Functionf("Clearing zedrouter error %s", status.Error)
		status.ClearErrorWithSource()
		changed = true
	}
	log.Tracef("Done with AppNetworkStatus for %s", uuidStr)

	// Make sure we have a DomainConfig. Clears dc.Activate based
	// on the AppInstanceConfig's Activate
	dc, err := MaybeAddDomainConfig(ctx, config, *status, ns)
	if dc != nil {
		publishDomainConfig(ctx, dc)
	}
	if err != nil {
		log.Errorf("Error from MaybeAddDomainConfig for %s: %s",
			uuidStr, err)
		status.SetError(err.Error(), time.Now())
		changed = true
		log.Functionf("Waiting for DomainStatus Activated for %s",
			uuidStr)
		return changed
	}

	// Check DomainStatus; update AppInstanceStatus if error
	ds := lookupDomainStatus(ctx, uuidStr)
	if ds == nil {
		log.Functionf("Waiting for DomainStatus for %s", uuidStr)
		return changed
	}
	if status.DomainName != ds.DomainName {
		status.DomainName = ds.DomainName
		changed = true
	}
	if status.BootTime != ds.BootTime {
		log.Functionf("Update boottime to %v for %s",
			ds.BootTime.Format(time.RFC3339Nano), status.Key())
		status.BootTime = ds.BootTime
		changed = true
	}
	c := updateVifUsed(status, *ds)
	if c {
		changed = true
	}
	if ds.State != status.State {
		log.Functionf("Set State from DomainStatus from %d to %d",
			status.State, ds.State)
		status.State = ds.State
		changed = true
	}
	// Ignore errors during a halt
	if ds.HasError() {
		log.Warnf("doInactivateHalt sees error from domainmgr for %s: %s",
			uuidStr, ds.Error)
	}
	if status.IsErrorSource(types.DomainStatus{}) {
		log.Functionf("Clearing domainmgr error %s", status.Error)
		status.ClearErrorWithSource()
		changed = true
	}
	// XXX compare with equal before setting changed?
	status.IoAdapterList = ds.IoAdapterList
	changed = true
	if ds.Pending() {
		log.Functionf("Waiting for DomainStatus !Pending for %s", uuidStr)
		return changed
	}
	if ds.Activated {
		log.Functionf("Waiting for Not Activated for DomainStatus %s",
			uuidStr)
		return changed
	}
	// XXX network is still around! Need to call doInactivate in doRemove?
	// XXX fix asymmetry?
	status.Activated = false
	status.ActivateInprogress = false
	ctx.checkFreedResources = true
	changed = true
	log.Functionf("doInactivateHalt done for %s", uuidStr)
	return changed
}

func appendError(allErrors string, lasterr string) string {
	return fmt.Sprintf("%s%s\n\n", allErrors, lasterr)
}
