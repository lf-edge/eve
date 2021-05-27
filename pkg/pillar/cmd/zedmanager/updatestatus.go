// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/uuidtonum"
	"github.com/satori/go.uuid"
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
	config := lookupAppInstanceConfig(ctx, uuidStr)
	if config == nil || (status.PurgeInprogress == types.BringDown) {
		removeAIStatus(ctx, status)
		return
	}
	changed := doUpdate(ctx, *config, status)
	if changed {
		log.Functionf("updateAIStatusUUID status change %d for %s",
			status.State, uuidStr)
		publishAppInstanceStatus(ctx, status)
	}
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
	log.Functionf("removeAIStatus(%s): PurgeInprogress bringing it up",
		status.Key())
	status.PurgeInprogress = types.BringUp
	publishAppInstanceStatus(ctx, status)
	config := lookupAppInstanceConfig(ctx, uuidStr)
	if config != nil {
		changed := doUpdate(ctx, *config, status)
		if changed {
			publishAppInstanceStatus(ctx, status)
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

	log.Functionf("doUpdate: UUID:%s, Name", uuidStr)

	// The existence of Config is interpreted to mean the
	// AppInstance should be INSTALLED. Activate is checked separately.
	changed, done := doInstall(ctx, config, status)
	if !done {
		return changed
	}

	// Are we doing a purge?
	if status.PurgeInprogress == types.RecreateVolumes {
		log.Functionf("PurgeInprogress(%s) volumemgr done",
			status.Key())
		status.PurgeInprogress = types.BringDown
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
	c, done := doPrepare(ctx, config, status)
	changed = changed || c
	if !done {
		return changed
	}

	if !status.EffectiveActivate {
		if status.Activated || status.ActivateInprogress {
			c := doInactivateHalt(ctx, config, status)
			changed = changed || c
		} else {
			// Since we are not activating we set the state to
			// HALTED to indicate it is not running since it
			// might have been halted before the device was rebooted
			if status.State == types.INSTALLED {
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

func doInstall(ctx *zedmanagerContext,
	config types.AppInstanceConfig,
	status *types.AppInstanceStatus) (bool, bool) {

	uuidStr := status.Key()

	log.Functionf("doInstall: UUID: %s", uuidStr)
	allErrors := ""
	var errorSource interface{}
	var errorTime time.Time
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
	if status.PurgeInprogress == types.RecreateVolumes {
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
			_, ok := domainVolMap[vrs.Key()]
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
				vrs.VolumeID, vrs.GenerationCounter)
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
			errString := fmt.Sprintf("New volumeRefConfig (VolumeID: %s, GenerationCounter: %d) found."+
				"New Storage configs are not allowed unless purged",
				vrc.VolumeID, vrc.GenerationCounter)
			log.Error(errString)
			status.SetError(errString, time.Now())
			return true, false
		}
		newVrs := types.VolumeRefStatus{
			VolumeID:          vrc.VolumeID,
			GenerationCounter: vrc.GenerationCounter,
			RefCount:          vrc.RefCount,
			MountDir:          vrc.MountDir,
			PendingAdd:        true,
			State:             types.INITIAL,
		}
		log.Functionf("Adding new VolumeRefStatus %v", newVrs)
		status.VolumeRefStatusList = append(status.VolumeRefStatusList, newVrs)
		changed = true
	}

	if status.State < types.CREATED_VOLUME || status.PurgeInprogress != types.NotInprogress {
		for i := range status.VolumeRefStatusList {
			vrs := &status.VolumeRefStatusList[i]
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
		status.SetErrorWithSource(allErrors, errorSource, errorTime)
	}
	if allErrors != "" {
		log.Errorf("Volumemgr error for %s: %s", uuidStr, allErrors)
		return changed, false
	}

	if minState < types.CREATED_VOLUME {
		log.Functionf("Waiting for all volumes for %s", uuidStr)
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
	if vrs.PendingAdd {
		MaybeAddVolumeRefConfig(ctx, config.UUIDandVersion.UUID,
			vrs.VolumeID, vrs.GenerationCounter, vrs.MountDir)
		vrs.PendingAdd = false
		changed = true
	}
	log.Functionf("doInstallVolumeRef: VolumeRefStatus volumeID %s, generationCounter %d",
		vrs.VolumeID, vrs.GenerationCounter)

	// VolumeRefStatus in app instance status is updated with the volume
	// ref status published from the volumemgr if status gets changed
	pubsubVrs := lookupVolumeRefStatus(ctx, vrs.Key())
	if pubsubVrs == nil {
		log.Functionf("doInstallVolumeRef: Volumemgr VolumeRefStatus not found. key: %s", vrs.Key())
		return changed
	}
	if *pubsubVrs != *vrs {
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

		remaining, latent, err := getRemainingMemory(ctx)
		if err != nil {
			errStr := fmt.Sprintf("getRemainingMemory failed: %s\n",
				err)
			log.Errorf("doActivate(%s) failed: %s",
				status.Key(), errStr)
			status.SetErrorWithSource(errStr,
				types.AppInstanceConfig{}, time.Now())
			status.MissingMemory = true
			changed = true
			return changed
		}
		if remaining < uint64(config.FixedResources.Memory)<<10 {
			errStr := fmt.Sprintf("Remaining memory bytes %d app instance needs %d\n",
				remaining, config.FixedResources.Memory<<10)
			log.Errorf("doActivate(%s) failed: %s",
				status.Key(), errStr)
			status.SetErrorWithSource(errStr,
				types.AppInstanceConfig{}, time.Now())
			status.MissingMemory = true
			publishAppInstanceStatus(ctx, status)
			changed = true
			return changed
		}
		if remaining < latent+uint64(config.FixedResources.Memory)<<10 {
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
			status.SetErrorWithSource(ds.Error, types.DomainStatus{},
				ds.ErrorTime)
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
		switch status.State {
		case types.RESTARTING, types.PURGING:
			// Leave unchanged
		default:
			log.Functionf("Set State from DomainStatus from %d to %d",
				status.State, ds.State)
			status.State = ds.State
			changed = true
		}
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
			_ = purgeCmdDone(ctx, config, status)
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
	for i := range statusPtr.UnderlayNetworks {
		ulStatus := &statusPtr.UnderlayNetworks[i]
		net := ds.VifInfoByVif(ulStatus.Vif)
		if net != nil && net.VifUsed != ulStatus.VifUsed {
			log.Functionf("Found VifUsed %s for Vif %s", net.VifUsed, ulStatus.Vif)
			ulStatus.VifUsed = net.VifUsed
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
		log.Functionf("purgeCmdDone(%s) unused volume ref %s generationCounter %d",
			config.Key(), vrs.VolumeID, vrs.GenerationCounter)
		MaybeRemoveVolumeRefConfig(ctx, config.UUIDandVersion.UUID,
			vrs.VolumeID, vrs.GenerationCounter)
		changed = true
	}
	log.Functionf("purgeCmdDone(%s) volumeRefStatus from %d to %d",
		config.Key(), len(status.VolumeRefStatusList), len(newVrs))
	status.VolumeRefStatusList = newVrs
	// Update persistent counter
	uuidtonum.UuidToNumAllocate(log, ctx.pubUuidToNum,
		status.UUIDandVersion.UUID,
		int(config.PurgeCmd.Counter),
		false, "purgeCmdCounter")
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
	log.Functionf("Done with AppNetworkStatus removal/deactivaye for %s", uuidStr)
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

	for i := range status.VolumeRefStatusList {
		vrs := &status.VolumeRefStatusList[i]
		MaybeRemoveVolumeRefConfig(ctx, appInstID,
			vrs.VolumeID, vrs.GenerationCounter)
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
		switch status.State {
		case types.RESTARTING, types.PURGING:
			// Leave unchanged
		default:
			log.Functionf("Set State from DomainStatus from %d to %d",
				status.State, ds.State)
			status.State = ds.State
			changed = true
		}
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
	// XXX fix assymetry?
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
