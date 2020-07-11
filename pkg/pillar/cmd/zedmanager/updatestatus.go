// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/uuidtonum"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Update this AppInstanceStatus generate config updates to
// the microservices
func updateAIStatusUUID(ctx *zedmanagerContext, uuidStr string) {

	log.Infof("updateAIStatusUUID(%s)", uuidStr)
	status := lookupAppInstanceStatus(ctx, uuidStr)
	if status == nil {
		log.Infof("updateAIStatusUUID for %s: Missing AppInstanceStatus",
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
		log.Infof("updateAIStatusUUID status change %d for %s",
			status.State, uuidStr)
		publishAppInstanceStatus(ctx, status)
	}
}

// Remove this AppInstanceStatus and generate config removes for
// the microservices
func removeAIStatusUUID(ctx *zedmanagerContext, uuidStr string) {

	log.Infof("removeAIStatusUUID(%s)", uuidStr)
	status := lookupAppInstanceStatus(ctx, uuidStr)
	if status == nil {
		log.Infof("removeAIStatusUUID for %s: Missing AppInstanceStatus",
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
		log.Infof("removeAIStatus status change for %s",
			uuidStr)
		publishAppInstanceStatus(ctx, status)
	}
	if !done {
		if uninstall {
			log.Infof("removeAIStatus(%s) waiting for removal",
				status.Key())
		} else {
			log.Infof("removeAIStatus(%s): PurgeInprogress waiting for removal",
				status.Key())
		}
		return
	}

	if uninstall {
		log.Infof("removeAIStatus(%s) remove done", uuidStr)
		// Write out what we modified to AppInstanceStatus aka delete
		unpublishAppInstanceStatus(ctx, status)
		return
	}
	log.Infof("removeAIStatus(%s): PurgeInprogress bringing it up",
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

func doUpdate(ctx *zedmanagerContext,
	config types.AppInstanceConfig,
	status *types.AppInstanceStatus) bool {

	uuidStr := status.Key()

	log.Infof("doUpdate: UUID:%s, Name", uuidStr)

	// The existence of Config is interpreted to mean the
	// AppInstance should be INSTALLED. Activate is checked separately.
	changed, done := doInstall(ctx, config, status)
	if !done {
		return changed
	}

	// Are we doing a purge?
	if status.PurgeInprogress == types.RecreateVolumes {
		log.Infof("PurgeInprogress(%s) volumemgr done",
			status.Key())
		status.PurgeInprogress = types.BringDown
		changed = true
		// Keep the old volumes in place
		_, done := doRemove(ctx, status, false)
		if !done {
			log.Infof("PurgeInprogress(%s) waiting for removal",
				status.Key())
			return changed
		}
		log.Infof("PurgeInprogress(%s) bringing it up",
			status.Key())
	}
	c, done := doPrepare(ctx, config, status)
	changed = changed || c
	if !done {
		return changed
	}

	if !config.Activate {
		if status.Activated || status.ActivateInprogress {
			c := doInactivateHalt(ctx, config, status)
			changed = changed || c
		} else {
			// If we have a !ReadOnly disk this will create a copy
			err := MaybeAddDomainConfig(ctx, config, *status, nil)
			if err != nil {
				log.Errorf("Error from MaybeAddDomainConfig for %s: %s",
					uuidStr, err)
				status.SetErrorWithSource(err.Error(),
					types.DomainStatus{}, time.Now())
				changed = true
			}
		}
		log.Infof("Waiting for config.Activate for %s", uuidStr)
		return changed
	}
	log.Infof("Have config.Activate for %s", uuidStr)
	c = doActivate(ctx, uuidStr, config, status)
	changed = changed || c
	log.Infof("doUpdate done for %s", uuidStr)
	return changed
}

func doInstall(ctx *zedmanagerContext,
	config types.AppInstanceConfig,
	status *types.AppInstanceStatus) (bool, bool) {

	uuidStr := status.Key()

	log.Infof("doInstall: UUID: %s", uuidStr)
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

	// If we are purging and we failed to activate due some volumes
	// which are now removed from VolumeRefConfigList we remove them
	if status.PurgeInprogress == types.RecreateVolumes && !status.Activated {
		removed := false
		newVrs := []types.VolumeRefStatus{}
		for i := range status.VolumeRefStatusList {
			vrs := &status.VolumeRefStatusList[i]
			vrc := getVolumeRefConfigFromAIConfig(&config, *vrs)
			if vrc != nil {
				newVrs = append(newVrs, *vrs)
				continue
			}
			log.Infof("Removing potentially bad VolumeRefStatus %v",
				vrs)
			if status.IsErrorSource(vrs.ErrorSourceType) {
				log.Infof("Removing error %s", status.Error)
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
		log.Infof("purge inactive (%s) volumeRefStatus from %d to %d",
			config.Key(), len(status.VolumeRefStatusList), len(newVrs))
		status.VolumeRefStatusList = newVrs
		if removed {
			log.Infof("Waiting for bad VolumeRefStatus to go away for AppInst %s",
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
			PendingAdd:        true,
			State:             types.INITIAL,
		}
		log.Infof("Adding new VolumeRefStatus %v", newVrs)
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
		log.Infof("Waiting for all volumes for %s", uuidStr)
		return changed, false
	}
	log.Infof("Done with volumes for %s", uuidStr)
	log.Infof("doInstall done for %s", uuidStr)
	return changed, true
}

// If VolumeRefStatus was updated we return true
func doInstallVolumeRef(ctx *zedmanagerContext, config types.AppInstanceConfig,
	status *types.AppInstanceStatus, vrs *types.VolumeRefStatus) bool {

	changed := false
	if vrs.PendingAdd {
		MaybeAddVolumeRefConfig(ctx, config.UUIDandVersion.UUID,
			vrs.VolumeID, vrs.GenerationCounter)
		vrs.PendingAdd = false
		changed = true
	}
	log.Infof("doInstallVolumeRef: VolumeRefStatus volumeID %s, generationCounter %d",
		vrs.VolumeID, vrs.GenerationCounter)

	// VolumeRefStatus in app instance status is updated with the volume
	// ref status published from the volumemgr if status gets changed
	pubsubVrs := lookupVolumeRefStatus(ctx, vrs.Key())
	if pubsubVrs == nil {
		log.Infof("doInstallVolumeRef: Volumemgr VolumeRefStatus not found. key: %s", vrs.Key())
		return changed
	}
	if *pubsubVrs != *vrs {
		*vrs = *pubsubVrs
		changed = true
		log.Infof("VolumeRefStatus updated for %s", vrs.Key())
	}
	if vrs.IsContainer() && !status.IsContainer {
		status.IsContainer = true
		changed = true
		log.Infof("doInstallVolumeRef: Updated IsContainer flag in app instance status to %v",
			status.IsContainer)
	}
	return changed
}

func doPrepare(ctx *zedmanagerContext,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) (bool, bool) {

	uuidStr := status.Key()
	log.Infof("doPrepare for %s", uuidStr)
	changed := false

	if len(config.OverlayNetworkList) != len(status.EIDList) {
		errString := fmt.Sprintf("Mismatch in OLList config vs. status length: %d vs %d",
			len(config.OverlayNetworkList),
			len(status.EIDList))
		log.Error(errString)
		status.SetError(errString, time.Now())
		changed = true
		return changed, false
	}

	// Make sure we have an EIDConfig for each overlay
	for _, ec := range config.OverlayNetworkList {
		MaybeAddEIDConfig(ctx, config.UUIDandVersion,
			config.DisplayName, &ec)
	}
	// Check EIDStatus for each overlay; update AppInstanceStatus
	eidsAllocated := true
	for i, ec := range config.OverlayNetworkList {
		key := types.EidKey(config.UUIDandVersion, ec.IID)
		es := lookupEIDStatus(ctx, key)
		if es == nil || es.Pending() {
			log.Infof("lookupEIDStatus %s failed",
				key)
			eidsAllocated = false
			continue
		}
		status.EIDList[i] = es.EIDStatusDetails
		if status.EIDList[i].EID == nil {
			log.Infof("Missing EID for %s", key)
			eidsAllocated = false
		} else {
			log.Infof("Found EID %v for %s",
				status.EIDList[i].EID, key)
			changed = true
		}
	}
	if !eidsAllocated {
		log.Infof("Waiting for all EID allocations for %s", uuidStr)
		return changed, false
	}
	// Automatically move from VERIFIED to INSTALLED
	if status.State >= types.BOOTING {
		// Leave unchanged
	} else {
		status.State = types.INSTALLED
		changed = true
	}
	changed = true
	log.Infof("Done with EID allocations for %s", uuidStr)
	log.Infof("doPrepare done for %s", uuidStr)
	return changed, true
}

// doActivate - Returns if the status has changed. Doesn't publish any changes.
// It is caller's responsibility to publish.
func doActivate(ctx *zedmanagerContext, uuidStr string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) bool {

	log.Infof("doActivate for %s", uuidStr)
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
				log.Infof("Update boottime to %s for %s",
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
				log.Infof("RestartInprogress(%s) came down - set bring up",
					status.Key())
				status.RestartInprogress = types.BringUp
				changed = true
			}
		}
	}

	// Track that we have cleanup work in case something fails
	status.ActivateInprogress = true

	// Make sure we have an AppNetworkConfig
	MaybeAddAppNetworkConfig(ctx, config, status)

	// Check AppNetworkStatus
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns == nil {
		log.Infof("Waiting for AppNetworkStatus for %s", uuidStr)
		return changed
	}
	if ns.Pending() {
		log.Infof("Waiting for AppNetworkStatus !Pending for %s", uuidStr)
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
	updateAppNetworkStatus(status, ns)
	if !ns.Activated {
		log.Infof("Waiting for AppNetworkStatus Activated for %s", uuidStr)
		return changed
	}
	if status.IsErrorSource(types.AppNetworkStatus{}) {
		log.Infof("Clearing zedrouter error %s", status.Error)
		status.ClearErrorWithSource()
		changed = true
	}
	log.Debugf("Done with AppNetworkStatus for %s", uuidStr)

	// Make sure we have a DomainConfig
	err := MaybeAddDomainConfig(ctx, config, *status, ns)
	if err != nil {
		log.Errorf("Error from MaybeAddDomainConfig for %s: %s",
			uuidStr, err)
		status.SetErrorWithSource(err.Error(), types.DomainStatus{},
			time.Now())
		changed = true
		log.Infof("Waiting for DomainStatus Activated for %s",
			uuidStr)
		return changed
	}

	// Check DomainStatus; update AppInstanceStatus if error
	ds := lookupDomainStatus(ctx, uuidStr)
	if ds == nil {
		log.Infof("Waiting for DomainStatus for %s", uuidStr)
		return changed
	}
	if status.DomainName != ds.DomainName {
		status.DomainName = ds.DomainName
		changed = true
	}
	if status.BootTime != ds.BootTime {
		log.Infof("Update boottime to %s for %s",
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
		dc := lookupDomainConfig(ctx, config.Key())
		if dc == nil {
			log.Errorf("RestartInprogress(%s) No DomainConfig",
				status.Key())
		} else if dc.Activate {
			log.Infof("RestartInprogress(%s) Clear Activate",
				status.Key())
			dc.Activate = false
			publishDomainConfig(ctx, dc)
		} else if !ds.Activated {
			log.Infof("RestartInprogress(%s) Set Activate",
				status.Key())
			status.RestartInprogress = types.BringUp
			changed = true
			dc.Activate = true
			publishDomainConfig(ctx, dc)
		} else {
			log.Infof("RestartInprogress(%s) waiting for domain down",
				status.Key())
		}
	}
	// Look for xen errors. Ignore if we are going down
	if status.RestartInprogress != types.BringDown {
		if ds.HasError() {
			log.Errorf("Received error from domainmgr for %s: %s",
				uuidStr, ds.Error)
			status.SetErrorWithSource(ds.Error, types.DomainStatus{},
				ds.ErrorTime)
			changed = true
		} else if status.IsErrorSource(types.DomainStatus{}) {
			log.Infof("Clearing domainmgr error %s", status.Error)
			status.ClearErrorWithSource()
			changed = true
		}
	} else {
		if ds.HasError() {
			log.Warnf("bringDown sees error from domainmgr for %s: %s",
				uuidStr, ds.Error)
		}
		if status.IsErrorSource(types.DomainStatus{}) {
			log.Infof("Clearing domainmgr error %s", status.Error)
			status.ClearErrorWithSource()
			changed = true
		}
	}
	if ds.State != status.State {
		switch status.State {
		case types.RESTARTING, types.PURGING:
			// Leave unchanged
		default:
			log.Infof("Set State from DomainStatus from %d to %d",
				status.State, ds.State)
			status.State = ds.State
			changed = true
		}
	}
	// XXX compare with equal before setting changed?
	status.IoAdapterList = ds.IoAdapterList
	changed = true
	if ds.State < types.BOOTING {
		log.Infof("Waiting for DomainStatus to BOOTING for %s",
			uuidStr)
		return changed
	}
	if ds.Pending() {
		log.Infof("Waiting for DomainStatus !Pending for %s", uuidStr)
		return changed
	}
	log.Infof("Done with DomainStatus for %s", uuidStr)

	if !status.Activated {
		status.Activated = true
		status.ActivateInprogress = false
		changed = true
	}
	// Are we doing a restart?
	if status.RestartInprogress == types.BringUp {
		if ds.Activated {
			log.Infof("RestartInprogress(%s) activated",
				status.Key())
			status.RestartInprogress = types.NotInprogress
			status.State = types.RUNNING
			changed = true
		} else {
			log.Infof("RestartInprogress(%s) waiting for Activated",
				status.Key())
		}
	}
	if status.PurgeInprogress == types.BringUp {
		if ds.Activated {
			log.Infof("PurgeInprogress(%s) activated",
				status.Key())
			status.PurgeInprogress = types.NotInprogress
			status.State = types.RUNNING
			_ = purgeCmdDone(ctx, config, status)
			changed = true
		} else {
			log.Infof("PurgeInprogress(%s) waiting for Activated",
				status.Key())
		}
	}
	log.Infof("doActivate done for %s", uuidStr)
	return changed
}

// Check if VifUsed has changed and return true if it has
func updateVifUsed(statusPtr *types.AppInstanceStatus, ds types.DomainStatus) bool {
	changed := false
	for i := range statusPtr.UnderlayNetworks {
		ulStatus := &statusPtr.UnderlayNetworks[i]
		net := ds.VifInfoByVif(ulStatus.Vif)
		if net != nil && net.VifUsed != ulStatus.VifUsed {
			log.Infof("Found VifUsed %s for Vif %s", net.VifUsed, ulStatus.Vif)
			ulStatus.VifUsed = net.VifUsed
			changed = true
		}
	}
	for i := range statusPtr.OverlayNetworks {
		olStatus := &statusPtr.OverlayNetworks[i]
		net := ds.VifInfoByVif(olStatus.Vif)
		if net != nil && net.VifUsed != olStatus.VifUsed {
			log.Infof("Found VifUsed %s for Vif %s", net.VifUsed, olStatus.Vif)
			olStatus.VifUsed = net.VifUsed
			changed = true
		}
	}

	// for _, ec := range config.OverlayNetworkList {
	return changed
}

func purgeCmdDone(ctx *zedmanagerContext, config types.AppInstanceConfig,
	status *types.AppInstanceStatus) bool {

	log.Infof("purgeCmdDone(%s) for %s", config.Key(), config.DisplayName)

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
		log.Infof("purgeCmdDone(%s) unused volume ref %s generationCounter %d",
			config.Key(), vrs.VolumeID, vrs.GenerationCounter)
		MaybeRemoveVolumeRefConfig(ctx, config.UUIDandVersion.UUID,
			vrs.VolumeID, vrs.GenerationCounter)
		changed = true
	}
	log.Infof("purgeCmdDone(%s) volumeRefStatus from %d to %d",
		config.Key(), len(status.VolumeRefStatusList), len(newVrs))
	status.VolumeRefStatusList = newVrs
	// Update persistent counter
	uuidtonum.UuidToNumAllocate(ctx.pubUuidToNum,
		status.UUIDandVersion.UUID,
		int(status.PurgeCmd.Counter),
		false, "purgeCmdCounter")
	return changed
}

func doRemove(ctx *zedmanagerContext,
	status *types.AppInstanceStatus, uninstall bool) (bool, bool) {

	appInstID := status.UUIDandVersion.UUID
	uuidStr := appInstID.String()
	log.Infof("doRemove for %s uninstall %t", appInstID, uninstall)

	changed := false
	done := false
	c, done := doInactivate(ctx, appInstID, status)
	changed = changed || c
	if !done {
		log.Infof("doRemove waiting for inactivate for %s", uuidStr)
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
	log.Infof("doRemove done for %s", uuidStr)
	return changed, done
}

func doInactivate(ctx *zedmanagerContext, appInstID uuid.UUID,
	status *types.AppInstanceStatus) (bool, bool) {

	uuidStr := appInstID.String()
	log.Infof("doInactivate for %s", uuidStr)
	changed := false
	done := false
	uninstall := (status.PurgeInprogress != types.BringDown)

	if uninstall {
		log.Infof("doInactivate uninstall for %s", uuidStr)
		// First halt the domain by deleting
		if lookupDomainConfig(ctx, uuidStr) != nil {
			unpublishDomainConfig(ctx, uuidStr)
		}

	} else {
		log.Infof("doInactivate NOT uninstall for %s", uuidStr)
		// First half the domain by clearing Activate
		dc := lookupDomainConfig(ctx, uuidStr)
		if dc == nil {
			log.Warnf("doInactivate: No DomainConfig for %s",
				uuidStr)
		} else if dc.Activate {
			log.Infof("doInactivate: Clearing Activate for DomainConfig for %s",
				uuidStr)
			dc.Activate = false
			publishDomainConfig(ctx, dc)
		}
	}
	// Check if DomainStatus !Activated; update AppInstanceStatus if error
	ds := lookupDomainStatus(ctx, uuidStr)
	if ds != nil && (uninstall || ds.Activated) {
		if uninstall {
			log.Infof("Waiting for DomainStatus removal for %s",
				uuidStr)
		} else {
			log.Infof("Waiting for DomainStatus !Activated for %s",
				uuidStr)
		}
		// Update state
		if status.DomainName != ds.DomainName {
			status.DomainName = ds.DomainName
			changed = true
		}
		if status.BootTime != ds.BootTime {
			log.Infof("Update boottime to %v for %s",
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
			log.Infof("Clearing domainmgr error %s",
				status.Error)
			status.ClearErrorWithSource()
			changed = true
		}
		return changed, done
	}
	log.Infof("Done with DomainStatus removal/deactivate for %s", uuidStr)

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
			log.Infof("doInactivate: Clearing Activate for AppNetworkConfig for %s",
				uuidStr)
			m.Activate = false
			publishAppNetworkConfig(ctx, m)
		}
	}
	// Check if AppNetworkStatus gone or !Activated
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns != nil && (uninstall || ns.Activated) {
		if uninstall {
			log.Infof("Waiting for AppNetworkStatus removal for %s",
				uuidStr)
		} else {
			log.Infof("Waiting for AppNetworkStatus !Activated for %s",
				uuidStr)
		}
		if ns.HasError() {
			log.Errorf("Received error from zedrouter for %s: %s",
				uuidStr, ns.Error)
			status.SetErrorWithSource(ns.Error, types.AppNetworkStatus{},
				ns.ErrorTime)
			changed = true
		} else if status.IsErrorSource(types.AppNetworkStatus{}) {
			log.Infof("Clearing zedrouter error %s", status.Error)
			status.ClearErrorWithSource()
			changed = true
		}
		return changed, done
	}
	log.Infof("Done with AppNetworkStatus removal/deactivaye for %s", uuidStr)
	done = true
	status.Activated = false
	status.ActivateInprogress = false
	log.Infof("doInactivate done for %s", uuidStr)
	return changed, done
}

func doUnprepare(ctx *zedmanagerContext, uuidStr string,
	status *types.AppInstanceStatus) bool {

	log.Infof("doUnprepare for %s", uuidStr)
	changed := false

	// Remove the EIDConfig for each overlay
	for _, es := range status.EIDList {
		unpublishEIDConfig(ctx, status.UUIDandVersion, &es)
	}
	// Check EIDStatus for each overlay; update AppInstanceStatus
	eidsFreed := true
	for i, es := range status.EIDList {
		key := types.EidKey(status.UUIDandVersion, es.IID)
		es := lookupEIDStatus(ctx, key)
		if es != nil {
			log.Infof("lookupEIDStatus not gone on remove for %s",
				key)
			// Could it have changed?
			changed = true
			status.EIDList[i] = es.EIDStatusDetails
			eidsFreed = false
			continue
		}
		changed = true
	}
	if !eidsFreed {
		log.Infof("Waiting for all EID frees for %s", uuidStr)
		return changed
	}
	log.Debugf("Done with EID frees for %s", uuidStr)

	log.Infof("doUnprepare done for %s", uuidStr)
	return changed
}

func doUninstall(ctx *zedmanagerContext, appInstID uuid.UUID,
	status *types.AppInstanceStatus) (bool, bool) {

	log.Infof("doUninstall for %s", appInstID)
	changed := false
	del := false

	for i := range status.VolumeRefStatusList {
		vrs := &status.VolumeRefStatusList[i]
		MaybeRemoveVolumeRefConfig(ctx, appInstID,
			vrs.VolumeID, vrs.GenerationCounter)
		changed = true
	}
	log.Debugf("Done with all volume refs removes for %s",
		appInstID)

	del = true
	log.Infof("doUninstall done for %s", appInstID)
	return changed, del
}

// Handle Activate=false which is different than doInactivate
// Keep DomainConfig around so the vdisks stay around
// Keep AppInstanceConfig around and with Activate set.
func doInactivateHalt(ctx *zedmanagerContext,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) bool {

	uuidStr := status.Key()
	log.Infof("doInactivateHalt for %s", uuidStr)
	changed := false

	// Check AppNetworkStatus
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns == nil {
		log.Infof("Waiting for AppNetworkStatus for %s", uuidStr)
		return changed
	}
	updateAppNetworkStatus(status, ns)
	if ns.Pending() {
		log.Infof("Waiting for AppNetworkStatus !Pending for %s", uuidStr)
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
		log.Infof("Clearing zedrouter error %s", status.Error)
		status.ClearErrorWithSource()
		changed = true
	}
	log.Debugf("Done with AppNetworkStatus for %s", uuidStr)

	// Make sure we have a DomainConfig. Clears dc.Activate based
	// on the AppInstanceConfig's Activate
	err := MaybeAddDomainConfig(ctx, config, *status, ns)
	if err != nil {
		log.Errorf("Error from MaybeAddDomainConfig for %s: %s",
			uuidStr, err)
		status.SetError(err.Error(), time.Now())
		changed = true
		log.Infof("Waiting for DomainStatus Activated for %s",
			uuidStr)
		return changed
	}

	// Check DomainStatus; update AppInstanceStatus if error
	ds := lookupDomainStatus(ctx, uuidStr)
	if ds == nil {
		log.Infof("Waiting for DomainStatus for %s", uuidStr)
		return changed
	}
	if status.DomainName != ds.DomainName {
		status.DomainName = ds.DomainName
		changed = true
	}
	if status.BootTime != ds.BootTime {
		log.Infof("Update boottime to %v for %s",
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
			log.Infof("Set State from DomainStatus from %d to %d",
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
		log.Infof("Clearing domainmgr error %s", status.Error)
		status.ClearErrorWithSource()
		changed = true
	}
	// XXX compare with equal before setting changed?
	status.IoAdapterList = ds.IoAdapterList
	changed = true
	if ds.Pending() {
		log.Infof("Waiting for DomainStatus !Pending for %s", uuidStr)
		return changed
	}
	if ds.Activated {
		log.Infof("Waiting for Not Activated for DomainStatus %s",
			uuidStr)
		return changed
	}
	// XXX network is still around! Need to call doInactivate in doRemove?
	// XXX fix assymetry?
	status.Activated = false
	status.ActivateInprogress = false
	changed = true
	log.Infof("doInactivateHalt done for %s", uuidStr)
	return changed
}

func appendError(allErrors string, lasterr string) string {
	return fmt.Sprintf("%s%s\n\n", allErrors, lasterr)
}
