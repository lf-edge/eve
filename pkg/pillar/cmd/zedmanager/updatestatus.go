// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/uuidtonum"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Find all the config which refer to this safename.
func updateAIStatusWithStorageSafename(ctx *zedmanagerContext,
	safename string,
	updateContainerImageID bool, containerImageID string) {

	log.Infof("updateAIStatusWithStorageSafename for %s - "+
		"updateContainerImageID: %v, containerImageID: %s\n",
		safename, updateContainerImageID, containerImageID)
	pub := ctx.pubAppInstanceStatus
	items := pub.GetAll()
	found := false
	for key, st := range items {
		status := cast.CastAppInstanceStatus(st)
		if status.Key() != key {
			log.Errorf("updateAIStatusWithStorageSafename key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		log.Debugf("Processing AppInstanceConfig for UUID %s\n",
			status.UUIDandVersion.UUID)
		for _, ss := range status.StorageStatusList {
			safename2 := types.UrlToSafename(ss.Name, ss.ImageSha256)
			if safename == safename2 {
				log.Infof("Found StorageStatus URL %s safename %s\n",
					ss.Name, safename)
				changed := false
				if updateContainerImageID &&
					status.ContainerImageID != containerImageID {
					log.Debugf("Update AIS ContainerImageID: %s\n",
						containerImageID)
					status.ContainerImageID = containerImageID
					changed = true
				} else {
					log.Debugf("No change in ContainerId in Status. "+
						"status.ContainerImageID: %s, containerImageID: %s\n",
						status.ContainerImageID, containerImageID)

				}
				if changed {
					publishAppInstanceStatus(ctx, &status)
				}
				updateAIStatusUUID(ctx, status.Key())
				found = true
			}
		}
	}
	if !found {
		log.Warnf("updateAIStatusWithStorageSafename for %s not found\n", safename)
	}
}

// Find all the config which refer to this safename.
func updateAIStatusSha(ctx *zedmanagerContext, sha string) {

	log.Infof("updateAIStatusSha for %s\n", sha)
	pub := ctx.pubAppInstanceStatus
	items := pub.GetAll()
	found := false
	for key, st := range items {
		status := cast.CastAppInstanceStatus(st)
		if status.Key() != key {
			log.Errorf("updateAIStatusSha key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		log.Debugf("Processing AppInstanceConfig for UUID %s\n",
			status.UUIDandVersion.UUID)
		for _, ss := range status.StorageStatusList {
			if sha == ss.ImageSha256 {
				log.Infof("Found StorageStatus URL %s sha %s\n",
					ss.Name, sha)
				updateAIStatusUUID(ctx, status.Key())
				found = true
			}
		}
	}
	if !found {
		log.Warnf("updateAIStatusSha for %s not found\n", sha)
	}
}

// Update this AppInstanceStatus generate config updates to
// the microservices
func updateAIStatusUUID(ctx *zedmanagerContext, uuidStr string) {

	log.Infof("updateAIStatusUUID(%s)\n", uuidStr)
	status := lookupAppInstanceStatus(ctx, uuidStr)
	if status == nil {
		log.Infof("updateAIStatusUUID for %s: Missing AppInstanceStatus\n",
			uuidStr)
		return
	}
	config := lookupAppInstanceConfig(ctx, uuidStr)
	if config == nil || (status.PurgeInprogress == types.BRING_DOWN) {
		removeAIStatus(ctx, status)
		return
	}
	changed := doUpdate(ctx, uuidStr, *config, status)
	if changed {
		log.Infof("updateAIStatusUUID status change for %s\n",
			uuidStr)
		publishAppInstanceStatus(ctx, status)
	}
}

// Remove this AppInstanceStatus and generate config removes for
// the microservices
func removeAIStatusUUID(ctx *zedmanagerContext, uuidStr string) {

	log.Infof("removeAIStatusUUID(%s)\n", uuidStr)
	status := lookupAppInstanceStatus(ctx, uuidStr)
	if status == nil {
		log.Infof("removeAIStatusUUID for %s: Missing AppInstanceStatus\n",
			uuidStr)
		return
	}
	removeAIStatus(ctx, status)
}

func removeAIStatus(ctx *zedmanagerContext, status *types.AppInstanceStatus) {
	uuidStr := status.Key()
	uninstall := (status.PurgeInprogress != types.BRING_DOWN)
	changed, done := doRemove(ctx, uuidStr, status, uninstall)
	if changed {
		log.Infof("removeAIStatus status change for %s\n",
			uuidStr)
		publishAppInstanceStatus(ctx, status)
	}
	if !done {
		if uninstall {
			log.Infof("removeAIStatus(%s) waiting for removal\n",
				status.Key())
		} else {
			log.Infof("removeAIStatus(%s): PurgeInprogress waiting for removal\n",
				status.Key())
		}
		return
	}

	if uninstall {
		log.Infof("removeAIStatus(%s) remove done\n", uuidStr)
		// Write out what we modified to AppInstanceStatus aka delete
		unpublishAppInstanceStatus(ctx, status)
		return
	}
	log.Infof("removeAIStatus(%s): PurgeInprogress bringing it up\n",
		status.Key())
	status.PurgeInprogress = types.BRING_UP
	publishAppInstanceStatus(ctx, status)
	config := lookupAppInstanceConfig(ctx, uuidStr)
	if config != nil {
		changed := doUpdate(ctx, uuidStr, *config, status)
		if changed {
			publishAppInstanceStatus(ctx, status)
		}
	} else {
		log.Errorf("removeAIStatus(%s): PurgeInprogress no config!\n",
			status.Key())
	}
}

// Find all the Status which refer to this safename.
func removeAIStatusSafename(ctx *zedmanagerContext, safename string) {

	log.Infof("removeAIStatusSafename for %s\n", safename)
	pub := ctx.pubAppInstanceStatus
	items := pub.GetAll()
	found := false
	for key, st := range items {
		status := cast.CastAppInstanceStatus(st)
		if status.Key() != key {
			log.Errorf("removeAIStatusSafename key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		log.Debugf("Processing AppInstanceStatus for UUID %s\n",
			status.UUIDandVersion.UUID)
		for _, ss := range status.StorageStatusList {
			safename2 := types.UrlToSafename(ss.Name, ss.ImageSha256)
			if safename == safename2 {
				log.Debugf("Found StorageStatus URL %s safename %s\n",
					ss.Name, safename2)
				updateOrRemove(ctx, status)
				found = true
			}
		}
	}
	if !found {
		log.Warnf("removeAIStatusSafename for %s not found\n", safename)
	}
}

// Find all the Status which refer to this safename.
func removeAIStatusSha(ctx *zedmanagerContext, sha string) {

	log.Infof("removeAIStatusSha for %s\n", sha)
	pub := ctx.pubAppInstanceStatus
	items := pub.GetAll()
	found := false
	for key, st := range items {
		status := cast.CastAppInstanceStatus(st)
		if status.Key() != key {
			log.Errorf("removeAIStatusSha key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		log.Debugf("Processing AppInstanceStatus for UUID %s\n",
			status.UUIDandVersion.UUID)
		for _, ss := range status.StorageStatusList {
			if sha == ss.ImageSha256 {
				log.Debugf("Found StorageStatus URL %s sha %s\n",
					ss.Name, sha)
				updateOrRemove(ctx, status)
				found = true
			}
		}
	}
	if !found {
		log.Warnf("removeAIStatusSha for %s not found\n", sha)
	}
}

// If we have an AIConfig we update it - the image might have disappeared.
// Otherwise we proceeed with remove.
func updateOrRemove(ctx *zedmanagerContext, status types.AppInstanceStatus) {
	uuidStr := status.Key()
	log.Infof("updateOrRemove(%s)\n", uuidStr)
	config := lookupAppInstanceConfig(ctx, uuidStr)
	if config == nil || (status.PurgeInprogress == types.BRING_DOWN) {
		log.Infof("updateOrRemove: remove for %s\n", uuidStr)
		removeAIStatus(ctx, &status)
	} else {
		log.Infof("updateOrRemove: update for %s\n", uuidStr)
		changed := doUpdate(ctx, uuidStr, *config, &status)
		if changed {
			log.Infof("updateOrRemove status change for %s\n",
				uuidStr)
			publishAppInstanceStatus(ctx, &status)
		}
	}
}

func doUpdate(ctx *zedmanagerContext, uuidStr string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) bool {

	log.Infof("doUpdate for %s\n", uuidStr)

	// The existence of Config is interpreted to mean the
	// AppInstance should be INSTALLED. Activate is checked separately.
	changed, done := doInstall(ctx, uuidStr, config, status)
	if !done {
		return changed
	}

	// Are we doing a purge?
	if status.PurgeInprogress == types.DOWNLOAD {
		log.Infof("PurgeInprogress(%s) download/verifications done\n",
			status.Key())
		status.PurgeInprogress = types.BRING_DOWN
		changed = true
		// Keep the verified images in place
		_, done := doRemove(ctx, uuidStr, status, false)
		if !done {
			log.Infof("PurgeInprogress(%s) waiting for removal\n",
				status.Key())
			return changed
		}
		log.Infof("PurgeInprogress(%s) bringing it up\n",
			status.Key())
	}
	c, done := doPrepare(ctx, uuidStr, config, status)
	changed = changed || c
	if !done {
		return changed
	}

	if !config.Activate {
		if status.Activated || status.ActivateInprogress {
			c := doInactivateHalt(ctx, uuidStr, config, status)
			changed = changed || c
		} else {
			// If we have a !ReadOnly disk this will create a copy
			err := MaybeAddDomainConfig(ctx, config, *status, nil)
			if err != nil {
				log.Errorf("Error from MaybeAddDomainConfig for %s: %s\n",
					uuidStr, err)
				status.ErrorSource = pubsub.TypeToName(types.DomainStatus{})
				status.Error = fmt.Sprintf("%s", err)
				status.ErrorSource = pubsub.TypeToName(types.DomainStatus{})
				status.ErrorTime = time.Now()
				changed = true
			}
		}
		log.Infof("Waiting for config.Activate for %s\n", uuidStr)
		return changed
	}
	log.Infof("Have config.Activate for %s\n", uuidStr)
	c = doActivate(ctx, uuidStr, config, status)
	changed = changed || c
	log.Infof("doUpdate done for %s\n", uuidStr)
	return changed
}

func doInstall(ctx *zedmanagerContext, uuidStr string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) (bool, bool) {

	log.Infof("doInstall for %s\n", uuidStr)
	minState := types.MAXSTATE
	allErrors := ""
	errorSource := ""
	var errorTime time.Time
	changed := false

	if len(config.StorageConfigList) != len(status.StorageStatusList) {
		errString := fmt.Sprintf("Mismatch in storageConfig vs. Status length: %d vs %d\n",
			len(config.StorageConfigList),
			len(status.StorageStatusList))
		if status.PurgeInprogress == types.NONE {
			log.Errorln(errString)
			status.Error = errString
			status.ErrorTime = time.Now()
			changed = true
			return changed, false
		}
		log.Warnln(errString)
	}
	// If we are purging and we failed to activate due some images
	// which are not removed from StorageConfigList we remove them
	if status.PurgeInprogress == types.DOWNLOAD && !status.Activated {
		removed := false
		newSs := []types.StorageStatus{}
		for i := range status.StorageStatusList {
			ss := &status.StorageStatusList[i]
			sc := lookupStorageConfig(&config, *ss)
			if sc != nil {
				newSs = append(newSs, *ss)
				continue
			}
			log.Infof("Removing potentially bad StorageStatus %v\n",
				ss)
			if status.ErrorSource == ss.ErrorSource {
				log.Infof("Removing error %s\n", status.Error)
				status.Error = ""
				status.ErrorSource = ""
				status.ErrorTime = time.Time{}
			}
			c := MaybeRemoveStorageStatus(ctx, ss)
			if c {
				// Keep in StorageStatus until we get an update
				// from downloader
				newSs = append(newSs, *ss)
				removed = true
			}
		}
		log.Infof("purge inactive (%s) storageStatus from %d to %d\n",
			config.Key(), len(status.StorageStatusList), len(newSs))
		status.StorageStatusList = newSs
		if removed {
			log.Infof("Waiting for bad StorageStatus to go away for %s\n",
				uuidStr)
			return removed, false
		}
	}

	// Any StorageStatus to add?
	for _, sc := range config.StorageConfigList {
		ss := lookupStorageStatus(status, sc)
		if ss != nil {
			continue
		}
		if status.PurgeInprogress == types.NONE {
			errString := fmt.Sprintf("New storageConfig not allowed unless purge:\n\t%s\n\t%s",
				sc.Name, sc.ImageSha256)
			log.Errorln(errString)
			status.Error = errString
			status.ErrorTime = time.Now()
			changed = true
			return changed, false
		}
		newSs := types.StorageStatus{}
		newSs.UpdateFromStorageConfig(sc)
		log.Infof("Adding new StorageStatus %v\n", newSs)
		status.StorageStatusList = append(status.StorageStatusList, newSs)
		changed = true
	}

	waitingForCerts := false

	for i := range status.StorageStatusList {
		ss := &status.StorageStatusList[i]
		sc := config.StorageConfigList[i]
		safename := types.UrlToSafename(ss.Name, ss.ImageSha256)
		log.Infof("StorageStatus URL %s safename %s\n",
			ss.Name, safename)

		// Shortcut if image is already verified
		vs := lookupVerifyImageStatusAny(ctx, safename,
			ss.ImageSha256)
		// Handle post-reboot verification in progress by allowing
		// types.DOWNLOADED. If the verification later fails we will
		// get a delete of the VerifyImageStatus and skip this
		if vs != nil && (vs.State == types.DELIVERED || vs.State == types.DOWNLOADED) {
			switch vs.State {
			case types.DELIVERED:
				log.Infof("doUpdate found verified image for %s sha %s\n",
					safename, ss.ImageSha256)

			case types.DOWNLOADED:
				log.Infof("doUpdate found downloaded/verified image for %s sha %s\n",
					safename, ss.ImageSha256)
			}
			if vs.Safename != safename {
				// If found based on sha256
				log.Infof("doUpdate found diff safename %s\n",
					vs.Safename)
			}
			// If we don't already have a RefCount add one
			if !ss.HasVerifierRef {
				log.Infof("doUpdate !HasVerifierRef vs. RefCount %d for %s\n",
					vs.RefCount, vs.Safename)
				// We don't need certs since Status already
				// exists
				MaybeAddVerifyImageConfig(ctx, vs.Safename, ss, false)
				ss.HasVerifierRef = true
				changed = true
			}
			if minState > vs.State {
				minState = vs.State
			}
			if vs.State != ss.State {
				ss.State = vs.State
				ss.Progress = 100
				changed = true
			}
			continue
		}
		if !ss.HasDownloaderRef {
			log.Infof("doUpdate !HasDownloaderRef for %s\n",
				safename)
			AddOrRefcountDownloaderConfig(ctx, safename, sc, ss)
			ss.HasDownloaderRef = true
			changed = true
		}
		ds := lookupDownloaderStatus(ctx, safename)
		if ds == nil {
			log.Infof("lookupDownloaderStatus %s failed\n",
				safename)
			minState = types.DOWNLOAD_STARTED
			ss.State = types.DOWNLOAD_STARTED
			changed = true
			continue
		}
		if minState > ds.State {
			minState = ds.State
		}
		if ds.State != ss.State {
			ss.State = ds.State
			changed = true
		}
		if ds.Progress != ss.Progress {
			ss.Progress = ds.Progress
			changed = true
		}
		if ds.Pending() {
			log.Infof("lookupDownloaderStatus %s Pending\n",
				safename)
			continue
		}
		if ds.LastErr != "" {
			log.Errorf("Received error from downloader for %s: %s\n",
				safename, ds.LastErr)
			ss.Error = ds.LastErr
			ss.ErrorSource = pubsub.TypeToName(types.DownloaderStatus{})
			errorSource = ss.ErrorSource
			allErrors = appendError(allErrors, "downloader",
				ds.LastErr)
			ss.ErrorTime = ds.LastErrTime
			errorTime = ds.LastErrTime
			changed = true
			continue
		} else if ss.ErrorSource == pubsub.TypeToName(types.DownloaderStatus{}) {
			log.Infof("Clearing downloader error %s\n", ss.Error)
			ss.Error = ""
			ss.ErrorSource = ""
			ss.ErrorTime = time.Time{}
			changed = true
		}
		switch ds.State {
		case types.INITIAL:
			// Nothing to do
		case types.DOWNLOAD_STARTED:
			// Nothing to do
		case types.DOWNLOADED:
			// Kick verifier to start if it hasn't already
			if !ss.HasVerifierRef {
				if MaybeAddVerifyImageConfig(ctx, safename, ss, true) {
					ss.HasVerifierRef = true
					changed = true
				} else {
					// Waiting for certs
					waitingForCerts = true
				}
			}
		}
	}

	if minState == types.MAXSTATE {
		// Odd; no StorageConfig in list
		minState = types.DOWNLOADED
	}
	switch status.State {
	case types.RESTARTING, types.PURGING:
		// Leave unchanged
	default:
		status.State = minState
		changed = true
	}
	status.Error = allErrors
	status.ErrorSource = errorSource
	status.ErrorTime = errorTime
	if allErrors != "" {
		log.Errorf("Download error for %s: %s\n", uuidStr, allErrors)
		return changed, false
	}

	if minState < types.DOWNLOADED {
		log.Infof("Waiting for all downloads for %s\n", uuidStr)
		return changed, false
	}
	if waitingForCerts {
		log.Infof("Waiting for certs for %s\n", uuidStr)
		return changed, false
	}
	log.Infof("Done with downloads for %s\n", uuidStr)
	minState = types.MAXSTATE
	for i := range status.StorageStatusList {
		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(ss.Name, ss.ImageSha256)
		log.Infof("Found StorageStatus URL %s safename %s\n",
			ss.Name, safename)

		vs := lookupVerifyImageStatusAny(ctx, safename,
			ss.ImageSha256)
		if vs == nil {
			log.Infof("lookupVerifyImageStatusAny %s sha %s failed\n",
				safename, ss.ImageSha256)
			// Keep at current state
			minState = types.DOWNLOADED
			changed = true
			continue
		}
		if minState > vs.State {
			minState = vs.State
		}
		if vs.State != ss.State {
			ss.State = vs.State
			changed = true
		}
		if vs.Pending() {
			log.Infof("lookupVerifyImageStatusAny %s Pending\n",
				safename)
			continue
		}
		if vs.LastErr != "" {
			log.Errorf("Received error from verifier for %s: %s\n",
				safename, vs.LastErr)
			ss.Error = vs.LastErr
			ss.ErrorSource = pubsub.TypeToName(types.VerifyImageStatus{})
			errorSource = ss.ErrorSource
			allErrors = appendError(allErrors, "verifier",
				vs.LastErr)
			ss.ErrorTime = vs.LastErrTime
			errorTime = vs.LastErrTime
			changed = true
			continue
		} else if ss.ErrorSource == pubsub.TypeToName(types.VerifyImageStatus{}) {
			log.Infof("Clearing verifier error %s\n", ss.Error)
			ss.Error = ""
			ss.ErrorSource = ""
			ss.ErrorTime = time.Time{}
			changed = true
		}
		switch vs.State {
		case types.INITIAL:
			// Nothing to do
		default:
			ss.ActiveFileLocation = finalDirname + "/" + vs.Safename
			log.Infof("Update SSL ActiveFileLocation for %s: %s\n",
				uuidStr, ss.ActiveFileLocation)
			changed = true
		}
	}
	if minState == types.MAXSTATE {
		// Odd; no StorageConfig in list
		minState = types.DELIVERED
	}
	switch status.State {
	case types.RESTARTING, types.PURGING:
		// Leave unchanged
	default:
		status.State = minState
		changed = true
	}
	status.Error = allErrors
	status.ErrorSource = errorSource
	status.ErrorTime = errorTime
	if allErrors != "" {
		log.Errorf("Verify error for %s: %s\n", uuidStr, allErrors)
		return changed, false
	}

	if minState < types.DELIVERED {
		log.Infof("Waiting for all verifications for %s\n", uuidStr)
		return changed, false
	}
	log.Infof("Done with verifications for %s\n", uuidStr)
	log.Infof("doInstall done for %s\n", uuidStr)
	return changed, true
}

func doPrepare(ctx *zedmanagerContext, uuidStr string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) (bool, bool) {

	log.Infof("doPrepare for %s\n", uuidStr)
	changed := false

	if len(config.OverlayNetworkList) != len(status.EIDList) {
		errString := fmt.Sprintf("Mismatch in OLList config vs. status length: %d vs %d\n",
			len(config.OverlayNetworkList),
			len(status.EIDList))
		log.Errorln(errString)
		status.Error = errString
		status.ErrorTime = time.Now()
		changed = true
		return changed, false
	}

	// XXX could allocate EIDs before we download for better parallelism
	// with zedcloud
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
			log.Infof("lookupEIDStatus %s failed\n",
				key)
			eidsAllocated = false
			continue
		}
		status.EIDList[i] = es.EIDStatusDetails
		if status.EIDList[i].EID == nil {
			log.Infof("Missing EID for %s\n", key)
			eidsAllocated = false
		} else {
			log.Infof("Found EID %v for %s\n",
				status.EIDList[i].EID, key)
			changed = true
		}
	}
	if !eidsAllocated {
		log.Infof("Waiting for all EID allocations for %s\n", uuidStr)
		return changed, false
	}
	// Automatically move from DELIVERED to INSTALLED
	switch status.State {
	case types.RESTARTING, types.PURGING:
		// Leave unchanged
	default:
		status.State = types.INSTALLED
	}
	changed = true
	log.Infof("Done with EID allocations for %s\n", uuidStr)
	log.Infof("doPrepare done for %s\n", uuidStr)
	return changed, true
}

// Really a constant
var nilUUID uuid.UUID

func doActivate(ctx *zedmanagerContext, uuidStr string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) bool {

	log.Infof("doActivate for %s\n", uuidStr)
	changed := false

	// Are we doing a restart and it came down?
	switch status.RestartInprogress {
	case types.BRING_DOWN:
		// If !status.Activated e.g, due to error, then
		// need to bring down first.
		ds := lookupDomainStatus(ctx, config.Key())
		if ds != nil && status.DomainName != ds.DomainName {
			status.DomainName = ds.DomainName
			changed = true
		}
		if ds != nil && status.BootTime != ds.BootTime {
			status.BootTime = ds.BootTime
			changed = true
		}
		if ds != nil && !ds.Activated && ds.LastErr == "" {
			log.Infof("RestartInprogress(%s) came down - set bring up\n",
				status.Key())
			status.RestartInprogress = types.BRING_UP
			changed = true
		}
	}

	// Track that we have cleanup work in case something fails
	status.ActivateInprogress = true

	// Make sure we have an AppNetworkConfig
	MaybeAddAppNetworkConfig(ctx, config, status)

	// Check AppNetworkStatus
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns == nil {
		log.Infof("Waiting for AppNetworkStatus for %s\n", uuidStr)
		return changed
	}
	if ns.Pending() {
		log.Infof("Waiting for AppNetworkStatus !Pending for %s\n", uuidStr)
		return changed
	}
	if ns.Error != "" {
		log.Errorf("Received error from zedrouter for %s: %s\n",
			uuidStr, ns.Error)
		status.Error = ns.Error
		status.ErrorSource = pubsub.TypeToName(types.AppNetworkStatus{})
		status.ErrorTime = ns.ErrorTime
		changed = true
		return changed
	}
	updateAppNetworkStatus(status, ns)
	if !ns.Activated {
		log.Infof("Waiting for AppNetworkStatus Activated for %s\n", uuidStr)
		return changed
	}
	if status.ErrorSource == pubsub.TypeToName(types.AppNetworkStatus{}) {
		log.Infof("Clearing zedrouter error %s\n", status.Error)
		status.Error = ""
		status.ErrorSource = ""
		status.ErrorTime = time.Time{}
		changed = true
	}
	log.Debugf("Done with AppNetworkStatus for %s\n", uuidStr)

	// Make sure we have a DomainConfig
	err := MaybeAddDomainConfig(ctx, config, *status, ns)
	if err != nil {
		log.Errorf("Error from MaybeAddDomainConfig for %s: %s\n",
			uuidStr, err)
		status.Error = fmt.Sprintf("%s", err)
		status.ErrorSource = pubsub.TypeToName(types.DomainStatus{})
		status.ErrorTime = time.Now()
		changed = true
		log.Infof("Waiting for DomainStatus Activated for %s\n",
			uuidStr)
		return changed
	}

	// Check DomainStatus; update AppInstanceStatus if error
	ds := lookupDomainStatus(ctx, uuidStr)
	if ds == nil {
		log.Infof("Waiting for DomainStatus for %s\n", uuidStr)
		return changed
	}
	if status.DomainName != ds.DomainName {
		status.DomainName = ds.DomainName
		changed = true
	}
	if status.BootTime != ds.BootTime {
		status.BootTime = ds.BootTime
		changed = true
	}
	// Are we doing a restart?
	if status.RestartInprogress == types.BRING_DOWN {
		dc := lookupDomainConfig(ctx, config.Key())
		if dc == nil {
			log.Errorf("RestartInprogress(%s) No DomainConfig\n",
				status.Key())
		} else if dc.Activate {
			log.Infof("RestartInprogress(%s) Clear Activate\n",
				status.Key())
			dc.Activate = false
			publishDomainConfig(ctx, dc)
		} else if !ds.Activated {
			log.Infof("RestartInprogress(%s) Set Activate\n",
				status.Key())
			status.RestartInprogress = types.BRING_UP
			changed = true
			dc.Activate = true
			publishDomainConfig(ctx, dc)
		} else {
			log.Infof("RestartInprogress(%s) waiting for domain down\n",
				status.Key())
		}
	}
	// Look for xen errors. Ignore if we are going down
	if status.RestartInprogress != types.BRING_DOWN {
		if ds.LastErr != "" {
			log.Errorf("Received error from domainmgr for %s: %s\n",
				uuidStr, ds.LastErr)
			status.Error = ds.LastErr
			status.ErrorSource = pubsub.TypeToName(types.DomainStatus{})
			status.ErrorTime = ds.LastErrTime
			changed = true
		} else if status.ErrorSource == pubsub.TypeToName(types.DomainStatus{}) {
			log.Infof("Clearing domainmgr error %s\n", status.Error)
			status.Error = ""
			status.ErrorSource = ""
			status.ErrorTime = time.Time{}
			changed = true
		}
	} else {
		if ds.LastErr != "" {
			log.Warnf("bringDown sees error from domainmgr for %s: %s\n",
				uuidStr, ds.LastErr)
		}
		if status.ErrorSource == pubsub.TypeToName(types.DomainStatus{}) {
			log.Infof("Clearing domainmgr error %s\n", status.Error)
			status.Error = ""
			status.ErrorSource = ""
			status.ErrorTime = time.Time{}
			changed = true
		}
	}
	if ds.State != status.State {
		switch status.State {
		case types.RESTARTING, types.PURGING:
			// Leave unchanged
		default:
			log.Infof("Set State from DomainStatus from %d to %d\n",
				status.State, ds.State)
			status.State = ds.State
			changed = true
		}
	}
	// XXX compare with equal before setting changed?
	status.IoAdapterList = ds.IoAdapterList
	changed = true
	if ds.State < types.BOOTING {
		log.Infof("Waiting for DomainStatus to BOOTING for %s\n",
			uuidStr)
		return changed
	}
	if ds.Pending() {
		log.Infof("Waiting for DomainStatus !Pending for %s\n", uuidStr)
		return changed
	}
	// Update ActiveFileLocation and Vdev from DiskStatus
	for _, disk := range ds.DiskStatusList {
		// Need to lookup based on ImageSha256
		found := false
		for i := range status.StorageStatusList {
			ss := &status.StorageStatusList[i]
			if ss.ImageSha256 == disk.ImageSha256 {
				found = true
				log.Infof("Found SSL ActiveFileLocation for %s: %s\n",
					uuidStr, disk.ActiveFileLocation)
				if ss.ActiveFileLocation != disk.ActiveFileLocation {
					log.Infof("Update SSL ActiveFileLocation for %s: %s\n",
						uuidStr, disk.ActiveFileLocation)
					ss.ActiveFileLocation = disk.ActiveFileLocation
					changed = true
				}
				if ss.Vdev != disk.Vdev {
					log.Infof("Update SSL Vdev for %s: %s\n",
						uuidStr, disk.Vdev)
					ss.Vdev = disk.Vdev
					changed = true
				}
			}
		}
		if !found {
			log.Infof("No SSL ActiveFileLocation for %s: %s\n",
				uuidStr, disk.ActiveFileLocation)
		}
	}
	log.Infof("Done with DomainStatus for %s\n", uuidStr)

	if !status.Activated {
		status.Activated = true
		status.ActivateInprogress = false
		changed = true
	}
	// Are we doing a restart?
	if status.RestartInprogress == types.BRING_UP {
		if ds.Activated {
			log.Infof("RestartInprogress(%s) activated\n",
				status.Key())
			status.RestartInprogress = types.NONE
			status.State = types.RUNNING
			changed = true
		} else {
			log.Infof("RestartInprogress(%s) waiting for Activated\n",
				status.Key())
		}
	}
	if status.PurgeInprogress == types.BRING_UP {
		if ds.Activated {
			log.Infof("PurgeInprogress(%s) activated\n",
				status.Key())
			status.PurgeInprogress = types.NONE
			status.State = types.RUNNING
			_ = purgeCmdDone(ctx, config, status)
			changed = true
		} else {
			log.Infof("PurgeInprogress(%s) waiting for Activated\n",
				status.Key())
		}
	}
	log.Infof("doActivate done for %s\n", uuidStr)
	return changed
}

func lookupStorageStatus(status *types.AppInstanceStatus, sc types.StorageConfig) *types.StorageStatus {

	for i := range status.StorageStatusList {
		ss := &status.StorageStatusList[i]
		if ss.Name == sc.Name &&
			ss.ImageSha256 == sc.ImageSha256 {
			log.Debugf("lookupStorageStatus found %s %s\n",
				ss.Name, ss.ImageSha256)
			return ss
		}
	}
	return nil
}

func lookupStorageConfig(config *types.AppInstanceConfig, ss types.StorageStatus) *types.StorageConfig {

	for i := range config.StorageConfigList {
		sc := &config.StorageConfigList[i]
		if ss.Name == sc.Name &&
			ss.ImageSha256 == sc.ImageSha256 {
			log.Debugf("lookupStorageConfig found SC %s %s\n",
				sc.Name, sc.ImageSha256)
			return sc
		}
	}
	return nil
}

func purgeCmdDone(ctx *zedmanagerContext, config types.AppInstanceConfig,
	status *types.AppInstanceStatus) bool {

	log.Infof("purgeCmdDone(%s) for %s\n", config.Key(), config.DisplayName)

	changed := false
	// Process the StorageStatusList items which are not in StorageConfigList
	newSs := []types.StorageStatus{}
	for i := range status.StorageStatusList {
		ss := &status.StorageStatusList[i]
		sc := lookupStorageConfig(&config, *ss)
		if sc != nil {
			newSs = append(newSs, *ss)
			continue
		}
		log.Debugf("purgeCmdDone(%s) unused SS %s %s\n",
			config.Key(), ss.Name, ss.ImageSha256)
		c := MaybeRemoveStorageStatus(ctx, ss)
		if c {
			changed = true
		}
	}
	log.Infof("purgeCmdDone(%s) storageStatus from %d to %d\n",
		config.Key(), len(status.StorageStatusList), len(newSs))
	status.StorageStatusList = newSs
	// Update persistent counter
	uuidtonum.UuidToNumAllocate(ctx.pubUuidToNum,
		status.UUIDandVersion.UUID,
		int(status.PurgeCmd.Counter),
		false, "purgeCmdCounter")
	return changed
}

// MaybeRemoveStorageStatus returns changed bool and updates StorageStatus
func MaybeRemoveStorageStatus(ctx *zedmanagerContext, ss *types.StorageStatus) bool {

	changed := false

	// Decrease refcount if we had increased it
	if ss.HasVerifierRef {
		MaybeRemoveVerifyImageConfigSha256(ctx, ss.ImageSha256)
		ss.HasVerifierRef = false
		changed = true
	}
	// Decrease refcount if we had increased it
	if ss.HasDownloaderRef {
		safename := types.UrlToSafename(ss.Name, ss.ImageSha256)
		MaybeRemoveDownloaderConfig(ctx, safename)
		ss.HasDownloaderRef = false
		changed = true
	}
	return changed
}

func doRemove(ctx *zedmanagerContext, uuidStr string,
	status *types.AppInstanceStatus, uninstall bool) (bool, bool) {

	log.Infof("doRemove for %s uninstall %v\n", uuidStr, uninstall)

	changed := false
	done := false
	c, done := doInactivate(ctx, uuidStr, status)
	changed = changed || c
	if !done {
		log.Infof("doRemove waiting for inactivate for %s\n", uuidStr)
		return changed, done
	}
	if !status.Activated {
		c := doUnprepare(ctx, uuidStr, status)
		changed = changed || c
		if uninstall {
			c, d := doUninstall(ctx, uuidStr, status)
			changed = changed || c
			done = done || d
		} else {
			done = true
		}
	}
	log.Infof("doRemove done for %s\n", uuidStr)
	return changed, done
}

func doInactivate(ctx *zedmanagerContext, uuidStr string,
	status *types.AppInstanceStatus) (bool, bool) {

	log.Infof("doInactivate for %s\n", uuidStr)
	changed := false
	done := false

	// First halt the domain
	unpublishDomainConfig(ctx, uuidStr)

	// Check if DomainStatus gone; update AppInstanceStatus if error
	ds := lookupDomainStatus(ctx, uuidStr)
	if ds != nil {
		if status.DomainName != ds.DomainName {
			status.DomainName = ds.DomainName
			changed = true
		}
		if status.BootTime != ds.BootTime {
			status.BootTime = ds.BootTime
			changed = true
		}
		log.Infof("Waiting for DomainStatus removal for %s\n", uuidStr)
		// Look for xen errors.
		if !ds.Activated {
			if ds.LastErr != "" {
				log.Errorf("Received error from domainmgr for %s: %s\n",
					uuidStr, ds.LastErr)
				status.Error = ds.LastErr
				status.ErrorSource = pubsub.TypeToName(types.DomainStatus{})
				status.ErrorTime = ds.LastErrTime
				changed = true
			} else if status.ErrorSource == pubsub.TypeToName(types.DomainStatus{}) {
				log.Infof("Clearing domainmgr error %s\n",
					status.Error)
				status.Error = ""
				status.ErrorSource = ""
				status.ErrorTime = time.Time{}
				changed = true
			}
		}
		return changed, done
	}

	log.Infof("Done with DomainStatus removal for %s\n", uuidStr)

	uninstall := (status.PurgeInprogress != types.BRING_DOWN)
	if uninstall {
		unpublishAppNetworkConfig(ctx, uuidStr)
	} else {
		m := lookupAppNetworkConfig(ctx, status.Key())
		if m != nil {
			log.Infof("doInactivate: Clearing Activate for AppNetworkConfig for %s\n",
				uuidStr)
			m.Activate = false
			publishAppNetworkConfig(ctx, m)
		} else {
			log.Warnf("doInactivte: No AppNetworkConfig for %s\n",
				uuidStr)
		}
	}
	// Check if AppNetworkStatus gone or !Activated
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns != nil && (uninstall || ns.Activated) {
		if uninstall {
			log.Infof("Waiting for AppNetworkStatus removal for %s\n",
				uuidStr)
		} else {
			log.Infof("Waiting for AppNetworkStatus !Activated for %s\n",
				uuidStr)
		}
		if ns.Error != "" {
			log.Errorf("Received error from zedrouter for %s: %s\n",
				uuidStr, ns.Error)
			status.Error = ns.Error
			status.ErrorSource = pubsub.TypeToName(types.AppNetworkStatus{})
			status.ErrorTime = ns.ErrorTime
			changed = true
		} else if status.ErrorSource == pubsub.TypeToName(types.AppNetworkStatus{}) {
			log.Infof("Clearing zedrouter error %s\n", status.Error)
			status.Error = ""
			status.ErrorSource = ""
			status.ErrorTime = time.Time{}
			changed = true
		}
		return changed, done
	}
	log.Debugf("Done with AppNetworkStatus removal for %s\n", uuidStr)
	done = true
	status.Activated = false
	status.ActivateInprogress = false
	log.Infof("doInactivate done for %s\n", uuidStr)
	return changed, done
}

func doUnprepare(ctx *zedmanagerContext, uuidStr string,
	status *types.AppInstanceStatus) bool {

	log.Infof("doUnprepare for %s\n", uuidStr)
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
			log.Infof("lookupEIDStatus not gone on remove for %s\n",
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
		log.Infof("Waiting for all EID frees for %s\n", uuidStr)
		return changed
	}
	log.Debugf("Done with EID frees for %s\n", uuidStr)

	log.Infof("doUnprepare done for %s\n", uuidStr)
	return changed
}

func doUninstall(ctx *zedmanagerContext, uuidStr string,
	status *types.AppInstanceStatus) (bool, bool) {

	log.Infof("doUninstall for %s\n", uuidStr)
	changed := false
	del := false

	for i := range status.StorageStatusList {
		ss := &status.StorageStatusList[i]
		c := MaybeRemoveStorageStatus(ctx, ss)
		if c {
			changed = true
		}
	}
	log.Debugf("Done with all verify and downloader removes for %s\n", uuidStr)

	del = true
	log.Infof("doUninstall done for %s\n", uuidStr)
	return changed, del
}

// Handle Activate=false which is different than doInactivate
// Keep DomainConfig around so the vdisks stay around
// Keep AppInstanceConfig around and with Activate set.
func doInactivateHalt(ctx *zedmanagerContext, uuidStr string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) bool {

	log.Infof("doInactivateHalt for %s\n", uuidStr)
	changed := false

	// Check AppNetworkStatus
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns == nil {
		log.Infof("Waiting for AppNetworkStatus for %s\n", uuidStr)
		return changed
	}
	updateAppNetworkStatus(status, ns)
	if ns.Pending() {
		log.Infof("Waiting for AppNetworkStatus !Pending for %s\n", uuidStr)
		return changed
	}
	// XXX should we make it not Activated?
	if ns.Error != "" {
		log.Errorf("Received error from zedrouter for %s: %s\n",
			uuidStr, ns.Error)
		status.Error = ns.Error
		status.ErrorSource = pubsub.TypeToName(types.AppNetworkStatus{})
		status.ErrorTime = ns.ErrorTime
		changed = true
		return changed
	} else if status.ErrorSource == pubsub.TypeToName(types.AppNetworkStatus{}) {
		log.Infof("Clearing zedrouter error %s\n", status.Error)
		status.Error = ""
		status.ErrorSource = ""
		status.ErrorTime = time.Time{}
		changed = true
	}
	log.Debugf("Done with AppNetworkStatus for %s\n", uuidStr)

	// Make sure we have a DomainConfig. Clears dc.Activate based
	// on the AppInstanceConfig's Activate
	err := MaybeAddDomainConfig(ctx, config, *status, ns)
	if err != nil {
		log.Errorf("Error from MaybeAddDomainConfig for %s: %s\n",
			uuidStr, err)
		status.Error = fmt.Sprintf("%s", err)
		status.ErrorTime = time.Now()
		changed = true
		log.Infof("Waiting for DomainStatus Activated for %s\n",
			uuidStr)
		return changed
	}

	// Check DomainStatus; update AppInstanceStatus if error
	ds := lookupDomainStatus(ctx, uuidStr)
	if ds == nil {
		log.Infof("Waiting for DomainStatus for %s\n", uuidStr)
		return changed
	}
	if status.DomainName != ds.DomainName {
		status.DomainName = ds.DomainName
		changed = true
	}
	if status.BootTime != ds.BootTime {
		status.BootTime = ds.BootTime
		changed = true
	}
	if ds.State != status.State {
		switch status.State {
		case types.RESTARTING, types.PURGING:
			// Leave unchanged
		default:
			log.Infof("Set State from DomainStatus from %d to %d\n",
				status.State, ds.State)
			status.State = ds.State
			changed = true
		}
	}
	// Ignore errors during a halt
	if ds.LastErr != "" {
		log.Warnf("doInactivateHalt sees error from domainmgr for %s: %s\n",
			uuidStr, ds.LastErr)
	}
	if status.ErrorSource == pubsub.TypeToName(types.DomainStatus{}) {
		log.Infof("Clearing domainmgr error %s\n", status.Error)
		status.Error = ""
		status.ErrorSource = ""
		status.ErrorTime = time.Time{}
		changed = true
	}
	// XXX compare with equal before setting changed?
	status.IoAdapterList = ds.IoAdapterList
	changed = true
	if ds.Pending() {
		log.Infof("Waiting for DomainStatus !Pending for %s\n", uuidStr)
		return changed
	}
	if ds.Activated {
		log.Infof("Waiting for Not Activated for DomainStatus %s\n",
			uuidStr)
		return changed
	}
	// XXX network is still around! Need to call doInactivate in doRemove?
	// XXX fix assymetry?
	status.Activated = false
	status.ActivateInprogress = false
	changed = true
	log.Infof("doInactivateHalt done for %s\n", uuidStr)
	return changed
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}
