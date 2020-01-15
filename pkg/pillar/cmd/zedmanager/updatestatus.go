// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/uuidtonum"
	"github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/disk"
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
	for _, st := range items {
		status := st.(types.AppInstanceStatus)
		log.Debugf("updateAIStatusWithStorageSafename: Processing "+
			"AppInstanceConfig for UUID %s\n",
			status.UUIDandVersion.UUID)
		for ssIndx := range status.StorageStatusList {
			ssPtr := &status.StorageStatusList[ssIndx]
			safename2 := (*ssPtr).Safename()
			if safename == safename2 {
				log.Infof("Found StorageStatus URL %s safename %s\n",
					ssPtr.Name, safename)
				if updateContainerImageID {
					if ssPtr.ContainerImageID != containerImageID {
						log.Debugf("Update AIS containerImageID: %s\n",
							containerImageID)
						ssPtr.ContainerImageID = containerImageID
						publishAppInstanceStatus(ctx, &status)
					} else {
						log.Debugf("No change in ContainerId in Status. "+
							"ssPtr.ContainerImageID: %s, containerImageID: %s",
							ssPtr.ContainerImageID, containerImageID)
					}
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

// updateAIStatusWithImageSha
//  Update AI Sattus for all App Instances that use the specified image
func updateAIStatusWithImageSha(ctx *zedmanagerContext, sha string) {

	log.Infof("updateAIStatusWithImageSha for %s\n", sha)
	pub := ctx.pubAppInstanceStatus
	items := pub.GetAll()
	found := false
	for _, st := range items {
		status := st.(types.AppInstanceStatus)
		log.Debugf("Processing AppInstanceConfig for UUID %s\n",
			status.UUIDandVersion.UUID)
		for _, ss := range status.StorageStatusList {
			if sha == ss.ImageSha256 {
				log.Infof("Found StorageStatus URL %s sha %s\n",
					ss.Name, sha)
				updateAIStatusUUID(ctx, status.Key())
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		log.Warnf("updateAIStatusWithImageSha for %s not found\n", sha)
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
	changed := doUpdate(ctx, *config, status)
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
	changed, done := doRemove(ctx, status, uninstall)
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
		changed := doUpdate(ctx, *config, status)
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
	for _, st := range items {
		status := st.(types.AppInstanceStatus)
		log.Debugf("Processing AppInstanceStatus for UUID %s\n",
			status.UUIDandVersion.UUID)
		for _, ss := range status.StorageStatusList {
			safename2 := ss.Safename()
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
	for _, st := range items {
		status := st.(types.AppInstanceStatus)
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
		changed := doUpdate(ctx, *config, &status)
		if changed {
			log.Infof("updateOrRemove status change for %s\n",
				uuidStr)
			publishAppInstanceStatus(ctx, &status)
		}
	}
}

func checkDiskSize(ctxPtr *zedmanagerContext) error {

	var totalAppDiskSize uint64

	if ctxPtr.globalConfig.IgnoreDiskCheckForApps {
		log.Debugf("Ignoring diskchecks for Apps")
		return nil
	}

	appDiskSizeList := ""
	pub := ctxPtr.pubAppInstanceStatus
	items := pub.GetAll()
	for _, iterStatusJSON := range items {
		iterStatus := iterStatusJSON.(types.AppInstanceStatus)
		if iterStatus.State < types.INSTALLED {
			log.Debugf("App %s State %d < INSTALLED",
				iterStatus.UUIDandVersion, iterStatus.State)
			continue
		}
		appDiskSize, err := utils.GetDiskSizeForAppInstance(iterStatus)
		if err != nil {
			log.Errorf("checkDiskSize: err: %s", err.Error())
			return err
		}
		totalAppDiskSize += appDiskSize
		appDiskSizeList += fmt.Sprintf("AppUUID: %s (Size: %d),\n",
			iterStatus.UUIDandVersion.UUID.String(), appDiskSize)
	}
	deviceDiskUsage, err := disk.Usage(types.PersistDir)
	if err != nil {
		err := fmt.Errorf("Failed to get diskUsage for /persist. err: %s",
			err.Error())
		log.Errorf("checkDiskSize: err:%s", err.Error())
		return err
	}
	deviceDiskSize := deviceDiskUsage.Total
	diskReservedForDom0 := uint64(float64(deviceDiskSize) *
		(float64(ctxPtr.globalConfig.Dom0MinDiskUsagePercent) * 0.01))
	allowedDeviceDiskSizeForApps := deviceDiskSize - diskReservedForDom0
	if allowedDeviceDiskSizeForApps < totalAppDiskSize {
		err := fmt.Errorf("Disk space not available for app - "+
			"Total Device Disk Size: %+v\n"+
			"Disk Size Reserved For Dom0: %+v\n"+
			"Allowed Disk Size For Apps: %+v\n"+
			"Total Disk Size Used By Apps: %+v\n"+
			"App Disk Size List:\n%s",
			deviceDiskSize, diskReservedForDom0, allowedDeviceDiskSizeForApps,
			totalAppDiskSize, appDiskSizeList)
		log.Errorf("checkDiskSize: err:%s", err.Error())
		return err
	}
	return nil
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
	if status.PurgeInprogress == types.DOWNLOAD {
		log.Infof("PurgeInprogress(%s) download/verifications done\n",
			status.Key())
		status.PurgeInprogress = types.BRING_DOWN
		changed = true
		// Keep the verified images in place
		_, done := doRemove(ctx, status, false)
		if !done {
			log.Infof("PurgeInprogress(%s) waiting for removal\n",
				status.Key())
			return changed
		}
		log.Infof("PurgeInprogress(%s) bringing it up\n",
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

// doInstallProcessStorageEntriesWithVerifiedImage
//  Returns: (imageStatusPtr, vsPtr, storageStatusUpdate)
func doInstallProcessStorageEntriesWithVerifiedImage(
	ctx *zedmanagerContext,
	appInstUUID uuid.UUID,
	ssPtr *types.StorageStatus) (*types.ImageStatus,
	*types.VerifyImageStatus, bool) {

	changed := false
	safename := ssPtr.Safename()

	// Check if the image is already present in ImageStatus. If yes,
	// go ahead and use it.

	isPtr := lookupImageStatusForApp(ctx, appInstUUID, ssPtr.ImageSha256)
	if isPtr != nil {
		// DiskStatus found for he App.
		log.Debugf("Image Status found for app UUID: %s. ImageStatus: %+v",
			appInstUUID.String(), *isPtr)
		if ssPtr.State != types.DELIVERED {
			ssPtr.State = types.DELIVERED
			ssPtr.Progress = 100
			changed = true
		}
		return isPtr, nil, changed
	}
	// Check if image is already verified
	vs := lookupVerifyImageStatusAny(ctx, safename, ssPtr.ImageSha256)
	// Handle post-reboot verification in progress by allowing
	// types.DOWNLOADED. If the verification later fails we will
	// get a delete of the VerifyImageStatus and skip this
	if vs == nil {
		log.Debugf("Verifier status not found for %s sha %s",
			safename, ssPtr.ImageSha256)
		return nil, nil, false
	}
	if vs.Expired {
		log.Infof("Vs.Expired Set. Re-download image %s, sha %s",
			safename, ssPtr.ImageSha256)
		return nil, nil, false
	}
	switch vs.State {
	case types.DELIVERED:
		log.Infof("Found verified image for %s sha %s\n",
			safename, ssPtr.ImageSha256)

	case types.DOWNLOADED:
		log.Infof("Found downloaded/verified image for %s sha %s\n",
			safename, ssPtr.ImageSha256)
	default:
		log.Infof("vs.State (%d) not DELIVERED / DOWNLOADED. safename: %s"+
			" sha %s", vs.State, safename, ssPtr.ImageSha256)
		return nil, nil, false
	}
	if vs.Safename != safename {
		// If found based on sha256
		log.Infof("Found diff safename %s\n", vs.Safename)
	}
	if ssPtr.IsContainer {
		log.Debugf("Container. ssPtr.ContainerImageID: %s, "+
			"vs.IsContainer = %t, vs.ContainerImageID: %s\n",
			ssPtr.ContainerImageID, vs.IsContainer, vs.ContainerImageID)
		if len(ssPtr.ContainerImageID) == 0 {
			ssPtr.ContainerImageID = vs.ContainerImageID
			changed = true
		}
	}
	if vs.State != ssPtr.State {
		ssPtr.State = vs.State
		ssPtr.Progress = 100
		changed = true
	}

	// If we don't already have a RefCount add one
	if !ssPtr.HasVerifierRef {
		log.Infof("!HasVerifierRef")
		// We don't need certs since Status already exists
		MaybeAddVerifyImageConfig(ctx, appInstUUID.String(), *ssPtr, false)
		ssPtr.HasVerifierRef = true
		changed = true
	}
	log.Debugf("Verifier Status Exists for StorageEntry: Name: %s, "+
		"ImageID: %s,  vs.RefCount: %d, ssPtr.State: %d",
		ssPtr.Name, ssPtr.ImageID, vs.RefCount, ssPtr.State)
	return isPtr, vs, changed
}

func doInstall(ctx *zedmanagerContext,
	config types.AppInstanceConfig,
	status *types.AppInstanceStatus) (bool, bool) {

	uuidStr := status.Key()

	log.Infof("doInstall: UUID: %s\n", uuidStr)
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
			status.SetError(errString, "Invalid PurgeInProgress", time.Now())
			return true, false
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
				status.ClearError()
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
			log.Infof("Waiting for bad StorageStatus to go away for AppInst %s",
				status.Key())
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
			errString := fmt.Sprintf("New storageConfig (Name: %s, "+
				"ImageSha256: %s, ImageID: %s) found. New Storage configs are "+
				"not allowed unless purged",
				sc.Name, sc.ImageSha256, sc.ImageID)
			log.Errorln(errString)
			status.Error = errString
			status.ErrorTime = time.Now()
			return true, false
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
		safename := ss.Safename()
		log.Infof("StorageStatus Name: %s, safename %s, ImageSha256: %s",
			ss.Name, safename, ss.ImageSha256)

		// Check if VerifierStatus already exists.
		isPtr, vs, statusUpdated := doInstallProcessStorageEntriesWithVerifiedImage(
			ctx, status.UUIDandVersion.UUID, ss)
		changed = changed || statusUpdated
		if isPtr != nil {
			log.Debugf("doInstall: Installed image exists. StorageStatus "+
				"Name: %s, safename %s, ImageSha256: %s",
				ss.Name, safename, ss.ImageSha256)
			// Image with imageStatus is in INSTALLED state
			if minState > types.INSTALLED {
				minState = types.INSTALLED
			}
			continue
		}
		if vs != nil {
			log.Debugf("doInstall: Verified image exists. StorageStatus "+
				"Name: %s, safename %s, ImageSha256: %s",
				ss.Name, safename, ss.ImageSha256)
			if minState > vs.State {
				minState = vs.State
			}
			continue
		}
		if !ss.HasDownloaderRef {
			log.Infof("doInstall !HasDownloaderRef for %s\n",
				safename)
			AddOrRefcountDownloaderConfig(ctx, safename, *ss)
			ss.HasDownloaderRef = true
			changed = true
		}
		ds := lookupDownloaderStatus(ctx, safename)
		if ds == nil || ds.Expired {
			if ds == nil {
				log.Infof("downloadStatus not found. name: %s", safename)
			} else {
				log.Infof("downloadStatusExpired set. name: %s", safename)
			}
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
				ret, errInfo := MaybeAddVerifyImageConfig(ctx, uuidStr,
					*ss, true)
				if ret {
					ss.HasVerifierRef = true
					changed = true
				} else {
					// if errors, set the certError flag
					// otherwise, mark as waiting for certs
					if errInfo.Error != "" {
						ss.SetErrorInfo(errInfo)
						errorSource = ss.ErrorSource
						allErrors = appendError(allErrors, "baseosmgr", ss.Error)
						errorTime = ss.ErrorTime
						changed = true
					} else {
						if !waitingForCerts {
							changed = true
							waitingForCerts = true
						}
					}
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
		safename := ss.Safename()
		log.Infof("Found StorageStatus URL %s safename %s\n",
			ss.Name, safename)

		isPtr := lookupImageStatusForApp(ctx, config.UUIDandVersion.UUID,
			ss.ImageSha256)
		if isPtr != nil {
			ss.ActiveFileLocation = types.VerifiedAppImgDirname + "/" + safename
			log.Infof("Update SSL ActiveFileLocation for %s: %s\n",
				uuidStr, ss.ActiveFileLocation)
			changed = true
		} else {
			vs := lookupVerifyImageStatusAny(ctx, safename, ss.ImageSha256)
			if vs == nil || vs.Expired {
				log.Infof("VerifyImageStatus for %s sha %s not found (%v)\n",
					safename, ss.ImageSha256, vs)
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
				log.Infof("lookupVerifyImageStatusAny %s Pending\n", safename)
				continue
			}
			if vs.LastErr != "" {
				log.Errorf("Received error from verifier for %s: %s\n",
					safename, vs.LastErr)
				ss.Error = vs.LastErr
				ss.ErrorSource = pubsub.TypeToName(types.VerifyImageStatus{})
				errorSource = ss.ErrorSource
				allErrors = appendError(allErrors, "verifier", vs.LastErr)
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
				ss.ActiveFileLocation = types.VerifiedAppImgDirname + "/" + vs.Safename
				log.Infof("Update SSL ActiveFileLocation for %s: %s\n",
					uuidStr, ss.ActiveFileLocation)
				changed = true
			}
		}
		log.Debugf("doInstall: StorageStatus ImageID:%s, Safename: %s, "+
			"minState:%d", ss.ImageID, ss.Name, minState)
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
	log.Debugf("doInstall: uuidStr: %s, minState:%d", uuidStr, minState)

	status.Error = allErrors
	status.ErrorSource = errorSource
	status.ErrorTime = errorTime
	if allErrors != "" {
		log.Errorf("Verify error for %s: %s\n", uuidStr, allErrors)
		return changed, false
	}

	if minState < types.DELIVERED {
		log.Infof("doInstall: Waiting for all verifications for %s. "+
			"minState: %d", uuidStr, minState)
		return changed, false
	}
	log.Infof("Done with verifications for %s\n", uuidStr)
	log.Infof("doInstall done for %s\n", uuidStr)
	return changed, true
}

func doPrepare(ctx *zedmanagerContext,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) (bool, bool) {

	uuidStr := status.Key()
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

// doActivate - Returns if the status has changed. Doesn't publish any changes.
// It is caller's responsibility to publish.
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

	// Check
	err := checkDiskSize(ctx)
	if err != nil {
		log.Errorf("doActivate: checkDiskSize Failed. err: %s", err)
		status.SetError(err.Error(), "CheckDiskSize", time.Now())
		return true
	}

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
		status.SetError(ns.Error, pubsub.TypeToName(types.AppNetworkStatus{}),
			ns.ErrorTime)
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
		status.ClearError()
		changed = true
	}
	log.Debugf("Done with AppNetworkStatus for %s\n", uuidStr)

	// Make sure we have a DomainConfig
	err = MaybeAddDomainConfig(ctx, config, *status, ns)
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

	log.Infof("MaybeRemoveStorageStatus: removing StorageStatus for:"+
		"Name: %s, ImageSha256: %s, HasDownloaderRef: %t, HasVerifierRef: %t,"+
		"IsContainer: %t, ContainerImageID: %s, Error: %s",
		ss.Name, ss.ImageSha256, ss.HasDownloaderRef, ss.HasVerifierRef,
		ss.IsContainer, ss.ContainerImageID, ss.Error)

	// Decrease refcount if we had increased it
	if ss.HasVerifierRef {
		MaybeRemoveVerifyImageConfigSha256(ctx, ss.ImageSha256)
		ss.HasVerifierRef = false
		changed = true
	}
	// Decrease refcount if we had increased it
	if ss.HasDownloaderRef {
		safename := ss.Safename()
		MaybeRemoveDownloaderConfig(ctx, safename)
		ss.HasDownloaderRef = false
		changed = true
	}
	return changed
}

func doRemove(ctx *zedmanagerContext,
	status *types.AppInstanceStatus, uninstall bool) (bool, bool) {

	uuidStr := status.Key()

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
func doInactivateHalt(ctx *zedmanagerContext,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) bool {

	uuidStr := status.Key()
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
