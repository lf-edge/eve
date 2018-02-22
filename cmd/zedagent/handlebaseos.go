// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// base os event handlers

package main

import (
	"errors"
	"fmt"
	"github.com/zededa/go-provision/types"
	"log"
	"os"
	"reflect"
	"time"
)

// zedagent publishes these config/status files
// and also the consumer
var baseOsConfigMap map[string]types.BaseOsConfig
var baseOsStatusMap map[string]types.BaseOsStatus

func initBaseOsMaps() {

	if baseOsConfigMap == nil {
		log.Printf("create baseOsConfig map\n")
		baseOsConfigMap = make(map[string]types.BaseOsConfig)
	}

	if baseOsStatusMap == nil {
		log.Printf("create baseOsStatus map\n")
		baseOsStatusMap = make(map[string]types.BaseOsStatus)
	}
}

// the storage download/verification event handler
// through base of storage list
func baseOsHandleStatusUpdateSafename(safename string) {

	log.Printf("baseOsStatusUpdateSafename for %s\n", safename)

	for _, baseOsConfig := range baseOsConfigMap {

		for _, sc := range baseOsConfig.StorageConfigList {

			safename1 := types.UrlToSafename(sc.DownloadURL, sc.ImageSha256)

			// base os config contains the current image
			if safename == safename1 {

				uuidStr := baseOsConfig.UUIDandVersion.UUID.String()
				log.Printf("baseOsHandleStatusUpdateSafename for %s, Found baseOs %s\n", safename, uuidStr)

				// handle the change event for this base os config
				baseOsHandleStatusUpdate(uuidStr)
			}
		}
	}
}

func addOrUpdateBaseOsConfig(uuidStr string, config types.BaseOsConfig) {

	changed := false
	added := false

	if m, ok := baseOsConfigMap[uuidStr]; ok {
		// XXX or just compare version like elsewhere?
		if !reflect.DeepEqual(m, config) {
			log.Printf("addOrUpdateBaseOsConfig for %s, Config change\n", uuidStr)
			changed = true
		}
	} else {
		log.Printf("addOrUpdateBaseOsConfig for %s, Config add\n", uuidStr)
		added = true
		changed = true
	}
	if changed {
		baseOsConfigMap[uuidStr] = config
	}

	if added {

		status := types.BaseOsStatus{
			UUIDandVersion: config.UUIDandVersion,
			BaseOsVersion:  config.BaseOsVersion,
			ConfigSha256:   config.ConfigSha256,
			PartitionLabel: config.PartitionLabel,
		}

		// XXX PartitionLabel can be empty here!
		if status.PartitionLabel != "" {
			status.Activated = getActivationStatus(status)
		}

		status.StorageStatusList = make([]types.StorageStatus,
			len(config.StorageConfigList))

		for i, sc := range config.StorageConfigList {
			ss := &status.StorageStatusList[i]
			ss.DownloadURL = sc.DownloadURL
			ss.ImageSha256 = sc.ImageSha256
			ss.Target = sc.Target
			// XXX:FIXME hijacking the top level image sha
			if status.ConfigSha256 != "" {
				status.ConfigSha256 = sc.ImageSha256
			}
		}

		baseOsStatusMap[uuidStr] = status
		statusFilename := fmt.Sprintf("%s/%s.json",
			zedagentBaseOsStatusDirname, uuidStr)
		writeBaseOsStatus(&status, statusFilename)
	}

	if changed {
		baseOsHandleStatusUpdate(uuidStr)
	}
}

func getBaseOsImageSha(config types.BaseOsConfig) string {
	for _, sc := range config.StorageConfigList {
		return sc.ImageSha256
	}
	return ""
}

func baseOsConfigGet(uuidStr string) *types.BaseOsConfig {

	config, ok := baseOsConfigMap[uuidStr]
	if !ok {
		log.Printf("baseOsHandleConfigGet for %s, Config absent\n", uuidStr)
		return nil
	}
	return &config
}

func baseOsStatusGet(uuidStr string) *types.BaseOsStatus {

	status, ok := baseOsStatusMap[uuidStr]
	if !ok {
		log.Printf("baseOsStatusGet for %s, Status absent\n", uuidStr)
		return nil
	}
	return &status
}

// Check if the BaseOsStatus is the current partition and is active
func getActivationStatus(status types.BaseOsStatus) bool {

	log.Printf("getActivationStatus: partitionLabel %s\n",
		status.PartitionLabel)
	if !isCurrentPartition(status.PartitionLabel) {
		return false
	}
	return isCurrentPartitionStateActive()
}

func baseOsHandleStatusUpdate(uuidStr string) {

	config := baseOsConfigGet(uuidStr)
	if config == nil {
		return
	}

	status := baseOsStatusGet(uuidStr)
	if status == nil {
		return
	}

	changed := doBaseOsStatusUpdate(uuidStr, *config, status)

	if changed {
		log.Printf("baseOsHandleStatusUpdate for %s, Status changed\n", uuidStr)
		baseOsStatusMap[uuidStr] = *status
		statusFilename := fmt.Sprintf("%s/%s.json",
			zedagentBaseOsStatusDirname, uuidStr)
		writeBaseOsStatus(status, statusFilename)
	}
}

func doBaseOsStatusUpdate(uuidStr string, config types.BaseOsConfig,
	status *types.BaseOsStatus) bool {

	log.Printf("doBaseOsStatusUpdate for %s\n", uuidStr)

	changed, proceed := doBaseOsInstall(uuidStr, config, status)
	if !proceed {
		return changed
	}

	if config.Activate == false {
		log.Printf("doBaseOsStatusUpdate for %s, Activate is not set\n", uuidStr)
		changed = doBaseOsInactivate(uuidStr, status)
		return changed
	}

	setPersistentPartitionInfo(uuidStr, config)

	if status.Activated == true {
		log.Printf("doBaseOsStatusUpdate for %s, is already activated\n", uuidStr)
		return false
	}

	changed = doBaseOsActivate(uuidStr, config, status)
	log.Printf("doBaseOsStatusUpdate done for %s\n", uuidStr)
	return changed
}

func doBaseOsActivate(uuidStr string, config types.BaseOsConfig,
	status *types.BaseOsStatus) bool {

	changed := false
	log.Printf("doBaseOsActivate for %s, partition %s\n",
		uuidStr, config.PartitionLabel)

	if config.PartitionLabel == "" {
		// XXX we hit this
		log.Printf("doBaseOsActivate for %s, unassigned partition\n", uuidStr)
		return changed
	}

	// check the partition label of the current root...
	// check PartitionLabel the one we got is really unused?
	// if partitionState unsed then change status to updating...

	if !isOtherPartition(config.PartitionLabel) {
		return changed
	}
	if !isOtherPartitionUnused(config.PartitionLabel) {
		return changed
	}

	log.Printf("doBaseOsActivate: activating %\n", uuidStr)
	setOtherPartitionStateUpdating()

	// if it is installed, flip the activated status
	if status.State == types.INSTALLED ||
		status.Activated == false {
		status.Activated = true
		changed = true
		startExecReboot()
	}

	return changed
}

func doBaseOsInstall(uuidStr string, config types.BaseOsConfig,
	status *types.BaseOsStatus) (bool, bool) {

	log.Printf("doBaseOsInstall for %s\n", uuidStr)
	changed := false

	// XXX:FIXME, handle image add/delete through deactivate/activate
	if len(config.StorageConfigList) != len(status.StorageStatusList) {

		errString := fmt.Sprintf("doBaseOsInstall for %s, Storage length mismatch: %d vs %d\n", uuidStr,
			len(config.StorageConfigList), len(status.StorageStatusList))

		status.Error = errString
		status.ErrorTime = time.Now()
		return changed, false
	}

	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		if ss.DownloadURL != sc.DownloadURL ||
			ss.ImageSha256 != sc.ImageSha256 {
			// Report to zedcloud
			errString := fmt.Sprintf("doBaseOsInstall for %s, Storage config mismatch:\n\t%s\n\t%s\n\t%s\n\t%s\n\n", uuidStr,
				sc.DownloadURL, ss.DownloadURL,
				sc.ImageSha256, ss.ImageSha256)
			log.Println(errString)
			status.Error = errString
			status.ErrorTime = time.Now()
			changed = true
			return changed, false
		}
	}

	// check for the download status change
	downloadchange, downloaded :=
		checkBaseOsStorageDownloadStatus(uuidStr, config, status)

	if downloaded == false {
		log.Printf("doBaseOsInstall for %s, Still not downloaded\n", uuidStr)
		return changed || downloadchange, false
	}

	// check for the verification status change
	verifychange, verified :=
		checkBaseOsVerificationStatus(uuidStr, config, status)

	if verified == false {
		log.Printf("doBaseOsInstall for %s, Still not verified\n", uuidStr)
		return changed || verifychange, false
	}

	for _, sc := range config.StorageConfigList {
		sc.FinalObjDir = config.PartitionLabel
	}

	// install the objects at appropriate place
	if ret := installDownloadedObjects(baseOsObj, uuidStr, config.StorageConfigList,
		status.StorageStatusList); ret == true {
		// move the state from DELIVERED to INSTALLED
		status.State = types.INSTALLED
		changed = true
	}

	statusFilename := fmt.Sprintf("%s/%s.json",
		zedagentBaseOsStatusDirname, uuidStr)
	writeBaseOsStatus(status, statusFilename)
	log.Printf("doBaseOsInstall for %s, Done %v\n", uuidStr, changed)
	return changed, true
}

func checkBaseOsStorageDownloadStatus(uuidStr string,
	config types.BaseOsConfig,
	status *types.BaseOsStatus) (bool, bool) {

	changed, minState, allErrors, errorTime := checkStorageDownloadStatus(baseOsObj, uuidStr, config.StorageConfigList, status.StorageStatusList)

	status.State = minState
	status.Error = allErrors
	status.ErrorTime = errorTime

	if minState == types.INITIAL {
		log.Printf("checkBaseOsStorageDownloadStatus for %s, Download error for %s\n", uuidStr)
		return changed, false
	}

	if minState < types.DOWNLOADED {
		log.Printf("checkBaseOsStorageDownloadStatus for %s, Waiting for all downloads\n", uuidStr)
		return changed, false
	}

	log.Printf("checkBaseOsStorageDownloadStatus for %s, Downloads done\n", uuidStr)
	return changed, true
}

func checkBaseOsVerificationStatus(uuidStr string,
	config types.BaseOsConfig, status *types.BaseOsStatus) (bool, bool) {

	changed, minState, allErrors, errorTime := checkStorageVerifierStatus(baseOsObj,
		uuidStr, config.StorageConfigList, status.StorageStatusList)

	status.State = minState
	status.Error = allErrors
	status.ErrorTime = errorTime
	if minState == types.INITIAL {
		log.Printf("checkBaseOsVerificationStatus for %s, Verification error\n",
			uuidStr)
		return changed, false
	}

	if minState < types.DELIVERED {
		log.Printf("checkBaseOsVerificationStatus for %s, Waiting for all verifications\n", uuidStr)
		return changed, false
	}
	log.Printf("checkBaseOsVerificationStatus for %s, Verifications done\n", uuidStr)
	return changed, true
}

func removeBaseOsConfig(uuidStr string) {

	log.Printf("removeBaseOsConfig for %s\n", uuidStr)

	if _, ok := baseOsConfigMap[uuidStr]; !ok {
		log.Printf("removeBaseOsconfig for %s, Config absent\n", uuidStr)
		return
	}
	delete(baseOsConfigMap, uuidStr)
	removeBaseOsStatus(uuidStr)

	log.Printf("removeBaseOSConfig for %s, done\n", uuidStr)
}

func removeBaseOsStatus(uuidStr string) {

	status, ok := baseOsStatusMap[uuidStr]
	if !ok {
		log.Printf("removeBaseOsStatus for %s, Status absent\n", uuidStr)
		return
	}

	changed, del := doBaseOsRemove(uuidStr, &status)
	if changed {
		log.Printf("removeBaseOsStatus for %s, Status change\n", uuidStr)
		baseOsStatusMap[uuidStr] = status
		statusFilename := fmt.Sprintf("%s/%s.json",
			zedagentBaseOsStatusDirname, uuidStr)
		writeBaseOsStatus(&status, statusFilename)
	}

	if del {

		// Write out what we modified to AppInstanceStatus aka delete
		statusFilename := fmt.Sprintf("%s/%s.json",
			zedagentBaseOsStatusDirname, uuidStr)
		if err := os.Remove(statusFilename); err != nil {
			log.Println(err)
		}
		delete(baseOsStatusMap, uuidStr)
		log.Printf("removeBaseOsStatus for %s, Done\n", uuidStr)
	}
}

func doBaseOsRemove(uuidStr string, status *types.BaseOsStatus) (bool, bool) {

	log.Printf("doBaseOsRemove for %s\n", uuidStr)

	changed := false
	del := false

	if status.Activated {
		changed = doBaseOsInactivate(uuidStr, status)
	}

	if !status.Activated {
		changed, del = doBaseOsUninstall(uuidStr, status)
	}

	log.Printf("doBaseOsRemove for %s, Done\n", uuidStr)
	return changed, del
}

func doBaseOsInactivate(uuidStr string, status *types.BaseOsStatus) bool {

	changed := false

	// XXX:FIXME , flip the currently active baseOs
	// to backup and adjust the baseOS
	// state accordingly

	if status.Activated {
		status.Activated = false
		changed = true
	}

	return changed
}

func doBaseOsUninstall(uuidStr string, status *types.BaseOsStatus) (bool, bool) {

	del := false
	changed := false
	removedAll := true

	for i, _ := range status.StorageStatusList {

		ss := &status.StorageStatusList[i]

		// Decrease refcount if we had increased it
		if ss.HasVerifierRef {
			log.Printf("doBaseOsUninstall for %s, Found verifer status %s\n", uuidStr, ss.ImageSha256)
			removeBaseOsVerifierConfig(ss.ImageSha256)
			ss.HasVerifierRef = false
			changed = true
		}

		_, err := lookupBaseOsVerificationStatusSha256(ss.ImageSha256)

		// XXX if additional refs it will not go away
		if false && err == nil {
			log.Printf("doBaseOsUninstall for %s, Verifier %s not yet gone\n", uuidStr, ss.ImageSha256)
			removedAll = false
			continue
		}
	}

	if !removedAll {
		log.Printf("doBaseOsUninstall for %s, Waiting for verifier purge\n", uuidStr)
		return changed, del
	}

	removedAll = true

	for i, _ := range status.StorageStatusList {

		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(ss.DownloadURL, ss.ImageSha256)
		log.Printf("doBaseOsUninstall for %s, Found Downloader status %s\n", uuidStr, safename)

		// Decrease refcount if we had increased it
		if ss.HasDownloaderRef {
			removeBaseOsDownloaderConfig(safename)
			ss.HasDownloaderRef = false
			changed = true
		}

		_, err := lookupBaseOsDownloaderStatus(ss.ImageSha256)
		// XXX if additional refs it will not go away
		if false && err == nil {
			log.Printf("doBaseOsUninstall for %s, Download %s not yet gone\n", uuidStr, safename)
			removedAll = false
			continue
		}
	}

	if !removedAll {
		log.Printf("doBaseOsUninstall for %s, Waiting for downloader purge\n", uuidStr)
		return changed, del
	}

	// XXX:FIXME, fill up the details
	if status.State == types.INITIAL {
		del = false
	}
	status.State = types.INITIAL
	log.Printf("doBaseOsUninstall for %s, Done\n", uuidStr)

	return changed, del
}

func installBaseOsObject(srcFilename string, dstFilename string) error {

	log.Printf("installBaseOsObject: %s to %s\n", srcFilename, dstFilename)

	if dstFilename == "" {
		log.Printf("installBaseOsObject: unssigned destination partition\n")
		err := errors.New("no destination partition")
		return err
	}

	return zbootWriteToPartition(srcFilename, dstFilename)
}
