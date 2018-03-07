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

			log.Printf("baseOsStatusUpdateSafename for %s, %s\n", safename, safename1)

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
			log.Printf("addOrUpdateBaseOsConfig(%v) for %s, Config change\n",
				config.BaseOsVersion, uuidStr)
			changed = true
		} else {
			log.Printf("addOrUpdateBaseOsConfig(%v) for %s, No change\n",
				config.BaseOsVersion, uuidStr)
		}
	} else {
		log.Printf("addOrUpdateBaseOsConfig(%v) for %s, Config add\n",
			config.BaseOsVersion, uuidStr)
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

		// PartitionLabel can be empty here!
		if status.PartitionLabel != "" {
			status.Activated = getActivationStatus(config, &status)
		}

		baseOsStatusMap[uuidStr] = status
		writeBaseOsStatus(&status, uuidStr)
	}

	if changed {
		baseOsHandleStatusUpdate(uuidStr)
	}
}

func baseOsGetImageSha(config types.BaseOsConfig) string {
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
func getActivationStatus(config types.BaseOsConfig, status *types.BaseOsStatus) bool {

	log.Printf("getActivationStatus(%s): partitionLabel %s\n",
		status.BaseOsVersion, status.PartitionLabel)

	uuidStr := status.UUIDandVersion.UUID.String()
	imageSha256 := baseOsGetImageSha(config)
	partInfo := getPersistentPartitionInfo(uuidStr, imageSha256)

	if partInfo == nil {
		// only for other partition
		if !isOtherPartition(config.PartitionLabel) {
			return false
		}

		log.Printf("getActivationStatus(%s): missing partitionMap %s\n",
			status.BaseOsVersion, status.PartitionLabel)
		uuidStr := config.UUIDandVersion.UUID.String()
		ret := setPersistentPartitionInfo(uuidStr, config, status)
		if ret != nil {
			errStr := fmt.Sprintf("%v for %s\n", ret, uuidStr)
			status.Error = errStr
			status.ErrorTime = time.Now()
			log.Printf("getActivationStatus: %s\n", errStr)
			return false
		}
		partInfo = getPersistentPartitionInfo(uuidStr, imageSha256)
		if partInfo == nil {
			errStr := fmt.Sprintf("%s, inconsistent partitionLabel %s\n",
				status.BaseOsVersion, status.PartitionLabel)
			status.Error = errStr
			status.ErrorTime = time.Now()
			log.Printf("getActivationStatus: %s\n", errStr)
			return false
		}
	}

	log.Printf("getActivationStatus(%s): state %v\n", uuidStr, partInfo.State)

	// replicate state information
	if partInfo.State == types.INSTALLED {
		status.State = partInfo.State
		for idx, _ := range status.StorageStatusList {
			ss := &status.StorageStatusList[idx]
			ss.State = partInfo.State
		}
	}

	// replicate Error Info
	if !partInfo.ErrorTime.IsZero() {
		status.Error = partInfo.Error
		status.ErrorTime = partInfo.ErrorTime
	}

	log.Printf("getActivationStatus(%s): %v\n", uuidStr, status)
	// for otherPartition, its always false
	if !isCurrentPartition(status.PartitionLabel) {
		return false
	}
	// if current Partition, get the status from zboot
	return isCurrentPartitionStateActive()
}

func baseOsHandleStatusUpdate(uuidStr string) {

	config := baseOsConfigGet(uuidStr)
	if config == nil {
		log.Printf("baseOsHandleStatusUpdate for %s, Config absent\n", uuidStr)
		return
	}

	status := baseOsStatusGet(uuidStr)
	if status == nil {
		log.Printf("baseOsHandleStatusUpdate for %s, Status absent\n", uuidStr)
		return
	}

	changed := doBaseOsStatusUpdate(uuidStr, *config, status)

	if changed {
		log.Printf("baseOsHandleStatusUpdate(%s) for %s, Status changed\n",
			config.BaseOsVersion, uuidStr)
		baseOsStatusMap[uuidStr] = *status
		writeBaseOsStatus(status, uuidStr)
	}
}

func doBaseOsStatusUpdate(uuidStr string, config types.BaseOsConfig,
	status *types.BaseOsStatus) bool {

	log.Printf("doBaseOsStatusUpdate(%s) for %s\n",
		config.BaseOsVersion, uuidStr)

	changed, proceed := doBaseOsInstall(uuidStr, config, status)
	if !proceed {
		return changed
	}

	if config.Activate == false {
		log.Printf("doBaseOsStatusUpdate(%s) for %s, Activate is not set\n",
			config.BaseOsVersion, uuidStr)
		changed = doBaseOsInactivate(uuidStr, config, status)
		return changed
	}

	if status.Activated == true {
		log.Printf("doBaseOsStatusUpdate(%s) for %s, is already activated\n",
			config.BaseOsVersion, uuidStr)
		return false
	}

	changed = doBaseOsActivate(uuidStr, config, status)
	log.Printf("doBaseOsStatusUpdate(%s) done for %s\n",
		config.BaseOsVersion, uuidStr)
	return changed
}

func doBaseOsActivate(uuidStr string, config types.BaseOsConfig,
	status *types.BaseOsStatus) bool {
	log.Printf("doBaseOsActivate(%s) uuid %s\n",
		config.BaseOsVersion, uuidStr)

	changed := false
	log.Printf("doBaseOsActivate(%s) for %s, partition %s\n",
		config.BaseOsVersion, uuidStr, config.PartitionLabel)

	if config.PartitionLabel == "" {
		log.Printf("doBaseOsActivate(%s) for %s, unassigned partition\n",
			config.BaseOsVersion, uuidStr)
		return changed
	}

	// check the partition label of the current root...
	// check PartitionLabel the one we got is really unused?
	// if partitionState unsed then change status to updating...

	if !isOtherPartition(config.PartitionLabel) ||
	   !isOtherPartitionStateUnused() {
		return changed
	}

	log.Printf("doBaseOsActivate: activating %\n", uuidStr)
	setOtherPartitionStateUpdating()

	// if it is installed, flip the activated status
	if status.State == types.INSTALLED ||
		status.Activated == false {
		status.Activated = true
		changed = true
		setPersistentPartitionInfo(uuidStr, config, status)
		startExecReboot()
	}

	return changed
}

func doBaseOsInstall(uuidStr string, config types.BaseOsConfig,
	status *types.BaseOsStatus) (bool, bool) {

	log.Printf("doBaseOsInstall(%s) for %s\n",
		config.BaseOsVersion, uuidStr)
	changed := false

	// XXX:FIXME, handle image add/delete through deactivate/activate
	if len(config.StorageConfigList) != len(status.StorageStatusList) {

		errString := fmt.Sprintf("doBaseOsInstall(%s) for %s, Storage length mismatch: %d vs %d\n",
			config.BaseOsVersion, uuidStr,
			len(config.StorageConfigList),
			len(status.StorageStatusList))

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
		log.Printf("doBaseOsInstall(%s) for %s, Still not downloaded\n",
			config.BaseOsVersion, uuidStr)
		return changed || downloadchange, false
	}

	// check for the verification status change
	verifychange, verified :=
		checkBaseOsVerificationStatus(uuidStr, config, status)

	if verified == false {
		log.Printf("doBaseOsInstall(%s) for %s, Still not verified\n",
			config.BaseOsVersion, uuidStr)
		return changed || verifychange, false
	}

	// install the objects at appropriate place
	if ret := installDownloadedObjects(baseOsObj, uuidStr, config.StorageConfigList,
		status.StorageStatusList); ret == true {
		// move the state from DELIVERED to INSTALLED
		status.State = types.INSTALLED
		setPersistentPartitionInfo(uuidStr, config, status)
		changed = true
	}

	writeBaseOsStatus(status, uuidStr)
	log.Printf("doBaseOsInstall(%s) for %s, Done %v\n",
		config.BaseOsVersion, uuidStr, changed)
	return changed, true
}

func checkBaseOsStorageDownloadStatus(uuidStr string,
	config types.BaseOsConfig,
	status *types.BaseOsStatus) (bool, bool) {

	ret := checkStorageDownloadStatus(baseOsObj, uuidStr,
			 config.StorageConfigList, status.StorageStatusList)

	status.State = ret.MinState
	status.Error = ret.AllErrors
	status.ErrorTime = ret.ErrorTime

	if ret.MinState == types.INITIAL {
		log.Printf("checkBaseOsStorageDownloadStatus(%s) for %s, Download error for %s\n",
			config.BaseOsVersion, uuidStr)
		return ret.Changed, false
	}

	if ret.MinState < types.DOWNLOADED {
		log.Printf("checkBaseOsStorageDownloadStatus(%s) for %s, Waiting for all downloads\n",
			config.BaseOsVersion, uuidStr)
		return ret.Changed, false
	}

	log.Printf("checkBaseOsStorageDownloadStatus(%s) for %s, Downloads done\n",
		config.BaseOsVersion, uuidStr)
	return ret.Changed, true
}

func checkBaseOsVerificationStatus(uuidStr string,
	config types.BaseOsConfig, status *types.BaseOsStatus) (bool, bool) {

	ret := checkStorageVerifierStatus(baseOsObj,
		uuidStr, config.StorageConfigList, status.StorageStatusList)

	status.State = ret.MinState
	status.Error = ret.AllErrors
	status.ErrorTime = ret.ErrorTime

	if ret.MinState == types.INITIAL {
		log.Printf("checkBaseOsVerificationStatus(%s) for %s, Verification error\n",
			config.BaseOsVersion, uuidStr)
		return ret.Changed, false
	}

	if ret.MinState < types.DELIVERED {
		log.Printf("checkBaseOsVerificationStatus(%s) for %s, Waiting for all verifications\n",
			config.BaseOsVersion, uuidStr)
		return ret.Changed, false
	}
	log.Printf("checkBaseOsVerificationStatus(%s) for %s, Verifications done\n",
		config.BaseOsVersion, uuidStr)
	return ret.Changed, true
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

	config := baseOsConfigGet(uuidStr)
	if config == nil {
		log.Printf("removeBaseOsStatus for %s, Config absent\n", uuidStr)
		return
	}

	status := baseOsStatusGet(uuidStr)
	if status == nil {
		log.Printf("removeBaseOsStatus for %s, Status absent\n", uuidStr)
		return
	}

	changed, del := doBaseOsRemove(uuidStr, *config, status)
	if changed {
		log.Printf("removeBaseOsStatus for %s, Status change\n", uuidStr)
		baseOsStatusMap[uuidStr] = *status
		writeBaseOsStatus(status, uuidStr)
	}

	if del {

		// Write out what we modified to BaseOsStatus aka delete
		statusFilename := fmt.Sprintf("%s/%s.json",
			zedagentBaseOsStatusDirname, uuidStr)
		if err := os.Remove(statusFilename); err != nil {
			log.Println(err)
		}
		delete(baseOsStatusMap, uuidStr)
		log.Printf("removeBaseOsStatus for %s, Done\n", uuidStr)
	}
}

func doBaseOsRemove(uuidStr string, config types.BaseOsConfig, status *types.BaseOsStatus) (bool, bool) {

	log.Printf("doBaseOsRemove(%s) for %s\n", status.BaseOsVersion, uuidStr)

	changed := false
	del := false

	if status.Activated {
		changed = doBaseOsInactivate(uuidStr, config, status)
	}

	if !status.Activated {
		changed, del = doBaseOsUninstall(uuidStr, status)
	}

	log.Printf("doBaseOsRemove(%s) for %s, Done\n",
		status.BaseOsVersion, uuidStr)
	return changed, del
}

func doBaseOsInactivate(uuidStr string, config types.BaseOsConfig,
		 status *types.BaseOsStatus) bool {
	log.Printf("doBaseOsInactivate(%s) for %s\n",
		status.BaseOsVersion, uuidStr)

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
	log.Printf("doBaseOsUninstall(%s) for %s\n",
		status.BaseOsVersion, uuidStr)

	del := false
	changed := false
	removedAll := true

	for i, _ := range status.StorageStatusList {

		ss := &status.StorageStatusList[i]

		// Decrease refcount if we had increased it
		if ss.HasVerifierRef {
			log.Printf("doBaseOsUninstall(%s) for %s, Found verifer status %s\n",
				status.BaseOsVersion, uuidStr, ss.ImageSha256)
			removeBaseOsVerifierConfig(ss.ImageSha256)
			ss.HasVerifierRef = false
			changed = true
		}

		_, err := lookupBaseOsVerificationStatusSha256(ss.ImageSha256)

		// XXX if additional refs it will not go away
		if false && err == nil {
			log.Printf("doBaseOsUninstall(%s) for %s, Verifier %s not yet gone\n",
				status.BaseOsVersion, uuidStr, ss.ImageSha256)
			removedAll = false
			continue
		}
	}

	if !removedAll {
		log.Printf("doBaseOsUninstall(%s) for %s, Waiting for verifier purge\n",
			status.BaseOsVersion, uuidStr)
		return changed, del
	}

	removedAll = true

	for i, _ := range status.StorageStatusList {

		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(ss.DownloadURL, ss.ImageSha256)
		log.Printf("doBaseOsUninstall(%s) for %s, Found Downloader status %s\n",
			status.BaseOsVersion, uuidStr, safename)

		// Decrease refcount if we had increased it
		if ss.HasDownloaderRef {
			removeBaseOsDownloaderConfig(safename)
			ss.HasDownloaderRef = false
			changed = true
		}

		_, err := lookupBaseOsDownloaderStatus(ss.ImageSha256)
		// XXX if additional refs it will not go away
		if false && err == nil {
			log.Printf("doBaseOsUninstall(%s) for %s, Download %s not yet gone\n",
				status.BaseOsVersion, uuidStr, safename)
			removedAll = false
			continue
		}
	}

	if !removedAll {
		log.Printf("doBaseOsUninstall(%s) for %s, Waiting for downloader purge\n",
			status.BaseOsVersion, uuidStr)
		return changed, del
	}

	// XXX:FIXME, fill up the details
	if status.State == types.INITIAL {
		del = false
	}
	status.State = types.INITIAL
	resetPersistentPartitionInfo(uuidStr)
	log.Printf("doBaseOsUninstall(%s) for %s, Done\n",
		status.BaseOsVersion, uuidStr)

	return changed, del
}

func installBaseOsObject(srcFilename string, dstFilename string) error {

	log.Printf("installBaseOsObject: %s to %s\n", srcFilename, dstFilename)

	if dstFilename == "" {
		log.Printf("installBaseOsObject: unssigned destination partition\n")
		err := errors.New("no destination partition")
		return err
	}

	err := zbootWriteToPartition(srcFilename, dstFilename)
	if err != nil {
		log.Printf("installBaseOsObject: write failed %s\n", err)
	}
	return err
}
