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
				log.Printf("%s, found baseOs %s\n", safename, uuidStr)

				// handle the change event for this base os config
				baseOsHandleStatusUpdate(uuidStr)
			}
		}
	}
}

func addOrUpdateBaseOsConfig(uuidStr string, config types.BaseOsConfig) {

	changed := false
	added := false

	if m := baseOsConfigGet(uuidStr); m != nil {
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
		baseOsConfigSet(uuidStr, &config)
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
		}

		baseOsGetActivationStatus(&status)
		baseOsStatusSet(uuidStr, &status)
		writeBaseOsStatus(&status, uuidStr)
	}

	if changed {
		baseOsHandleStatusUpdate(uuidStr)
	}
}

func baseOsConfigGet(uuidStr string) *types.BaseOsConfig {

	config, ok := baseOsConfigMap[uuidStr]
	if !ok {
		log.Printf("%s, baseOs config is absent\n", uuidStr)
		return nil
	}
	return &config
}

func baseOsConfigSet(uuidStr string, config *types.BaseOsConfig) {
	baseOsConfigMap[uuidStr] = *config
}

func baseOsConfigDelete(uuidStr string) bool {
	log.Printf("%s, baseOs config delete\n", uuidStr)
	if config := baseOsConfigGet(uuidStr); config != nil {
		delete(baseOsConfigMap, uuidStr)
		return true
	}
	return false
}
func baseOsStatusGet(uuidStr string) *types.BaseOsStatus {

	status, ok := baseOsStatusMap[uuidStr]
	if !ok {
		log.Printf("%s, baseOs status is absent\n", uuidStr)
		return nil
	}
	return &status
}

func baseOsStatusSet(uuidStr string, status *types.BaseOsStatus) {
	baseOsStatusMap[uuidStr] = *status
}

func baseOsStatusDelete(uuidStr string) bool {
	if status := baseOsStatusGet(uuidStr); status != nil {
		delete(baseOsStatusMap, uuidStr)
		return true
	}
	return false
}

func baseOsGetActivationStatus(status *types.BaseOsStatus) {

	log.Printf("baseOsGetActivationStatus(%s): partitionLabel %s\n",
		status.BaseOsVersion, status.PartitionLabel)

	// PartitionLabel can be empty here!
	if status.PartitionLabel == "" {
		status.Activated = false
		return
	}

	partName := status.PartitionLabel
	partVersion := GetShortVersion(partName)

	// if they match, mean already installed
	// mark the status accordingly
	if partVersion == status.BaseOsVersion {
		baseOsMarkInstalled(status)
	}

	// some partition specific attributes
	status.PartitionState = getPartitionState(partName)
	status.PartitionDevice = getPartitionDevname(partName)

	// for otherPartition, its always false
	if !isCurrentPartition(partName) {
		status.Activated = false
		return
	}
	// if current Partition, get the status from zboot
	status.Activated = isCurrentPartitionStateActive()
}

func baseOsMarkInstalled(status *types.BaseOsStatus) {

	if status.State != types.INSTALLED {
		log.Printf("%s, marking installed\n", status.BaseOsVersion)
		status.State = types.INSTALLED
		for idx, _ := range status.StorageStatusList {
			ss := &status.StorageStatusList[idx]
			ss.State = types.INSTALLED
		}
	}
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

	baseOsGetActivationStatus(status)

	changed := doBaseOsStatusUpdate(uuidStr, *config, status)

	if changed {
		log.Printf("baseOsHandleStatusUpdate(%s) for %s, Status changed\n",
			config.BaseOsVersion, uuidStr)
		baseOsStatusSet(uuidStr, status)
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

	log.Printf("doBaseOsActivate: %s activating\n", uuidStr)
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

	log.Printf("doBaseOsInstall(%s) for %s\n",
		config.BaseOsVersion, uuidStr)
	changed := false
	proceed := false

	// XXX:FIXME, handle image add/delete through deactivate/activate
	if len(config.StorageConfigList) != len(status.StorageStatusList) {

		errString := fmt.Sprintf("doBaseOsInstall(%s) for %s, Storage length mismatch: %d vs %d\n",
			config.BaseOsVersion, uuidStr,
			len(config.StorageConfigList),
			len(status.StorageStatusList))

		status.Error = errString
		status.ErrorTime = time.Now()
		return changed, proceed
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
			return changed, proceed
		}
	}

	// check for the download status change
	downloadchange, downloaded :=
		checkBaseOsStorageDownloadStatus(uuidStr, config, status)

	if downloaded == false {
		log.Printf("doBaseOsInstall(%s) for %s, Still not downloaded\n",
			config.BaseOsVersion, uuidStr)
		return changed || downloadchange, proceed
	}

	// check for the verification status change
	verifychange, verified :=
		checkBaseOsVerificationStatus(uuidStr, config, status)

	if verified == false {
		log.Printf("doBaseOsInstall(%s) for %s, Still not verified\n",
			config.BaseOsVersion, uuidStr)
		return changed || verifychange, proceed
	}

	// install the image at proper partition
	if ret := installDownloadedObjects(baseOsObj, uuidStr,
		config.StorageConfigList, status.StorageStatusList); ret == true {

		changed = true
		//match the version string
		if errString := checkInstalledVersion(config); errString != "" {
			status.State = types.INITIAL
			status.Error = errString
			status.ErrorTime = time.Now()
		} else {
			// move the state from DELIVERED to INSTALLED
			status.State = types.INSTALLED
			proceed = true
		}
	}

	writeBaseOsStatus(status, uuidStr)
	log.Printf("doBaseOsInstall(%s), Done %v\n",
		config.BaseOsVersion, proceed)
	return changed, proceed
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
	if ok := baseOsConfigDelete(uuidStr); ok {
		removeBaseOsStatus(uuidStr)
	}
	log.Printf("removeBaseOSConfig for %s, done\n", uuidStr)
}

func removeBaseOsStatus(uuidStr string) {

	config := baseOsConfigGet(uuidStr)
	if config == nil {
		return
	}

	status := baseOsStatusGet(uuidStr)
	if status == nil {
		return
	}

	changed, del := doBaseOsRemove(uuidStr, *config, status)
	if changed {
		log.Printf("removeBaseOsStatus for %s, Status change\n", uuidStr)
		baseOsStatusSet(uuidStr, status)
		writeBaseOsStatus(status, uuidStr)
	}

	if del {

		// Write out what we modified to BaseOsStatus aka delete
		// Remove the status file also
		if ok := baseOsStatusDelete(uuidStr); ok {
			statusFilename := fmt.Sprintf("%s/%s.json",
				zedagentBaseOsStatusDirname, uuidStr)
			if err := os.Remove(statusFilename); err != nil {
				log.Println(err)
			}
			log.Printf("%s, removeBaseOsStatus %s, Done\n", uuidStr)
		}
	}
}

func doBaseOsRemove(uuidStr string, config types.BaseOsConfig,
	status *types.BaseOsStatus) (bool, bool) {

	log.Printf("doBaseOsRemove(%s) for %s\n", status.BaseOsVersion, uuidStr)

	changed := false
	del := false

	changed = doBaseOsInactivate(uuidStr, config, status)

	changed, del = doBaseOsUninstall(uuidStr, status)

	log.Printf("doBaseOsRemove(%s) for %s, Done\n",
		status.BaseOsVersion, uuidStr)
	return changed, del
}

func doBaseOsInactivate(uuidStr string, config types.BaseOsConfig,
	status *types.BaseOsStatus) bool {
	log.Printf("doBaseOsInactivate(%s) %v\n",
		status.BaseOsVersion, status.Activated)

	// nothing to be done, flip will happen on reboot
	return true
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

	del = true
	log.Printf("doBaseOsUninstall(%s), Done\n", status.BaseOsVersion)
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

	// resetting the local cache
	resetOtherPartShortVersion()
	return err
}

// validate whether the image version matches with
// config version string
func checkInstalledVersion(config types.BaseOsConfig) string {

	log.Printf("check baseOs installation %s, %s, installation\n",
		config.PartitionLabel, config.BaseOsVersion)

	partVersion := GetShortVersion(config.PartitionLabel)
	if config.BaseOsVersion == partVersion {
		return ""
	}
	errStr := fmt.Sprintf("baseOs %s, %s, does not match installed %s",
		config.PartitionLabel, config.BaseOsVersion, partVersion)

	log.Println(errStr)
	return errStr
}
