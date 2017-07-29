// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package main

import (
	"fmt"
	"github.com/zededa/go-provision/types"
	"log"
	"reflect"
	"strings"
	"time"
)

// Maps from UUID (key) to AIConfig and AIStatus
var AIC map[string]types.AppInstanceConfig
var AIS map[string]types.AppInstanceStatus

func initMaps() {
	if AIC == nil {
		fmt.Printf("create AIC map\n")
		AIC = make(map[string]types.AppInstanceConfig)
	}
	if AIS == nil {
		fmt.Printf("create AIS map\n")
		AIS = make(map[string]types.AppInstanceStatus)
	}
}

func addOrUpdateConfig(uuidStr string, config types.AppInstanceConfig) {
	log.Printf("addOrUpdateConfig for %s\n", uuidStr)

	initMaps()

	changed := false
	if m, ok := AIC[uuidStr]; ok {
		if reflect.DeepEqual(m, config) {
			fmt.Printf("AI config changed for %s\n", uuidStr)
			changed = true
		}
	} else {
		fmt.Printf("AI config add for %s\n", uuidStr)
		changed = true
	}
	if changed {
		AIC[uuidStr] = config
		updateAIStatusUUID(uuidStr)
	}
}

func addOrUpdateStatus(uuidStr string, status types.AppInstanceStatus) {
	log.Printf("addOrUpdateStatus for %s\n", uuidStr)

	initMaps()

	changed := false
	if m, ok := AIS[uuidStr]; ok {
		if reflect.DeepEqual(m, status) {
			fmt.Printf("AI status changed for %s\n", uuidStr)
			changed = true
		}
	} else {
		fmt.Printf("AI status add for %s\n", uuidStr)
		changed = true
	}
	if changed {
		AIS[uuidStr] = status
		statusFilename := fmt.Sprintf("%s/%s.json",
			zedmanagerStatusDirname, uuidStr)
		writeAppInstanceStatus(&status, statusFilename)
	}
}

// Find all the AIStatus which refer to this safename.
func updateAIStatusSafename(safename string) {
	log.Printf("updateAIStatusSafename for %s\n", safename)

	for _, config := range AIC {
		fmt.Printf("found AIC for UUID %s\n",
			config.UUIDandVersion.UUID)
		for _, sc := range config.StorageConfigList {
			safename2 := urlToSafename(sc.DownloadURL, sc.ImageSha256)
			fmt.Printf("Found StorageConfig URL %s safename %s\n",
				sc.DownloadURL, safename2)
			if safename == safename2 {
				updateAIStatusUUID(config.UUIDandVersion.UUID.String())
				break
			}
		}
	}
}

// Update the state for this AIS and generate config updates to
// the microservices
func updateAIStatusUUID(uuidStr string) {
	if config, ok := AIC[uuidStr]; ok {
		status, ok := AIS[uuidStr]
		if !ok {
			log.Printf("updateAIStatusUUID for %s: Missing AI Status\n",
				uuidStr)
			return
		}
		changed := doUpdate(uuidStr, config, &status)
		if changed {
			log.Printf("updateAIStatusUUID status change for %s\n",
				uuidStr)
			AIS[uuidStr] = status
			statusFilename := fmt.Sprintf("%s/%s.json",
				zedmanagerStatusDirname, uuidStr)
			writeAppInstanceStatus(&status, statusFilename)
		}
	} else {
		log.Printf("updateAIStatusUUID for %s: Missing AI Config\n",
				uuidStr)
// XXX		doDelete(uuidStr)
// XXX		delete(AIS, uuidStr)
	}
}

func doUpdate(uuidStr string, config types.AppInstanceConfig,
     status *types.AppInstanceStatus) bool {
	log.Printf("doUpdate for %s\n", uuidStr)

	minState := types.MAXSTATE
	allErrors := ""
	var errorTime time.Time
	changed := false

	// XXX add separate function to init?
	if status.StorageStatusList == nil {
		fmt.Printf("XXX allocating StorageStatus len %d for %s\n",
			len(config.StorageConfigList), uuidStr)
		status.StorageStatusList = make([]types.StorageStatus,
			len(config.StorageConfigList))
		for i, sc := range config.StorageConfigList {
			ss := &status.StorageStatusList[i]
			ss.DownloadURL = sc.DownloadURL
			ss.ImageSha256 = sc.ImageSha256
		}
		changed = true
	}
	if len(config.StorageConfigList) != len(status.StorageStatusList) {
		// XXX should be fatal?
		log.Printf("Mismatch in storageConfig vs. Status length: %d vs %d\n", 
			len(config.StorageConfigList),
			len(status.StorageStatusList))
		return changed
	}
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]	    
		if ss.DownloadURL != sc.DownloadURL ||
		   ss.ImageSha256 != sc.ImageSha256 {
			// XXX should be fatal?
			log.Printf("Mismatch in storageConfig vs. Status:\n\t%s\n\t%s\n\t%s\n\t%s\n\n", 
				sc.DownloadURL, ss.DownloadURL,
				sc.ImageSha256, ss.ImageSha256)
			return changed
		}
	}		

	// XXX add separate function to init?
	if status.EIDList == nil {
		fmt.Printf("XXX allocating EIDStatus len %d for %s\n",
			len(config.OverlayNetworkList), uuidStr)
		status.EIDList = make([]types.EIDStatusDetails,
			len(config.OverlayNetworkList))
		changed = true
	}
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]	    
		safename := urlToSafename(sc.DownloadURL, sc.ImageSha256)
		fmt.Printf("Found StorageConfig URL %s safename %s\n",
			sc.DownloadURL, safename)
		
		// XXX shortcut if image is already verified
		// Doesn't get checked until after download. Order of reading
		// files?
		vs, err := LookupVerifyImageStatus(safename)
		if err == nil && vs.State == types.DELIVERED {
			log.Printf("XXX doUpdate found verified image for %s\n",
				safename)
			// XXX don't we need to have a refcnt? But against
			// the verified image somehow?
			if minState > vs.State {
				minState = vs.State
			}
			if vs.State != ss.State {
				ss.State = vs.State
				changed = true
			}
			continue
		}
		ds, err := LookupDownloaderStatus(safename)
		if err != nil {
			log.Printf("LookupDownloaderStatus %s failed %v\n",
				safename, err)
			continue
		}
		if minState > ds.State {
			minState = ds.State
		}
		if ds.State != ss.State {
			ss.State = ds.State
			changed = true
		}
		switch ds.State {
		case types.INITIAL:
			log.Printf("Received error from downloader for %s: %s\n",
				safename, ds.LastErr)
			ss.Error = ds.LastErr
			allErrors = appendError(allErrors, "downloader",
				ds.LastErr)
			ss.ErrorTime = ds.LastErrTime
			errorTime = ds.LastErrTime
			changed = true
		case types.DOWNLOAD_STARTED:
			// Nothing to do
		case types.DOWNLOADED:
			// Kick verifier to start if it hasn't already
			MaybeAddVerifyImageConfig(safename, &sc)
		}
	}
	if minState == types.MAXSTATE {
		// Odd; no StorageConfig in list
		minState = types.DOWNLOADED
	}
	status.State = minState
	status.Error = allErrors
	status.ErrorTime = errorTime
	if minState == types.INITIAL {
		log.Printf("Download error for %s\n", uuidStr)
		return changed
	}
	
	if minState < types.DOWNLOADED {
		log.Printf("Waiting for all downloads for %s\n", uuidStr)
		return changed
	}
	log.Printf("Done with downloads for %s\n", uuidStr)
	minState = types.MAXSTATE
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]	    
		safename := urlToSafename(sc.DownloadURL, sc.ImageSha256)
		fmt.Printf("Found StorageConfig URL %s safename %s\n",
			sc.DownloadURL, safename)
		
		vs, err := LookupVerifyImageStatus(safename)
		if err != nil {
			log.Printf("LookupVerifyImageStatus %s failed %v\n",
				safename, err)
			continue
		}
		if minState > vs.State {
			minState = vs.State
		}
		if vs.State != ss.State {
			ss.State = vs.State
			changed = true
		}
		switch vs.State {
		case types.INITIAL:
			log.Printf("Received error from verifier for %s: %s\n",
				safename, vs.LastErr)
			ss.Error = vs.LastErr
			allErrors = appendError(allErrors, "verifier",
				vs.LastErr)
			ss.ErrorTime = vs.LastErrTime
			errorTime = vs.LastErrTime
			changed = true
		}
	}
	if minState == types.MAXSTATE {
		// Odd; no StorageConfig in list
		minState = types.DELIVERED
	}
	status.State = minState
	status.Error = allErrors
	status.ErrorTime = errorTime
	if minState == types.INITIAL {
		log.Printf("Verify error for %s\n", uuidStr)
		return changed
	}
	
	if minState < types.DELIVERED {
		log.Printf("Waiting for all verifications for %s\n", uuidStr)
		return changed
	}
	log.Printf("Done with verifications for %s\n", uuidStr)
	// Make sure we have an EIDConfig for each overlay
	for _, ec := range config.OverlayNetworkList {
		MaybeAddEIDConfig(config.UUIDandVersion,
			config.DisplayName, &ec)
	}
	// Check EIDStatus for each overlay; update AI status
	eidsAllocated := true
	for i, ec := range config.OverlayNetworkList {
		key := fmt.Sprintf("%s:%d",
			config.UUIDandVersion.UUID.String(), ec.IID)
		es, err := LookupEIDStatus(config.UUIDandVersion, ec.IID)
		if err != nil {
			log.Printf("LookupEIDStatus %s failed %s\n",
				key, err)
			eidsAllocated = false
			continue
		}
		status.EIDList[i] = es.EIDStatusDetails
		if status.EIDList[i].EID == nil {
			log.Printf("Missing EID for %s\n", key)
			eidsAllocated = false
		} else {
			log.Printf("Found EID %v for %s\n",
				status.EIDList[i].EID, key)
			changed = true
		}
	}
	if !eidsAllocated {
		log.Printf("Waiting for all EID allocations for %s\n", uuidStr)
		return changed
	}
	log.Printf("Done with EID allocations for %s\n", uuidStr)

	// XXX would like to make a unique copy of !ReadOnly filesystems
	// before the VM is activated. Here? In xenmgr? In a storagemgr?

	// Defer networking and Xen setup until activated
	if !config.Activate {
		if status.Activated {
			status.Activated = false
			changed = true
		}
		log.Printf("Waiting for config.Activate for %s\n", uuidStr)
		return changed
	}
	log.Printf("Have config.Activate for %s\n", uuidStr)
	// Make sure we have an AppNetworkConfig
	MaybeAddAppNetworkConfig(config, status)

	// Check AppNetworkStatus
	ns, err := LookupAppNetworkStatus(uuidStr)
	if err != nil {
		log.Printf("Waiting for AppNetworkStatus for %s\n", uuidStr)
		return changed
	}
	log.Printf("Done with AppNetworkStatus for %s\n", uuidStr)

	// Make sure we have a DomainConfig
	MaybeAddDomainConfig(config, ns)

	// Check DomainStatus; update AI status if error
	ds, err := LookupDomainStatus(uuidStr)
	if err != nil {
		log.Printf("Waiting for DomainStatus for %s\n", uuidStr)
		return changed
	}
	// Look for xen errors.
	if !ds.Activated {
		if ds.LastErr != "" {
			log.Printf("Received error from xenmgr for %s: %s\n",
				uuidStr, ds.LastErr)
			status.Error = ds.LastErr
			status.ErrorTime = ds.LastErrTime
			changed = true
		}
		log.Printf("Waiting for DomainStatus Activated for %s\n",
			uuidStr)
		return changed
	}

	log.Printf("Done with DomainStatus for %s\n", uuidStr)

	if !status.Activated {
		status.Activated = true
		changed = true
	}
	log.Printf("doUpdate done for %s\n", uuidStr)
	return changed
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}

func doDelete(uuidStr string) {
	log.Printf("doDelete for %s\n", uuidStr)
	// XXX TBD do work
	log.Printf("doDelete done for %s\n", uuidStr)
}

func urlToSafename(url string, sha string) string {
	safename := strings.Replace(url, "/", "_", -1) + "." + sha
	return safename
}

