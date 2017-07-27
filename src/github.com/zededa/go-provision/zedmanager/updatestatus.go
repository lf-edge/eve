// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package main

import (
	"fmt"
	"github.com/zededa/go-provision/types"
	"log"
	"reflect"
	"strings"
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
			statusFilename := fmt.Sprintf("%s/%s.json",
				zedmanagerStatusDirname, uuidStr)
			writeAppInstanceStatus(&status, statusFilename)
		}
	} else {
		doDelete(uuidStr)
	}
}

func doUpdate(uuidStr string, config types.AppInstanceConfig,
     status *types.AppInstanceStatus) bool {
	log.Printf("doUpdate for %s\n", uuidStr)

	minState := types.MAXSTATE
	allErrors := ""
	changed := false

	if status.StorageStatusList == nil {
		fmt.Printf("XXX allocating StorageStatus len %d\n",
			len(config.StorageConfigList))
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
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]	    
		safename := urlToSafename(sc.DownloadURL, sc.ImageSha256)
		fmt.Printf("Found StorageConfig URL %s safename %s\n",
			sc.DownloadURL, safename)
		
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
	if minState == types.INITIAL {
		log.Printf("Download error for %s\n", uuidStr)
		return changed
	}
	
	if minState != types.DOWNLOADED {
		log.Printf("Waiting for all downloads for %s\n", uuidStr)
		return changed
	}
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
			changed = true
		}
	}
	if minState == types.MAXSTATE {
		// Odd; no StorageConfig in list
		minState = types.DELIVERED
	}
	status.State = minState
	status.Error = allErrors
	if minState == types.INITIAL {
		log.Printf("Verify error for %s\n", uuidStr)
		return changed
	}
	
	if minState != types.DELIVERED {
		log.Printf("Waiting for all verifications for %s\n", uuidStr)
		return changed
	}
	// XXX eidconfig for each overlay
	// XXX check eidstatus for each overlay; update AI status
	// XXX Activate?
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

