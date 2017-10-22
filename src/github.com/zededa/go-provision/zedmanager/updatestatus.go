// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package main

import (
	"fmt"
	"github.com/zededa/go-provision/types"
	"log"
	"os"
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
	added := false
	if m, ok := AIC[uuidStr]; ok {
		// XXX or just compare version like elsewhere?
		if !reflect.DeepEqual(m, config) {
			fmt.Printf("AI config changed for %s\n", uuidStr)
			changed = true
			if m.UUIDandVersion.Version == config.UUIDandVersion.Version {
				fmt.Printf("XXX AI config changed for %s but same version %s\n", uuidStr, config.UUIDandVersion.Version)
			}
		}
	} else {
		fmt.Printf("AI config add for %s\n", uuidStr)
		changed = true
		added = true
	}
	if changed {
		AIC[uuidStr] = config
	}
	if added {
		if _, ok := AIS[uuidStr]; !ok {
			status := types.AppInstanceStatus{
				UUIDandVersion: config.UUIDandVersion,
				DisplayName:    config.DisplayName,
			}

			status.StorageStatusList = make([]types.StorageStatus,
				len(config.StorageConfigList))
			for i, sc := range config.StorageConfigList {
				ss := &status.StorageStatusList[i]
				ss.DownloadURL = sc.DownloadURL
				ss.ImageSha256 = sc.ImageSha256
			}
			status.EIDList = make([]types.EIDStatusDetails,
				len(config.OverlayNetworkList))

			AIS[uuidStr] = status
			statusFilename := fmt.Sprintf("%s/%s.json",
				zedmanagerStatusDirname, uuidStr)
			writeAppInstanceStatus(&status, statusFilename)
		}
	}

	if changed {
		updateAIStatusUUID(uuidStr)
	}
	log.Printf("addOrUpdateConfig done for %s\n", uuidStr)
}

func removeConfig(uuidStr string) {
	log.Printf("removeConfig for %s\n", uuidStr)

	if _, ok := AIC[uuidStr]; !ok {
		log.Printf("AI config missing for remove for %s\n", uuidStr)
		return
	}
	delete(AIC, uuidStr)
	removeAIStatusUUID(uuidStr)
	log.Printf("removeConfig done for %s\n", uuidStr)
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
	config, ok := AIC[uuidStr]
	if !ok {
		log.Printf("updateAIStatusUUID for %s: Missing AI Config\n",
			uuidStr)
		return
	}
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
		publishAiInfoToCloud(config, status)
	}
}

// remove the state for this AIS and generate config removes for
// the microservices
func removeAIStatusUUID(uuidStr string) {
	status, ok := AIS[uuidStr]
	if !ok {
		log.Printf("removeAIStatusUUID for %s: Missing AI Status\n",
			uuidStr)
		return
	}
	changed, del := doRemove(uuidStr, &status)
	if changed {
		log.Printf("removeAIStatusUUID status change for %s\n",
			uuidStr)
		AIS[uuidStr] = status
		statusFilename := fmt.Sprintf("%s/%s.json",
			zedmanagerStatusDirname, uuidStr)
		writeAppInstanceStatus(&status, statusFilename)
	}
	if del {
		log.Printf("removeAIStatusUUID remove done for %s\n",
			uuidStr)
		// Write out what we modified to AppInstanceStatus aka delete
		statusFilename := fmt.Sprintf("%s/%s.json",
			zedmanagerStatusDirname, uuidStr)
		if err := os.Remove(statusFilename); err != nil {
			log.Println(err)
		}
		delete(AIS, uuidStr)
	}
}

// Find all the AIStatus which refer to this safename.
func removeAIStatusSafename(safename string) {
	log.Printf("removeAIStatusSafename for %s\n", safename)

	for _, status := range AIS {
		fmt.Printf("found AIS for UUID %s\n",
			status.UUIDandVersion.UUID)
		for _, ss := range status.StorageStatusList {
			safename2 := urlToSafename(ss.DownloadURL, ss.ImageSha256)
			fmt.Printf("Found StorageStatus URL %s safename %s\n",
				ss.DownloadURL, safename2)
			if safename == safename2 {
				removeAIStatusUUID(status.UUIDandVersion.UUID.String())
				break
			}
		}
	}
}

func doUpdate(uuidStr string, config types.AppInstanceConfig,
	status *types.AppInstanceStatus) bool {
	log.Printf("doUpdate for %s\n", uuidStr)

	// The existence of Config is interpreted to mean the
	// AI should be INSTALLED. Activate is checked separately.
	changed, proceed := doInstall(uuidStr, config, status)
	if !proceed {
		return changed
	}
	if !config.Activate {
		if status.Activated {
			changed = doInactivate(uuidStr, status)
		} else {
			// If we have a !ReadOnly disk this will create a copy
			err := MaybeAddDomainConfig(config, nil)
			if err != nil {
				log.Printf("Error from MaybeAddDomainConfig for %s: %s\n",
					uuidStr, err)
				status.Error = fmt.Sprintf("%s", err)
				status.ErrorTime = time.Now()
				changed = true
			}
		}
		log.Printf("Waiting for config.Activate for %s\n", uuidStr)
		return changed
	}
	log.Printf("Have config.Activate for %s\n", uuidStr)
	changed = doActivate(uuidStr, config, status)
	log.Printf("doUpdate done for %s\n", uuidStr)
	return changed
}

func doInstall(uuidStr string, config types.AppInstanceConfig,
	status *types.AppInstanceStatus) (bool, bool) {
	log.Printf("doInstall for %s\n", uuidStr)
	minState := types.MAXSTATE
	allErrors := ""
	var errorTime time.Time
	changed := false

	if len(config.StorageConfigList) != len(status.StorageStatusList) {
		errString := fmt.Sprintf("Mismatch in storageConfig vs. Status length: %d vs %d\n",
			len(config.StorageConfigList),
			len(status.StorageStatusList))
		log.Println(errString)
		status.Error = errString
		status.ErrorTime = time.Now()
		changed = true
		return changed, false
	}
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		if ss.DownloadURL != sc.DownloadURL ||
			ss.ImageSha256 != sc.ImageSha256 {
			// Report to zedcloud
			errString := fmt.Sprintf("Mismatch in storageConfig vs. Status:\n\t%s\n\t%s\n\t%s\n\t%s\n\n",
				sc.DownloadURL, ss.DownloadURL,
				sc.ImageSha256, ss.ImageSha256)
			log.Println(errString)
			status.Error = errString
			status.ErrorTime = time.Now()
			changed = true
			return changed, false
		}
	}

	if len(config.OverlayNetworkList) != len(status.EIDList) {
		errString := fmt.Sprintf("Mismatch in OLList config vs. status length: %d vs %d\n",
			len(config.OverlayNetworkList),
			len(status.EIDList))
		log.Println(errString)
		status.Error = errString
		status.ErrorTime = time.Now()
		changed = true
		return changed, false
	}
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		safename := urlToSafename(sc.DownloadURL, sc.ImageSha256)
		fmt.Printf("Found StorageConfig URL %s safename %s\n",
			sc.DownloadURL, safename)

		// Shortcut if image is already verified
		vs, err := LookupVerifyImageStatus(safename)
		if err == nil && vs.State == types.DELIVERED {
			log.Printf("doUpdate found verified image for %s\n",
				safename)
			// If we don't already have a RefCount add one
			if !ss.HasVerifierRef {
				log.Printf("doUpdate !HasVerifierRef vs.RefCount %d for %s\n",
					vs.RefCount, safename)
				vs.RefCount += 1
				ss.HasVerifierRef = true
				changed = true
			}

			if minState > vs.State {
				minState = vs.State
			}
			if vs.State != ss.State {
				ss.State = vs.State
				changed = true
			}
			continue
		}
		vs, err = LookupVerifyImageStatusSha256(sc.ImageSha256)
		if err == nil && vs.State == types.DELIVERED {
			log.Printf("doUpdate found verified image for sha256 %s\n",
				sc.ImageSha256)
			// If we don't already have a RefCount add one
			if !ss.HasVerifierRef {
				log.Printf("doUpdate !HasVerifierRef vs.RefCount %d for %s\n",
					vs.RefCount, safename)
				vs.RefCount += 1
				ss.HasVerifierRef = true
				changed = true
			}
			if minState > vs.State {
				minState = vs.State
			}
			if vs.State != ss.State {
				ss.State = vs.State
				changed = true
			}
			continue
		}
		if !ss.HasDownloaderRef {
			log.Printf("doUpdate !HasDownloaderRef for %s\n",
				safename)
			AddOrRefcountDownloaderConfig(safename, &sc)
			ss.HasDownloaderRef = true
			changed = true
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
			if !ss.HasVerifierRef {
				MaybeAddVerifyImageConfig(safename, &sc)
				ss.HasVerifierRef = true
				changed = true
			}
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
		return changed, false
	}

	if minState < types.DOWNLOADED {
		log.Printf("Waiting for all downloads for %s\n", uuidStr)
		return changed, false
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
		return changed, false
	}

	if minState < types.DELIVERED {
		log.Printf("Waiting for all verifications for %s\n", uuidStr)
		return changed, false
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
		return changed, false
	}
	// Automatically move from DELIVERED to INSTALLED
	status.State = types.INSTALLED
	changed = true
	log.Printf("Done with EID allocations for %s\n", uuidStr)
	log.Printf("doInstall done for %s\n", uuidStr)
	return changed, true
}

func doActivate(uuidStr string, config types.AppInstanceConfig,
	status *types.AppInstanceStatus) bool {
	log.Printf("doActivate for %s\n", uuidStr)
	changed := false

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
	err = MaybeAddDomainConfig(config, &ns)
	if err != nil {
		log.Printf("Error from MaybeAddDomainConfig for %s: %s\n",
			uuidStr, err)
		status.Error = fmt.Sprintf("%s", err)
		status.ErrorTime = time.Now()
		changed = true
		log.Printf("Waiting for DomainStatus Activated for %s\n",
			uuidStr)
		return changed
	}

	// Check DomainStatus; update AI status if error
	ds, err := LookupDomainStatus(uuidStr)
	if err != nil {
		log.Printf("Waiting for DomainStatus for %s\n", uuidStr)
		return changed
	}
	// Look for xen errors.
	if !ds.Activated {
		if ds.LastErr != "" {
			log.Printf("Received error from domainmgr for %s: %s\n",
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
	log.Printf("doActivate done for %s\n", uuidStr)
	return changed
}

func doRemove(uuidStr string, status *types.AppInstanceStatus) (bool, bool) {
	log.Printf("doRemove for %s\n", uuidStr)

	changed := false
	del := false
	if status.Activated {
		changed = doInactivate(uuidStr, status)
	}
	if !status.Activated {
		changed, del = doUninstall(uuidStr, status)
	}
	log.Printf("doRemove done for %s\n", uuidStr)
	return changed, del
}

func doInactivate(uuidStr string, status *types.AppInstanceStatus) bool {
	log.Printf("doInactivate for %s\n", uuidStr)
	changed := false

	// First halt the domain
	MaybeRemoveDomainConfig(uuidStr)

	// Check if DomainStatus gone; update AI status if error
	ds, err := LookupDomainStatus(uuidStr)
	if err == nil {
		log.Printf("Waiting for DomainStatus removal for %s\n", uuidStr)
		// Look for xen errors.
		if !ds.Activated {
			if ds.LastErr != "" {
				log.Printf("Received error from domainmgr for %s: %s\n",
					uuidStr, ds.LastErr)
				status.Error = ds.LastErr
				status.ErrorTime = ds.LastErrTime
				changed = true
			}
		}
		return changed
	}

	log.Printf("Done with DomainStatus removal for %s\n", uuidStr)

	MaybeRemoveAppNetworkConfig(uuidStr)

	// Check if AppNetworkStatus gone
	_, err = LookupAppNetworkStatus(uuidStr)
	if err == nil {
		log.Printf("Waiting for AppNetworkStatus removal for %s\n",
			uuidStr)
		return changed
	}
	log.Printf("Done with AppNetworkStatus removal for %s\n", uuidStr)

	status.Activated = false
	log.Printf("doInactivate done for %s\n", uuidStr)
	return changed
}

func doUninstall(uuidStr string, status *types.AppInstanceStatus) (bool, bool) {
	log.Printf("doUninstall for %s\n", uuidStr)
	changed := false
	del := false

	// Remove the EIDConfig for each overlay
	for _, es := range status.EIDList {
		MaybeRemoveEIDConfig(status.UUIDandVersion, &es)
	}
	// Check EIDStatus for each overlay; update AI status
	eidsFreed := true
	for i, es := range status.EIDList {
		es, err := LookupEIDStatus(status.UUIDandVersion, es.IID)
		if err == nil {
			key := fmt.Sprintf("%s:%d",
				status.UUIDandVersion.UUID.String(), es.IID)
			log.Printf("LookupEIDStatus not gone on remove for %s\n",
				key)
			eidsFreed = false
			continue
		}
		status.EIDList[i] = es.EIDStatusDetails
		changed = true
	}
	if !eidsFreed {
		log.Printf("Waiting for all EID frees for %s\n", uuidStr)
		return changed, del
	}
	log.Printf("Done with EID frees for %s\n", uuidStr)

	removedAll := true
	for _, ss := range status.StorageStatusList {
		// Decrease refcount if we had increased it
		if ss.HasVerifierRef {
			MaybeRemoveVerifyImageConfigSha256(ss.ImageSha256)
			ss.HasVerifierRef = false
			changed = true
		}

		_, err := LookupVerifyImageStatusSha256(ss.ImageSha256)
		// XXX if additional refs it will not go away
		if false && err == nil {
			log.Printf("LookupVerifyImageStatus %s not yet gone\n",
				ss.ImageSha256)
			removedAll = false
			continue
		}
	}
	if !removedAll {
		log.Printf("Waiting for all verify removes for %s\n", uuidStr)
		return changed, del
	}
	log.Printf("Done with all verify removes for %s\n", uuidStr)

	removedAll = true
	for _, ss := range status.StorageStatusList {
		safename := urlToSafename(ss.DownloadURL, ss.ImageSha256)
		fmt.Printf("Found StorageStatus URL %s safename %s\n",
			ss.DownloadURL, safename)
		// Decrease refcount if we had increased it
		if ss.HasDownloaderRef {
			MaybeRemoveDownloaderConfig(safename)
			ss.HasDownloaderRef = false
			changed = true
		}

		_, err := LookupDownloaderStatus(ss.ImageSha256)
		// XXX if additional refs it will not go away
		if false && err == nil {
			log.Printf("LookupDownloaderStatus %s not yet gone\n",
				safename)
			removedAll = false
			continue
		}
	}
	if !removedAll {
		log.Printf("Waiting for all downloader removes for %s\n", uuidStr)
		return changed, del
	}
	log.Printf("Done with all verify removes for %s\n", uuidStr)

	del = true
	log.Printf("doUninstall done for %s\n", uuidStr)
	return changed, del
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}

func urlToSafename(url string, sha string) string {
	safename := strings.Replace(url, "/", "_", -1) + "." + sha
	return safename
}
