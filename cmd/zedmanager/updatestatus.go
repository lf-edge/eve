// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedmanager

import (
	"fmt"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"log"
	"time"
)

// Find all the config and config which refer to this safename.
func updateAIStatusSafename(ctx *zedmanagerContext, safename string) {
	log.Printf("updateAIStatusSafename for %s\n", safename)

	sub := ctx.subAppInstanceConfig
	items := sub.GetAll()
	for key, c := range items {
		config := cast.CastAppInstanceConfig(c)
		if config.Key() != key {
			log.Printf("updateAIStatusSafename key/UUID mismatch %s vs %s; ignored %+v\n",
				key, config.Key(), config)
			continue
		}
		if debug {
			log.Printf("Processing AppInstanceConfig for UUID %s\n",
				config.UUIDandVersion.UUID)
		}
		for _, sc := range config.StorageConfigList {
			safename2 := types.UrlToSafename(sc.DownloadURL, sc.ImageSha256)
			if safename == safename2 {
				log.Printf("Found StorageConfig URL %s safename %s\n",
					sc.DownloadURL, safename2)
				updateAIStatusUUID(ctx,
					config.Key())
			}
		}
	}
}

// Update this AppInstanceStatus generate config updates to
// the microservices
func updateAIStatusUUID(ctx *zedmanagerContext, uuidStr string) {
	config := lookupAppInstanceConfig(ctx, uuidStr)
	if config == nil {
		log.Printf("updateAIStatusUUID for %s: Missing AppInstanceConfig\n",
			uuidStr)
		return
	}
	status := lookupAppInstanceStatus(ctx, uuidStr)
	if status == nil {
		log.Printf("updateAIStatusUUID for %s: Missing AppInstanceStatus\n",
			uuidStr)
		return
	}
	changed := doUpdate(ctx, uuidStr, *config, status)
	if changed {
		log.Printf("updateAIStatusUUID status change for %s\n",
			uuidStr)
		publishAppInstanceStatus(ctx, status)
	}
}

// Remove this AppInstanceStatus and generate config removes for
// the microservices
func removeAIStatusUUID(ctx *zedmanagerContext, uuidStr string) {
	status := lookupAppInstanceStatus(ctx, uuidStr)
	if status == nil {
		log.Printf("removeAIStatusUUID for %s: Missing AppInstanceStatus\n",
			uuidStr)
		return
	}
	removeAIStatus(ctx, status)
}

func removeAIStatus(ctx *zedmanagerContext, status *types.AppInstanceStatus) {
	uuidStr := status.Key()
	changed, del := doRemove(ctx, uuidStr, status)
	if changed {
		log.Printf("removeAIStatus status change for %s\n",
			uuidStr)
		publishAppInstanceStatus(ctx, status)
	}
	if del {
		log.Printf("removeAIStatus remove done for %s\n",
			uuidStr)
		// Write out what we modified to AppInstanceStatus aka delete
		unpublishAppInstanceStatus(ctx, status)
	}
}

// Find all the Status which refer to this safename.
func removeAIStatusSafename(ctx *zedmanagerContext, safename string) {
	log.Printf("removeAIStatusSafename for %s\n", safename)

	pub := ctx.pubAppInstanceStatus
	items := pub.GetAll()
	for key, st := range items {
		status := cast.CastAppInstanceStatus(st)
		if status.Key() != key {
			log.Printf("removeAIStatusSafename key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		if debug {
			log.Printf("Processing AppInstanceStatus for UUID %s\n",
				status.UUIDandVersion.UUID)
		}
		for _, ss := range status.StorageStatusList {
			safename2 := types.UrlToSafename(ss.DownloadURL, ss.ImageSha256)
			if safename == safename2 {
				if debug {
					log.Printf("Found StorageStatus URL %s safename %s\n",
						ss.DownloadURL, safename2)
				}
				removeAIStatus(ctx, &status)
			}
		}
	}
}

func doUpdate(ctx *zedmanagerContext, uuidStr string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) bool {

	log.Printf("doUpdate for %s\n", uuidStr)

	// The existence of Config is interpreted to mean the
	// AppInstance should be INSTALLED. Activate is checked separately.
	changed, done := doInstall(ctx, uuidStr, config, status)
	if !done {
		return changed
	}
	if !config.Activate {
		if status.Activated || status.ActivateInprogress {
			c := doInactivateHalt(ctx, uuidStr, config, status)
			changed = changed || c
		} else {
			// If we have a !ReadOnly disk this will create a copy
			err := MaybeAddDomainConfig(ctx, config, nil)
			if err != nil {
				log.Printf("Error from MaybeAddDomainConfig for %s: %s\n",
					uuidStr, err)
				status.State = types.INITIAL
				status.Error = fmt.Sprintf("%s", err)
				status.ErrorTime = time.Now()
				changed = true
			}
		}
		log.Printf("Waiting for config.Activate for %s\n", uuidStr)
		return changed
	}
	log.Printf("Have config.Activate for %s\n", uuidStr)
	c := doActivate(ctx, uuidStr, config, status)
	changed = changed || c
	log.Printf("doUpdate done for %s\n", uuidStr)
	return changed
}

func doInstall(ctx *zedmanagerContext, uuidStr string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) (bool, bool) {

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
		status.State = types.INITIAL
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
			status.State = types.INITIAL
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
		status.State = types.INITIAL
		status.Error = errString
		status.ErrorTime = time.Now()
		changed = true
		return changed, false
	}
	waitingForCerts := false
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(sc.DownloadURL, sc.ImageSha256)
		log.Printf("Found StorageConfig URL %s safename %s\n",
			sc.DownloadURL, safename)

		// Shortcut if image is already verified
		vs, err := LookupVerifyImageStatusAny(ctx, safename,
			sc.ImageSha256)
		if err == nil && vs.State == types.DELIVERED {
			log.Printf("doUpdate found verified image for %s sha %s\n",
				safename, sc.ImageSha256)
			if vs.Safename != safename {
				// If found based on sha256
				log.Printf("doUpdate found diff safename %s\n",
					vs.Safename)
			}
			// If we don't already have a RefCount add one
			if !ss.HasVerifierRef {
				log.Printf("doUpdate !HasVerifierRef vs. RefCount %d for %s\n",
					vs.RefCount, vs.Safename)
				// We don't need certs since Status already
				// exists
				MaybeAddVerifyImageConfig(ctx, vs.Safename,
					&sc, false)
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
			AddOrRefcountDownloaderConfig(ctx, safename, &sc)
			ss.HasDownloaderRef = true
			changed = true
		}
		ds := lookupDownloaderStatus(ctx, safename)
		if ds == nil {
			log.Printf("lookupDownloaderStatus %s failed\n",
				safename)
			minState = types.DOWNLOAD_STARTED
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
				if MaybeAddVerifyImageConfig(ctx, safename,
					&sc, true) {
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
	if waitingForCerts {
		log.Printf("Waiting for certs for %s\n", uuidStr)
		return changed, false
	}
	log.Printf("Done with downloads for %s\n", uuidStr)
	minState = types.MAXSTATE
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(sc.DownloadURL, sc.ImageSha256)
		log.Printf("Found StorageConfig URL %s safename %s\n",
			sc.DownloadURL, safename)

		vs, err := LookupVerifyImageStatusAny(ctx, safename,
			sc.ImageSha256)
		if err != nil {
			log.Printf("LookupVerifyImageStatusAny %s sha %s failed %v\n",
				safename, sc.ImageSha256, err)
			minState = types.DOWNLOADED
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
		default:
			ss.ActiveFileLocation = finalDirname + "/" + vs.Safename
			log.Printf("Update SSL ActiveFileLocation for %s: %s\n",
				uuidStr, ss.ActiveFileLocation)
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
		if es == nil {
			log.Printf("lookupEIDStatus %s failed\n",
				key)
			eidsAllocated = false
			continue
		}
		status.EIDList[i] = es.EIDStatusDetails
		/*
		log.Printf("XXXXX Parsing IID %d, EID %s\n",
			ec.IID, ec.EID.String())
		status.EIDList[i].IID = ec.IID
		status.EIDList[i].EID = ec.EID
		status.EIDList[i].LispSignature = ec.LispSignature
		status.EIDList[i].PemCert = ec.PemCert
		status.EIDList[i].PemPrivateKey = ec.PemPrivateKey
		*/
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

func doActivate(ctx *zedmanagerContext, uuidStr string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) bool {

	log.Printf("doActivate for %s\n", uuidStr)
	changed := false

	// Track that we have cleanup work in case something fails
	status.ActivateInprogress = true

	// Make sure we have an AppNetworkConfig
	MaybeAddAppNetworkConfig(ctx, config, status)

	// Check AppNetworkStatus
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns == nil {
		log.Printf("Waiting for AppNetworkStatus for %s\n", uuidStr)
		return changed
	}
	if ns.Error != "" {
		log.Printf("Received error from zedrouter for %s: %s\n",
			uuidStr, ns.Error)
		status.State = types.INITIAL
		status.Error = ns.Error
		status.ErrorTime = ns.ErrorTime
		changed = true
		return changed
	}
	if debug {
		log.Printf("Done with AppNetworkStatus for %s\n", uuidStr)
	}
	// Make sure we have a DomainConfig
	err := MaybeAddDomainConfig(ctx, config, ns)
	if err != nil {
		log.Printf("Error from MaybeAddDomainConfig for %s: %s\n",
			uuidStr, err)
		status.State = types.INITIAL
		status.Error = fmt.Sprintf("%s", err)
		status.ErrorTime = time.Now()
		changed = true
		log.Printf("Waiting for DomainStatus Activated for %s\n",
			uuidStr)
		return changed
	}

	// Check DomainStatus; update AppInstanceStatus if error
	ds := lookupDomainStatus(ctx, uuidStr)
	if ds == nil {
		log.Printf("Waiting for DomainStatus for %s\n", uuidStr)
		return changed
	}
	// Look for xen errors.
	if !ds.Activated {
		if ds.LastErr != "" {
			log.Printf("Received error from domainmgr for %s: %s\n",
				uuidStr, ds.LastErr)
			status.State = types.INITIAL
			status.Error = ds.LastErr
			status.ErrorTime = ds.LastErrTime
			changed = true
		}
		log.Printf("Waiting for DomainStatus Activated for %s\n",
			uuidStr)
		return changed
	}
	// Update ActiveFileLocation from DiskStatus
	for _, disk := range ds.DiskStatusList {
		// Need to lookup based on ImageSha256
		found := false
		for i, _ := range status.StorageStatusList {
			ss := &status.StorageStatusList[i]
			if ss.ImageSha256 == disk.ImageSha256 {
				found = true
				log.Printf("Found SSL ActiveFileLocation for %s: %s\n",
					uuidStr, disk.ActiveFileLocation)
				if ss.ActiveFileLocation != disk.ActiveFileLocation {
					log.Printf("Update SSL ActiveFileLocation for %s: %s\n",
						uuidStr, disk.ActiveFileLocation)
					ss.ActiveFileLocation = disk.ActiveFileLocation
					changed = true
				}
			}
		}
		if !found {
			log.Printf("No SSL ActiveFileLocation for %s: %s\n",
				uuidStr, disk.ActiveFileLocation)
		}
	}
	log.Printf("Done with DomainStatus for %s\n", uuidStr)

	if !status.Activated {
		status.Activated = true
		status.ActivateInprogress = false
		changed = true
	}
	log.Printf("doActivate done for %s\n", uuidStr)
	return changed
}

func doRemove(ctx *zedmanagerContext, uuidStr string,
	status *types.AppInstanceStatus) (bool, bool) {

	log.Printf("doRemove for %s\n", uuidStr)

	changed := false
	del := false
	if status.Activated || status.ActivateInprogress {
		c := doInactivate(ctx, uuidStr, status)
		changed = changed || c
	}
	if !status.Activated {
		c, d := doUninstall(ctx, uuidStr, status)
		changed = changed ||  c
		del = del || d
	}
	log.Printf("doRemove done for %s\n", uuidStr)
	return changed, del
}

func doInactivate(ctx *zedmanagerContext, uuidStr string,
	status *types.AppInstanceStatus) bool {

	log.Printf("doInactivate for %s\n", uuidStr)
	changed := false

	// First halt the domain
	unpublishDomainConfig(ctx, uuidStr)

	// Check if DomainStatus gone; update AppInstanceStatus if error
	ds := lookupDomainStatus(ctx, uuidStr)
	if ds != nil {
		log.Printf("Waiting for DomainStatus removal for %s\n", uuidStr)
		// Look for xen errors.
		if !ds.Activated {
			if ds.LastErr != "" {
				log.Printf("Received error from domainmgr for %s: %s\n",
					uuidStr, ds.LastErr)
				status.State = types.INITIAL
				status.Error = ds.LastErr
				status.ErrorTime = ds.LastErrTime
				changed = true
			}
		}
		return changed
	}

	log.Printf("Done with DomainStatus removal for %s\n", uuidStr)

	unpublishAppNetworkConfig(ctx, uuidStr)

	// Check if AppNetworkStatus gone
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns != nil {
		log.Printf("Waiting for AppNetworkStatus removal for %s\n",
			uuidStr)
		if ns.Error != "" {
			log.Printf("Received error from zedrouter for %s: %s\n",
				uuidStr, ns.Error)
			status.State = types.INITIAL
			status.Error = ns.Error
			status.ErrorTime = ns.ErrorTime
			changed = true
		}
		return changed
	}
	if debug {
		log.Printf("Done with AppNetworkStatus removal for %s\n",
			uuidStr)
	}
	status.Activated = false
	status.ActivateInprogress = false
	log.Printf("doInactivate done for %s\n", uuidStr)
	return changed
}

func doUninstall(ctx *zedmanagerContext, uuidStr string,
	status *types.AppInstanceStatus) (bool, bool) {

	log.Printf("doUninstall for %s\n", uuidStr)
	changed := false
	del := false

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
			log.Printf("lookupEIDStatus not gone on remove for %s\n",
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
	if debug {
		log.Printf("Done with EID frees for %s\n", uuidStr)
	}
	removedAll := true
	for i, _ := range status.StorageStatusList {
		ss := &status.StorageStatusList[i]
		// Decrease refcount if we had increased it
		if ss.HasVerifierRef {
			MaybeRemoveVerifyImageConfigSha256(ctx, ss.ImageSha256)
			ss.HasVerifierRef = false
			changed = true
		}

		_, err := LookupVerifyImageStatusSha256(ctx, ss.ImageSha256)
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
	if debug {
		log.Printf("Done with all verify removes for %s\n", uuidStr)
	}
	removedAll = true
	for i, _ := range status.StorageStatusList {
		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(ss.DownloadURL, ss.ImageSha256)
		if debug {
			log.Printf("Found StorageStatus URL %s safename %s\n",
				ss.DownloadURL, safename)
		}
		// Decrease refcount if we had increased it
		if ss.HasDownloaderRef {
			MaybeRemoveDownloaderConfig(ctx, safename)
			ss.HasDownloaderRef = false
			changed = true
		}

		ds := lookupDownloaderStatus(ctx, ss.ImageSha256)
		// XXX if additional refs it will not go away
		if false && ds != nil {
			log.Printf("lookupDownloaderStatus %s not yet gone\n",
				safename)
			removedAll = false
			continue
		}
	}
	if !removedAll {
		log.Printf("Waiting for all downloader removes for %s\n", uuidStr)
		return changed, del
	}
	if debug {
		log.Printf("Done with all verify removes for %s\n", uuidStr)
	}

	del = true
	log.Printf("doUninstall done for %s\n", uuidStr)
	return changed, del
}

// Handle Activate=false which is different than doInactivate
func doInactivateHalt(ctx *zedmanagerContext, uuidStr string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) bool {

	log.Printf("doInactivateHalt for %s\n", uuidStr)
	changed := false

	// Check AppNetworkStatus
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns == nil {
		log.Printf("Waiting for AppNetworkStatus for %s\n", uuidStr)
		return changed
	}
	if ns.Error != "" {
		log.Printf("Received error from zedrouter for %s: %s\n",
			uuidStr, ns.Error)
		status.State = types.INITIAL
		status.Error = ns.Error
		status.ErrorTime = ns.ErrorTime
		changed = true
		return changed
	}
	if debug {
		log.Printf("Done with AppNetworkStatus for %s\n", uuidStr)
	}

	// Make sure we have a DomainConfig
	err := MaybeAddDomainConfig(ctx, config, ns)
	if err != nil {
		log.Printf("Error from MaybeAddDomainConfig for %s: %s\n",
			uuidStr, err)
		status.State = types.INITIAL
		status.Error = fmt.Sprintf("%s", err)
		status.ErrorTime = time.Now()
		changed = true
		log.Printf("Waiting for DomainStatus Activated for %s\n",
			uuidStr)
		return changed
	}

	// Check DomainStatus; update AppInstanceStatus if error
	ds := lookupDomainStatus(ctx, uuidStr)
	if ds == nil {
		log.Printf("Waiting for DomainStatus for %s\n", uuidStr)
		return changed
	}
	// Look for xen errors.
	if ds.Activated {
		log.Printf("Waiting for Not Activated for DomainStatus %s\n",
			uuidStr)
		return changed
	}
	if ds.LastErr != "" {
		log.Printf("Received error from domainmgr for %s: %s\n",
			uuidStr, ds.LastErr)
		status.State = types.INITIAL
		status.Error = ds.LastErr
		status.ErrorTime = ds.LastErrTime
		changed = true
	}
	// XXX network is still around! Need to call doInactivate in doRemove?
	// XXX fix assymetry
	status.Activated = false
	status.ActivateInprogress = false
	changed = true
	log.Printf("doInactivateHalt done for %s\n", uuidStr)
	return changed
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}
