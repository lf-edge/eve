// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedmanager

import (
	"errors"
	"fmt"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"time"
)

// Find all the config which refer to this safename.
func updateAIStatusSafename(ctx *zedmanagerContext, safename string) {

	log.Infof("updateAIStatusSafename for %s\n", safename)
	sub := ctx.subAppInstanceConfig
	items := sub.GetAll()
	for key, c := range items {
		config := cast.CastAppInstanceConfig(c)
		if config.Key() != key {
			log.Errorf("updateAIStatusSafename key/UUID mismatch %s vs %s; ignored %+v\n",
				key, config.Key(), config)
			continue
		}
		log.Debugf("Processing AppInstanceConfig for UUID %s\n",
			config.UUIDandVersion.UUID)
		for _, sc := range config.StorageConfigList {
			safename2 := types.UrlToSafename(sc.Name, sc.ImageSha256)
			if safename == safename2 {
				log.Infof("Found StorageConfig URL %s safename %s\n",
					sc.Name, safename2)
				updateAIStatusUUID(ctx, config.Key())
			}
		}
	}
}

// Update this AppInstanceStatus generate config updates to
// the microservices
func updateAIStatusUUID(ctx *zedmanagerContext, uuidStr string) {
	status := lookupAppInstanceStatus(ctx, uuidStr)
	if status == nil {
		log.Infof("updateAIStatusUUID for %s: Missing AppInstanceStatus\n",
			uuidStr)
		return
	}
	config := lookupAppInstanceConfig(ctx, uuidStr)
	if config == nil {
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
			}
		}
	}
}

// If we have an AIConfig we update it - the image might have disappeared.
// Otherwise we proceeed with remove.
func updateOrRemove(ctx *zedmanagerContext, status types.AppInstanceStatus) {
	uuidStr := status.Key()
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
	// XXX when/how do we drop refcounts on old images? GC?
	// XXX need to keep old StorageStatusList with Has*Ref
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
		status.PurgeInprogress = types.BRING_UP
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
			err := MaybeAddDomainConfig(ctx, config, nil)
			if err != nil {
				log.Errorf("Error from MaybeAddDomainConfig for %s: %s\n",
					uuidStr, err)
				status.Error = fmt.Sprintf("%s", err)
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
	var errorTime time.Time
	changed := false

	if len(config.StorageConfigList) != len(status.StorageStatusList) {
		errString := fmt.Sprintf("Mismatch in storageConfig vs. Status length: %d vs %d\n",
			len(config.StorageConfigList),
			len(status.StorageStatusList))
		log.Errorln(errString)
		status.Error = errString
		status.ErrorTime = time.Now()
		changed = true
		return changed, false
	}
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		if ss.Name != sc.Name ||
			ss.ImageSha256 != sc.ImageSha256 {
			// Report to zedcloud
			errString := fmt.Sprintf("Mismatch in storageConfig vs. Status:\n\t%s\n\t%s\n\t%s\n\t%s\n\n",
				sc.Name, ss.Name,
				sc.ImageSha256, ss.ImageSha256)
			log.Errorln(errString)
			status.Error = errString
			status.ErrorTime = time.Now()
			changed = true
			return changed, false
		}
	}

	waitingForCerts := false
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(sc.Name, sc.ImageSha256)
		log.Infof("Found StorageConfig URL %s safename %s\n",
			sc.Name, safename)

		// Shortcut if image is already verified
		vs := lookupVerifyImageStatusAny(ctx, safename,
			sc.ImageSha256)
		if vs != nil && vs.State == types.DELIVERED {
			log.Infof("doUpdate found verified image for %s sha %s\n",
				safename, sc.ImageSha256)
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
			log.Infof("doUpdate !HasDownloaderRef for %s\n",
				safename)
			dst, err := lookupDatastoreConfig(ctx, sc.DatastoreId,
				sc.Name)
			if err != nil {
				// Remember to check when Datastores are added
				ss.MissingDatastore = true
				status.MissingDatastore = true
				ss.Error = fmt.Sprintf("%v", err)
				allErrors = appendError(allErrors, "datastore",
					ss.Error)
				ss.ErrorTime = time.Now()
				changed = true
				continue
			}
			ss.MissingDatastore = false
			AddOrRefcountDownloaderConfig(ctx, safename, &sc, dst)
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
			allErrors = appendError(allErrors, "downloader",
				ds.LastErr)
			ss.ErrorTime = ds.LastErrTime
			errorTime = ds.LastErrTime
			changed = true
			continue
		}
		switch ds.State {
		case types.INITIAL:
			// Nothing to do
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
	if status.MissingDatastore {
		status.MissingDatastore = false
		changed = true
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
	}
	status.Error = allErrors
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
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(sc.Name, sc.ImageSha256)
		log.Infof("Found StorageConfig URL %s safename %s\n",
			sc.Name, safename)

		vs := lookupVerifyImageStatusAny(ctx, safename,
			sc.ImageSha256)
		if vs == nil {
			log.Infof("lookupVerifyImageStatusAny %s sha %s failed\n",
				safename, sc.ImageSha256)
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
		if vs.Pending() {
			log.Infof("lookupVerifyImageStatusAny %s Pending\n",
				safename)
			continue
		}
		if vs.LastErr != "" {
			log.Errorf("Received error from verifier for %s: %s\n",
				safename, vs.LastErr)
			ss.Error = vs.LastErr
			allErrors = appendError(allErrors, "verifier",
				vs.LastErr)
			ss.ErrorTime = vs.LastErrTime
			errorTime = vs.LastErrTime
			changed = true
			continue
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
	}
	status.Error = allErrors
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

// Check for nil UUID (an indication the drive was missing in parseconfig)
// and a missing datastore id.
func lookupDatastoreConfig(ctx *zedmanagerContext,
	datastoreId uuid.UUID, name string) (*types.DatastoreConfig, error) {

	if datastoreId == nilUUID {
		errStr := fmt.Sprintf("lookupDatastoreConfig(%s) for %s: No datastore ID",
			datastoreId.String(), name)
		log.Errorln(errStr)
		return nil, errors.New(errStr)
	}
	cfg, err := ctx.subDatastoreConfig.Get(datastoreId.String())
	if err != nil {
		errStr := fmt.Sprintf("lookupDatastoreConfig(%s) for %s: %v",
			datastoreId.String(), name, err)
		log.Errorln(errStr)
		return nil, errors.New(errStr)
	}
	dst := cast.CastDatastoreConfig(cfg)
	return &dst, nil
}

func doActivate(ctx *zedmanagerContext, uuidStr string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) bool {

	log.Infof("doActivate for %s\n", uuidStr)
	changed := false

	// Are we doing a restart and it came down?
	switch status.RestartInprogress {
	case types.BRING_DOWN:
		ds := lookupDomainStatus(ctx, config.Key())
		if ds != nil && !ds.Activated {
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
	if ns == nil || ns.Pending() {
		log.Infof("Waiting for AppNetworkStatus for %s\n", uuidStr)
		return changed
	}
	if ns.Error != "" {
		log.Errorf("Received error from zedrouter for %s: %s\n",
			uuidStr, ns.Error)
		status.Error = ns.Error
		status.ErrorTime = ns.ErrorTime
		changed = true
		return changed
	}
	log.Debugf("Done with AppNetworkStatus for %s\n", uuidStr)

	// Make sure we have a DomainConfig
	err := MaybeAddDomainConfig(ctx, config, ns)
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
	if ds == nil || ds.Pending() {
		log.Infof("Waiting for DomainStatus for %s\n", uuidStr)
		return changed
	}
	// Look for xen errors.
	if ds.LastErr != "" {
		log.Errorf("Received error from domainmgr for %s: %s\n",
			uuidStr, ds.LastErr)
		status.Error = ds.LastErr
		status.ErrorTime = ds.LastErrTime
		changed = true
	}
	if ds.State != status.State {
		log.Infof("Set State from DomainStatus from %d to %d\n",
			status.State, ds.State)
		switch status.State {
		case types.RESTARTING, types.PURGING:
			// Leave unchanged
		default:
			status.State = ds.State
		}
	}

	if ds.State < types.BOOTING {
		log.Infof("Waiting for DomainStatus to BOOTING for %s\n",
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
				log.Infof("Found SSL ActiveFileLocation for %s: %s\n",
					uuidStr, disk.ActiveFileLocation)
				if ss.ActiveFileLocation != disk.ActiveFileLocation {
					log.Infof("Update SSL ActiveFileLocation for %s: %s\n",
						uuidStr, disk.ActiveFileLocation)
					ss.ActiveFileLocation = disk.ActiveFileLocation
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
	switch status.RestartInprogress {
	case types.NONE:
		// Nothing to do
	case types.BRING_DOWN:
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
	case types.BRING_UP:
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
			changed = true
		} else {
			log.Infof("PurgeInprogress(%s) waiting for Activated\n",
				status.Key())
		}
	}
	log.Infof("doActivate done for %s\n", uuidStr)
	return changed
}

func doRemove(ctx *zedmanagerContext, uuidStr string,
	status *types.AppInstanceStatus, uninstall bool) (bool, bool) {

	log.Infof("doRemove for %s uninstall %v\n", uuidStr, uninstall)

	changed := false
	done := false
	if status.Activated || status.ActivateInprogress {
		c := doInactivate(ctx, uuidStr, status)
		changed = changed || c
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
	status *types.AppInstanceStatus) bool {

	log.Infof("doInactivate for %s\n", uuidStr)
	changed := false

	// First halt the domain
	unpublishDomainConfig(ctx, uuidStr)

	// Check if DomainStatus gone; update AppInstanceStatus if error
	ds := lookupDomainStatus(ctx, uuidStr)
	if ds != nil {
		log.Infof("Waiting for DomainStatus removal for %s\n", uuidStr)
		// Look for xen errors.
		if !ds.Activated {
			if ds.LastErr != "" {
				log.Errorf("Received error from domainmgr for %s: %s\n",
					uuidStr, ds.LastErr)
				status.Error = ds.LastErr
				status.ErrorTime = ds.LastErrTime
				changed = true
			}
		}
		return changed
	}

	log.Infof("Done with DomainStatus removal for %s\n", uuidStr)

	unpublishAppNetworkConfig(ctx, uuidStr)

	// Check if AppNetworkStatus gone
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns != nil {
		log.Infof("Waiting for AppNetworkStatus removal for %s\n",
			uuidStr)
		if ns.Error != "" {
			log.Errorf("Received error from zedrouter for %s: %s\n",
				uuidStr, ns.Error)
			status.Error = ns.Error
			status.ErrorTime = ns.ErrorTime
			changed = true
		}
		return changed
	}
	log.Debugf("Done with AppNetworkStatus removal for %s\n", uuidStr)
	status.Activated = false
	status.ActivateInprogress = false
	log.Infof("doInactivate done for %s\n", uuidStr)
	return changed
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
			eidsFreed = false
			continue
		}
		status.EIDList[i] = es.EIDStatusDetails
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

	removedAll := true
	for i, _ := range status.StorageStatusList {
		ss := &status.StorageStatusList[i]
		// Decrease refcount if we had increased it
		if ss.HasVerifierRef {
			MaybeRemoveVerifyImageConfigSha256(ctx, ss.ImageSha256)
			ss.HasVerifierRef = false
			changed = true
		}

		vs := lookupVerifyImageStatusSha256(ctx, ss.ImageSha256)
		// XXX if additional refs it will not go away
		if false && vs != nil {
			log.Infof("lookupVerifyImageStatus %s not yet gone\n",
				ss.ImageSha256)
			removedAll = false
			continue
		}
	}
	if !removedAll {
		log.Infof("Waiting for all verify removes for %s\n", uuidStr)
		return changed, del
	}
	log.Debugf("Done with all verify removes for %s\n", uuidStr)
	removedAll = true
	for i, _ := range status.StorageStatusList {
		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(ss.Name, ss.ImageSha256)
		log.Debugf("Found StorageStatus URL %s safename %s\n",
			ss.Name, safename)
		// Decrease refcount if we had increased it
		if ss.HasDownloaderRef {
			MaybeRemoveDownloaderConfig(ctx, safename)
			ss.HasDownloaderRef = false
			changed = true
		}

		ds := lookupDownloaderStatus(ctx, ss.ImageSha256)
		// XXX if additional refs it will not go away
		if false && ds != nil {
			log.Infof("lookupDownloaderStatus %s not yet gone\n",
				safename)
			removedAll = false
			continue
		}
	}
	if !removedAll {
		log.Infof("Waiting for all downloader removes for %s\n", uuidStr)
		return changed, del
	}
	log.Debugf("Done with all downloader removes for %s\n", uuidStr)

	del = true
	log.Infof("doUninstall done for %s\n", uuidStr)
	return changed, del
}

// Handle Activate=false which is different than doInactivate
func doInactivateHalt(ctx *zedmanagerContext, uuidStr string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) bool {

	log.Infof("doInactivateHalt for %s\n", uuidStr)
	changed := false

	// Check AppNetworkStatus
	ns := lookupAppNetworkStatus(ctx, uuidStr)
	if ns == nil || ns.Pending() {
		log.Infof("Waiting for AppNetworkStatus for %s\n", uuidStr)
		return changed
	}
	if ns.Error != "" {
		log.Errorf("Received error from zedrouter for %s: %s\n",
			uuidStr, ns.Error)
		status.Error = ns.Error
		status.ErrorTime = ns.ErrorTime
		changed = true
		return changed
	}
	log.Debugf("Done with AppNetworkStatus for %s\n", uuidStr)

	// Make sure we have a DomainConfig
	err := MaybeAddDomainConfig(ctx, config, ns)
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
	if ds == nil || ds.Pending() {
		log.Infof("Waiting for DomainStatus for %s\n", uuidStr)
		return changed
	}
	// Look for xen errors.
	if ds.Activated {
		log.Infof("Waiting for Not Activated for DomainStatus %s\n",
			uuidStr)
		return changed
	}
	if ds.LastErr != "" {
		log.Errorf("Received error from domainmgr for %s: %s\n",
			uuidStr, ds.LastErr)
		status.Error = ds.LastErr
		status.ErrorTime = ds.LastErrTime
		changed = true
	}
	// XXX network is still around! Need to call doInactivate in doRemove?
	// XXX fix assymetry
	status.Activated = false
	status.ActivateInprogress = false
	changed = true
	log.Infof("doInactivateHalt done for %s\n", uuidStr)
	return changed
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}
