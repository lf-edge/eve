// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// base os event handlers

package zedagent

import (
	"errors"
	"fmt"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zboot"
	"log"
	"os"
	"time"
)

func lookupBaseOsSafename(ctx *zedagentContext, safename string) *types.BaseOsConfig {
	items := ctx.subBaseOsConfig.GetAll()
	for _, c := range items {
		config := cast.CastBaseOsConfig(c)
		for _, sc := range config.StorageConfigList {
			safename1 := types.UrlToSafename(sc.Name,
				sc.ImageSha256)

			// base os config contains the current image
			if safename == safename1 {
				return &config
			}
		}
	}
	return nil
}
func baseOsHandleStatusUpdateSafename(ctx *zedagentContext, safename string) {

	log.Printf("baseOsStatusUpdateSafename for %s\n", safename)
	config := lookupBaseOsSafename(ctx, safename)
	if config == nil {
		log.Printf("baseOsHandleStatusUpdateSafename(%s) not found\n",
			safename)
		return
	}
	uuidStr := config.Key()
	status := lookupBaseOsStatus(ctx, uuidStr)
	if status == nil {
		log.Printf("baseOsHandleStatusUpdateSafename(%s) no status\n",
			safename)
		return
	}
	log.Printf("baseOsHandleStatusUpdateSafename(%s) found %s\n",
		safename, uuidStr)

	// handle the change event for this base os config
	baseOsHandleStatusUpdate(ctx, config, status)
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

	// some partition specific attributes
	status.PartitionState = zboot.GetPartitionState(partName)
	status.PartitionDevice = zboot.GetPartitionDevname(partName)

	// for otherPartition, its always false
	if !zboot.IsCurrentPartition(partName) {
		status.Activated = false
		return
	}
	// if current Partition, get the status from zboot
	status.Activated = zboot.IsCurrentPartitionStateActive()
}

func baseOsHandleStatusUpdate(ctx *zedagentContext, config *types.BaseOsConfig,
	status *types.BaseOsStatus) {

	uuidStr := config.Key()
	log.Printf("baseOsHandleStatusUpdate(%s)\n", uuidStr)

	baseOsGetActivationStatus(status)

	changed := doBaseOsStatusUpdate(ctx, uuidStr, *config, status)

	if changed {
		log.Printf("baseOsHandleStatusUpdate(%s) for %s, Status changed\n",
			config.BaseOsVersion, uuidStr)
		publishBaseOsStatus(ctx, status)
	}
}

func doBaseOsStatusUpdate(ctx *zedagentContext, uuidStr string,
	config types.BaseOsConfig, status *types.BaseOsStatus) bool {

	log.Printf("doBaseOsStatusUpdate(%s) for %s\n",
		config.BaseOsVersion, uuidStr)

	changed := false
	// Are we already running this version? If so nothing to do.
	// Note that we don't return errors if someone tries to deactivate
	// the running version, but we don't act on it either.
	curPartName := zboot.GetCurrentPartition()
	if status.BaseOsVersion == zboot.GetShortVersion(curPartName) {
		status.PartitionLabel = curPartName
		// some partition specific attributes
		status.PartitionState = zboot.GetPartitionState(curPartName)
		status.PartitionDevice = zboot.GetPartitionDevname(curPartName)
		status.Activated = true
		return true
	}
	// Update other partition info
	// XXX in validate etc
	otherPartName := zboot.GetOtherPartition()
	if false && status.BaseOsVersion == zboot.GetShortVersion(otherPartName) &&
		status.PartitionLabel == "" {

		status.PartitionLabel = otherPartName
		// some partition specific attributes
		status.PartitionState = zboot.GetPartitionState(otherPartName)
		status.PartitionDevice = zboot.GetPartitionDevname(otherPartName)
		status.Activated = false
		changed = true
	}

	c, proceed := doBaseOsInstall(ctx, uuidStr, config, status)
	changed = changed || c
	if !proceed {
		return changed
	}

	if !config.Activate {
		log.Printf("doBaseOsStatusUpdate(%s) for %s, Activate is not set\n",
			config.BaseOsVersion, uuidStr)
		changed = doBaseOsInactivate(uuidStr, status)
		return changed
	}

	if status.Activated {
		log.Printf("doBaseOsStatusUpdate(%s) for %s, is already activated\n",
			config.BaseOsVersion, uuidStr)
		return false
	}

	changed = doBaseOsActivate(ctx, uuidStr, config, status)
	log.Printf("doBaseOsStatusUpdate(%s) done for %s\n",
		config.BaseOsVersion, uuidStr)
	return changed
}

// Returns changed boolean when the status was changed
func doBaseOsActivate(ctx *zedagentContext, uuidStr string,
	config types.BaseOsConfig, status *types.BaseOsStatus) bool {

	log.Printf("doBaseOsActivate(%s) uuid %s\n",
		config.BaseOsVersion, uuidStr)

	changed := false

	log.Printf("doBaseOsActivate(%s) for %s, partition %s\n",
		config.BaseOsVersion, uuidStr, status.PartitionLabel)

	if status.PartitionLabel == "" {
		log.Printf("doBaseOsActivate(%s) for %s, unassigned partition\n",
			config.BaseOsVersion, uuidStr)
		return changed
	}

	// Sanity check the partition label of the current root and
	// the partition state
	// We've already dd'ed the new image into the partition
	// hence can't compare versions here. Version check was done when
	// processing the baseOsConfig.

	if !zboot.IsOtherPartition(status.PartitionLabel) {
		return changed
	}
	partState := zboot.GetPartitionState(status.PartitionLabel)
	switch partState {
	case "unused":
		log.Printf("Installing %s over unused\n",
			config.BaseOsVersion)
	case "inprogress":
		log.Printf("Installing %s over inprogress\n",
			config.BaseOsVersion)
	case "updating":
		log.Printf("Installing %s over updating\n",
			config.BaseOsVersion)
	default:
		errString := fmt.Sprintf("Wrong partition state %s for %s",
			partState, status.PartitionLabel)
		log.Println(errString)
		status.Error = errString
		status.ErrorTime = time.Now()
		changed = true
		return changed
	}

	log.Printf("doBaseOsActivate: %s activating\n", uuidStr)
	zboot.SetOtherPartitionStateUpdating()
	publishDeviceInfo = true

	// Remove any old log files for a previous instance
	logdir := fmt.Sprintf("/persist/%s/log", status.PartitionLabel)
	log.Printf("Clearing old logs in %s\n", logdir)
	if err := os.RemoveAll(logdir); err != nil {
		log.Println(err)
	}

	// if it is installed, flip the activated status
	if status.State == types.INSTALLED || !status.Activated {
		status.Activated = true
		changed = true
		// Make sure we tell apps to shut down
		shutdownAppsGlobal()
		startExecReboot()
	}

	return changed
}

func doBaseOsInstall(ctx *zedagentContext, uuidStr string,
	config types.BaseOsConfig, status *types.BaseOsStatus) (bool, bool) {

	log.Printf("doBaseOsInstall(%s) %s\n", uuidStr, config.BaseOsVersion)
	changed := false
	proceed := false

	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		if ss.Name != sc.Name ||
			ss.ImageSha256 != sc.ImageSha256 {
			// Report to zedcloud
			errString := fmt.Sprintf("%s, for %s, Storage config mismatch:\n\t%s\n\t%s\n\t%s\n\t%s\n\n", uuidStr,
				config.BaseOsVersion,
				sc.Name, ss.Name,
				sc.ImageSha256, ss.ImageSha256)
			log.Println(errString)
			status.Error = errString
			status.ErrorTime = time.Now()
			changed = true
			return changed, proceed
		}
	}

	changed, proceed = validateAndAssignPartition(ctx, config, status)
	if !proceed {
		return changed, proceed
	}

	// check for the download status change
	downloadchange, downloaded :=
		checkBaseOsStorageDownloadStatus(ctx, uuidStr, config, status)

	if !downloaded {
		log.Printf(" %s, Still not downloaded\n", config.BaseOsVersion)
		return changed || downloadchange, proceed
	}

	// check for the verification status change
	verifychange, verified :=
		checkBaseOsVerificationStatus(ctx, uuidStr, config, status)

	if !verified {
		log.Printf("doBaseOsInstall(%s) still not verified %s\n",
			uuidStr, config.BaseOsVersion)
		return changed || verifychange, proceed
	}

	// XXX can we check the version before installing to the partition?
	// XXX requires loopback mounting the image. We dd as part of
	// this install call:

	// install the image at proper partition
	if installDownloadedObjects(baseOsObj, uuidStr,
		status.StorageStatusList) {

		changed = true
		//match the version string
		if errString := checkInstalledVersion(*status); errString != "" {
			status.State = types.INITIAL
			status.Error = errString
			status.ErrorTime = time.Now()
		} else {
			// move the state from DELIVERED to INSTALLED
			status.State = types.INSTALLED
			proceed = true
		}
	}

	publishBaseOsStatus(ctx, status)
	log.Printf("doBaseOsInstall(%s), Done %v\n",
		config.BaseOsVersion, proceed)
	return changed, proceed
}

// Returns changed, proceed as above
func validateAndAssignPartition(ctx *zedagentContext,
	config types.BaseOsConfig, status *types.BaseOsStatus) (bool, bool) {

	log.Printf("validateAndAssignPartition(%s)\n", config.BaseOsVersion)
	changed := false
	proceed := false
	curPartName := zboot.GetCurrentPartition()
	otherPartName := zboot.GetOtherPartition()
	curPartVersion := zboot.GetShortVersion(curPartName)
	otherPartVersion := zboot.GetShortVersion(otherPartName)

	// Does the other partition contain a failed update with the same
	// version?
	if zboot.IsOtherPartitionStateInProgress() &&
		otherPartVersion == config.BaseOsVersion {

		errStr := fmt.Sprintf("Attempt to reinstall failed update %s in %s: refused",
			config.BaseOsVersion, otherPartName)
		log.Println(errStr)
		status.Error = errStr
		status.ErrorTime = time.Now()
		changed = true
		return changed, proceed
	}

	if zboot.IsOtherPartitionStateActive() {
		if otherPartVersion == config.BaseOsVersion {
			// Don't try to download what is already in otherPartVersion
			log.Printf("validateAndAssignPartition(%s) not overwriting other with same version since testing inprogress\n",
				config.BaseOsVersion)
			return changed, proceed
		}

		// Must still be testing the current version; don't overwrite
		// fallback
		errStr := fmt.Sprintf("Attempt to install baseOs update %s while testing is in progress for %s: refused",
			config.BaseOsVersion, curPartVersion)
		log.Println(errStr)
		status.Error = errStr
		status.ErrorTime = time.Now()
		changed = true
		return changed, proceed
	}

	if config.Activate && status.PartitionLabel == "" {
		log.Printf("validateAndAssignPartition(%s) assigning with partition %s\n",
			config.BaseOsVersion, status.PartitionLabel)
		status.PartitionLabel = otherPartName
		status.PartitionState = zboot.GetPartitionState(otherPartName)
		status.PartitionDevice = zboot.GetPartitionDevname(otherPartName)

		// List has only one element but ...
		for idx, _ := range status.StorageStatusList {
			ss := &status.StorageStatusList[idx]
			ss.FinalObjDir = status.PartitionLabel
		}
		changed = true
	}
	proceed = true
	return changed, proceed
}

func checkBaseOsStorageDownloadStatus(ctx *zedagentContext, uuidStr string,
	config types.BaseOsConfig,
	status *types.BaseOsStatus) (bool, bool) {

	log.Printf("checkBaseOsStorageDownloadStatus(%s) for %s\n",
		config.BaseOsVersion, uuidStr)
	ret := checkStorageDownloadStatus(ctx, baseOsObj, uuidStr,
		config.StorageConfigList, status.StorageStatusList)

	status.State = ret.MinState

	if ret.MinState == types.INITIAL {
		status.Error = ret.AllErrors
		status.ErrorTime = ret.ErrorTime
		log.Printf("checkBaseOsStorageDownloadStatus(%s) for %s, Download error at %v: %v\n",
			config.BaseOsVersion, uuidStr, status.ErrorTime, status.Error)
		return ret.Changed, false
	}

	if ret.MinState < types.DOWNLOADED {
		log.Printf("checkBaseOsStorageDownloadStatus(%s) for %s, Waiting for all downloads\n",
			config.BaseOsVersion, uuidStr)
		return ret.Changed, false
	}

	if ret.WaitingForCerts {
		log.Printf("checkBaseOsStorageDownloadStatus(%s) for %s, Waiting for certs\n",
			config.BaseOsVersion, uuidStr)
		return ret.Changed, false
	}

	log.Printf("checkBaseOsStorageDownloadStatus(%s) for %s, Downloads done\n",
		config.BaseOsVersion, uuidStr)
	return ret.Changed, true
}

func checkBaseOsVerificationStatus(ctx *zedagentContext, uuidStr string,
	config types.BaseOsConfig, status *types.BaseOsStatus) (bool, bool) {

	ret := checkStorageVerifierStatus(ctx, baseOsObj,
		uuidStr, config.StorageConfigList, status.StorageStatusList)

	status.State = ret.MinState

	if ret.MinState == types.INITIAL {
		status.Error = ret.AllErrors
		status.ErrorTime = ret.ErrorTime
		log.Printf("checkBaseOsVerificationStatus(%s) for %s, Verification error at %v: %v\n",
			config.BaseOsVersion, uuidStr, status.ErrorTime, status.Error)
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

func removeBaseOsConfig(ctx *zedagentContext, uuidStr string) {

	log.Printf("removeBaseOsConfig for %s\n", uuidStr)
	removeBaseOsStatus(ctx, uuidStr)
	log.Printf("removeBaseOSConfig for %s, done\n", uuidStr)
}

func removeBaseOsStatus(ctx *zedagentContext, uuidStr string) {

	log.Printf("removeBaseOsStatus for %s\n", uuidStr)
	status := lookupBaseOsStatus(ctx, uuidStr)
	if status == nil {
		log.Printf("removeBaseOsStatus: no status\n")
		return
	}

	changed, del := doBaseOsRemove(ctx, uuidStr, status)
	if changed {
		log.Printf("removeBaseOsStatus for %s, Status change\n", uuidStr)
		publishBaseOsStatus(ctx, status)
	}

	if del {
		log.Printf("removeBaseOsStatus %s, Deleting\n", uuidStr)

		// Write out what we modified to BaseOsStatus aka delete
		unpublishBaseOsStatus(ctx, status.Key())
	}
	log.Printf("removeBaseOsStatus %s, Done\n", uuidStr)
}

func doBaseOsRemove(ctx *zedagentContext, uuidStr string,
	status *types.BaseOsStatus) (bool, bool) {

	log.Printf("doBaseOsRemove(%s) for %s\n", status.BaseOsVersion, uuidStr)

	changed := false
	del := false

	changed = doBaseOsInactivate(uuidStr, status)

	changed, del = doBaseOsUninstall(ctx, uuidStr, status)

	log.Printf("doBaseOsRemove(%s) for %s, Done\n",
		status.BaseOsVersion, uuidStr)
	return changed, del
}

func doBaseOsInactivate(uuidStr string, status *types.BaseOsStatus) bool {
	log.Printf("doBaseOsInactivate(%s) %v\n",
		status.BaseOsVersion, status.Activated)

	// nothing to be done, flip will happen on reboot
	return true
}

func doBaseOsUninstall(ctx *zedagentContext, uuidStr string,
	status *types.BaseOsStatus) (bool, bool) {

	log.Printf("doBaseOsUninstall(%s) for %s\n",
		status.BaseOsVersion, uuidStr)

	del := false
	changed := false
	removedAll := true

	// If this image is on the !active partition we mark that
	// as unused.
	if status.PartitionLabel != "" {
		partName := status.PartitionLabel
		if status.BaseOsVersion == zboot.GetShortVersion(partName) &&
			zboot.IsOtherPartition(partName) {
			log.Printf("doBaseOsUninstall(%s) for %s, currently on other %s\n",
				status.BaseOsVersion, uuidStr, partName)
			log.Printf("Mark other partition %s, unused\n", partName)
			zboot.SetOtherPartitionStateUnused()
		}
		status.PartitionLabel = ""
		changed = true
	}
	for i, _ := range status.StorageStatusList {

		ss := &status.StorageStatusList[i]

		// Decrease refcount if we had increased it
		if ss.HasVerifierRef {
			log.Printf("doBaseOsUninstall(%s) for %s, HasVerifierRef %s\n",
				status.BaseOsVersion, uuidStr, ss.ImageSha256)
			MaybeRemoveVerifierConfigSha256(ctx, baseOsObj,
				ss.ImageSha256)
			ss.HasVerifierRef = false
			changed = true
		} else {
			log.Printf("doBaseOsUninstall(%s) for %s, NO HasVerifier\n",
				status.BaseOsVersion, uuidStr)
		}

		vs := lookupVerificationStatusSha256(ctx, baseOsObj,
			ss.ImageSha256)

		if vs != nil {
			log.Printf("doBaseOsUninstall(%s) for %s, Verifier %s not yet gone; RefCount %d\n",
				status.BaseOsVersion, uuidStr, ss.ImageSha256,
				vs.RefCount)
			removedAll = false
			continue
		}
	}

	if !removedAll {
		// XXX Note that we hit this all the time, and
		// we proceed to not look at the downloads and proceed
		// to delete all the config and status for this baseos, which
		// is odd.
		// Changed to proceed in any case
		log.Printf("doBaseOsUninstall(%s) for %s, NOT Waiting for verifier purge\n",
			status.BaseOsVersion, uuidStr)
		// XXX return changed, del
	}

	removedAll = true

	for i, _ := range status.StorageStatusList {

		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(ss.Name, ss.ImageSha256)
		// Decrease refcount if we had increased it
		if ss.HasDownloaderRef {
			log.Printf("doBaseOsUninstall(%s) for %s, HasDownloaderRef %s\n",
				status.BaseOsVersion, uuidStr, safename)

			removeDownloaderConfig(ctx, baseOsObj, safename)
			ss.HasDownloaderRef = false
			changed = true
		} else {
			log.Printf("doBaseOsUninstall(%s) for %s, NO HasDownloaderRef\n",
				status.BaseOsVersion, uuidStr)
		}

		ds := lookupDownloaderStatus(ctx, baseOsObj, ss.ImageSha256)
		if ds != nil {
			log.Printf("doBaseOsUninstall(%s) for %s, Download %s not yet gone; RefCount %d\n",
				status.BaseOsVersion, uuidStr, safename,
				ds.RefCount)
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
		errStr := fmt.Sprintf("installBaseOsObject: unassigned destination partition for %s",
			srcFilename)
		log.Println(errStr)
		return errors.New(errStr)
	}

	err := zboot.WriteToPartition(srcFilename, dstFilename)
	if err != nil {
		errStr := fmt.Sprintf("installBaseOsObject: WriteToPartition failed %s: %s",
			dstFilename, err)
		log.Println(errStr)
		return errors.New(errStr)
	}
	return nil
}

// validate whether the image version matches with
// config version string
// XXX callers??
func checkInstalledVersion(status types.BaseOsStatus) string {

	log.Printf("checkInstalledVersion(%s) %s %s\n",
		status.UUIDandVersion.UUID.String(), status.PartitionLabel,
		status.BaseOsVersion)

	if status.PartitionLabel == "" {
		errStr := fmt.Sprintf("checkInstalledVersion(%s) invalid partition", status.BaseOsVersion)
		log.Println(errStr)
		return errStr
	}

	partVersion := zboot.GetShortVersion(status.PartitionLabel)
	// XXX this check can result in failures when multiple updates in progress in zedcloud!
	// XXX remove?
	if status.BaseOsVersion != partVersion {
		errStr := fmt.Sprintf("baseOs %s, %s, does not match installed %s",
			status.PartitionLabel, status.BaseOsVersion, partVersion)

		log.Println(errStr)
		// XXX return errStr
		// XXX restore
	}
	return ""
}

func lookupBaseOsConfig(ctx *zedagentContext, key string) *types.BaseOsConfig {

	sub := ctx.subBaseOsConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Printf("lookupBaseOsConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastBaseOsConfig(c)
	if config.Key() != key {
		log.Printf("lookupBaseOsConfig(%s) got %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

func lookupBaseOsStatus(ctx *zedagentContext, key string) *types.BaseOsStatus {
	pub := ctx.pubBaseOsStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("lookupBaseOsStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastBaseOsStatus(st)
	if status.Key() != key {
		log.Printf("lookupBaseOsStatus(%s) got %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func publishBaseOsStatus(ctx *zedagentContext, status *types.BaseOsStatus) {

	key := status.Key()
	log.Printf("Publishing BaseOsStatus %s\n", key)
	pub := ctx.pubBaseOsStatus
	pub.Publish(key, status)
}

func unpublishBaseOsStatus(ctx *zedagentContext, key string) {

	log.Printf("Unpublishing BaseOsStatus %s\n", key)
	pub := ctx.pubBaseOsStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("unpublishBaseOsStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

// Check the number of baseos and number of actvated
// Also check number of images in this config.
func validateBaseOsConfig(ctx *zedagentContext, config types.BaseOsConfig) error {

	var osCount, activateCount int
	items := ctx.subBaseOsConfig.GetAll()
	for key, c := range items {
		config := cast.CastBaseOsConfig(c)
		if config.Key() != key {
			log.Printf("validateBaseOsConfig(%s) got %s; ignored %+v\n",
				key, config.Key(), config)
			continue
		}
		osCount++
		if config.Activate {
			activateCount++
		}
	}

	// not more than max base os count(2)
	if osCount > MaxBaseOsCount {
		errStr := fmt.Sprintf("baseOs: Unsupported Instance Count %d",
			osCount)
		return errors.New(errStr)
	}

	// can not be more than one activate as true
	if osCount != 0 && activateCount != 1 {
		errStr := fmt.Sprintf("baseOs: Unsupported Activate Count %v\n",
			activateCount)
		return errors.New(errStr)
	}

	imageCount := len(config.StorageConfigList)
	if imageCount > BaseOsImageCount {
		errStr := fmt.Sprintf("baseOs(%s) invalid image count %d",
			config.BaseOsVersion, imageCount)
		return errors.New(errStr)
	}

	return nil
}
