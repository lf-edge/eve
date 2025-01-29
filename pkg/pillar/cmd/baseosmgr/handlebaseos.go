// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// base os event handlers

package baseosmgr

import (
	"fmt"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

// baseOsHandleStatusUpdateUUID find the config based on the UUID,
// and then call baseOsHandleStatusUpdate. Just a convenience function.
func baseOsHandleStatusUpdateUUID(ctx *baseOsMgrContext, id string) {
	log.Functionf("baseOsHandleStatusUpdateUUID for %s", id)
	config := lookupBaseOsConfig(ctx, id)
	if config == nil {
		// assume that this ContentTreeStatus is not for baseOs
		log.Functionf("baseOsHandleStatusUpdateUUID(%s) config not found", id)
		return
	}
	status := lookupBaseOsStatus(ctx, id)
	if status == nil {
		log.Functionf("baseOsHandleStatusUpdateUUID(%s) status not found", id)
		return
	}

	// We want to wait to drain until we're sure we actually have a usable image locally.
	// eve baseos image is downloaded locally, verified, available, and most importantly has been activated
	// before the node downtime/reboot is initiated, see if we need to defer the operation
	if ((status.State == types.LOADED) || (status.State == types.INSTALLED)) && config.Activate && !status.Activated {
		log.Tracef("baseOsHandleStatusUpdateUUID() image just activated id:%s config:%v status:%v state:%s", id, config, status, status.State)
		deferUpdate := shouldDeferForNodeDrain(ctx, id, config, status)
		if deferUpdate {
			return
		}
	}

	// handle the change event for this base os config
	baseOsHandleStatusUpdate(ctx, config, status)
}

// Returns changed; caller needs to publish
func baseOsGetActivationStatus(ctx *baseOsMgrContext,
	status *types.BaseOsStatus) bool {

	log.Functionf("baseOsGetActivationStatus(%s): partitionLabel %s",
		status.BaseOsVersion, status.PartitionLabel)

	changed := false

	// PartitionLabel can be empty here!
	if status.PartitionLabel == "" {
		if status.Activated {
			status.Activated = false
			changed = true
		}
		return changed
	}

	partName := status.PartitionLabel
	partStatus := getZbootStatus(ctx, partName)
	if partStatus == nil {
		if status.Activated {
			status.Activated = false
			changed = true
		}
		return changed
	}

	// some partition specific attributes
	ps := partStatus.PartitionState
	pd := partStatus.PartitionDevname
	if status.PartitionState != ps || status.PartitionDevice != pd {
		status.PartitionState = ps
		status.PartitionDevice = pd
		changed = true
	}
	var act bool
	// for otherPartition, its always false
	if !partStatus.CurrentPartition {
		act = false
	} else {
		// if current Partition, get the status
		curPartState := getPartitionState(ctx, zboot.GetCurrentPartition())
		act = (curPartState == "active")
	}
	if status.Activated != act {
		status.Activated = act
		changed = true
	}
	return changed
}

func baseOsHandleStatusUpdate(ctx *baseOsMgrContext, config *types.BaseOsConfig,
	status *types.BaseOsStatus) {

	uuidStr := config.Key()
	log.Functionf("baseOsHandleStatusUpdate(%s)", uuidStr)

	changed := baseOsGetActivationStatus(ctx, status)

	c := doBaseOsStatusUpdate(ctx, uuidStr, *config, status)
	changed = changed || c

	if changed {
		log.Functionf("baseOsHandleStatusUpdate(%s) for %s, Status changed",
			config.BaseOsVersion, uuidStr)
		publishBaseOsStatus(ctx, status)
	}
}

func doBaseOsStatusUpdate(ctx *baseOsMgrContext, uuidStr string,
	config types.BaseOsConfig, status *types.BaseOsStatus) bool {

	log.Functionf("doBaseOsStatusUpdate(%s) Activate %v for %s",
		config.BaseOsVersion, config.Activate, uuidStr)

	changed := false

	// check if the ContentSha256 and RelativeURL need to be updated
	// we only update to latch it from empty, and if it matches exactly
	cts := lookupContentTreeStatus(ctx, status.ContentTreeUUID)
	log.Functionf("doBaseOsStatusUpdate(%s) ContentTreeStatus %#v", config.BaseOsVersion, cts)
	if cts != nil {
		if cts.HasError() {
			description := cts.ErrorDescription
			description.ErrorEntities = []*types.ErrorEntity{{EntityID: cts.Key(), EntityType: types.ErrorEntityContentTree}}
			status.SetErrorDescription(description)
			return true
		}
		if status.HasError() {
			status.ClearError()
			changed = true
		}
	}

	// XXX status should tell us this since we baseOsGetActivationStatus
	// Are we already running this version? If so nothing to do.
	// Note that we don't return errors if someone tries to deactivate
	// the running version, but we don't act on it either.
	curPartName := zboot.GetCurrentPartition()
	partStatus := getZbootStatus(ctx, curPartName)
	var shortVerCurPart = ""
	if partStatus != nil {
		shortVerCurPart = partStatus.ShortVersion
	}
	if status.BaseOsVersion == shortVerCurPart {
		log.Functionf("doBaseOsStatusUpdate(%s) for %s found in current %s",
			config.BaseOsVersion, uuidStr, curPartName)
		baseOsSetPartitionInfoInStatus(ctx, status, curPartName)
		status.State = types.INSTALLED
		status.Activated = true
		return true
	}

	// Is this already in otherPartName? If so we update status
	// but proceed in case we need to overwrite the partition.
	// Implies re-downloading as opposed to reusing that unused
	// partition; other partition could have failed so safest to
	// re-download and overwrite.
	otherPartName := zboot.GetOtherPartition()
	partStatus = getZbootStatus(ctx, otherPartName)
	var shortVerOtherPart = ""
	if partStatus != nil {
		shortVerOtherPart = partStatus.ShortVersion
	}
	if (status.PartitionLabel == "" || status.PartitionLabel == otherPartName) &&
		status.BaseOsVersion == shortVerOtherPart {
		log.Functionf("doBaseOsStatusUpdate(%s) for %s found in other %s",
			config.BaseOsVersion, uuidStr, otherPartName)
		baseOsSetPartitionInfoInStatus(ctx, status, otherPartName)
		if !config.Activate {
			return true
		}
		// Might be corrupt? XXX should we verify sha? But modified!!
		status.State = types.DOWNLOADED
		status.Activated = false
		changed = true
	}

	c, proceed := doBaseOsInstall(ctx, uuidStr, config, status)
	changed = changed || c
	if !proceed {
		return changed
	}

	if !config.Activate {
		log.Functionf("doBaseOsStatusUpdate(%s) for %s, Activate is not set",
			config.BaseOsVersion, uuidStr)
		if status.Activated {
			c := doBaseOsInactivate(uuidStr, status)
			changed = changed || c
		}
		return changed
	}

	if status.Activated {
		log.Functionf("doBaseOsStatusUpdate(%s) for %s, is already activated",
			config.BaseOsVersion, uuidStr)
		return changed
	}

	c, proceed = validateAndAssignPartition(ctx, config, status)
	changed = changed || c
	if !proceed {
		return changed
	}
	changed = doBaseOsActivate(ctx, uuidStr, config, status)
	log.Functionf("doBaseOsStatusUpdate(%s) done for %s",
		config.BaseOsVersion, uuidStr)
	return changed
}

// Returns changed boolean when the status was changed
func doBaseOsActivate(ctx *baseOsMgrContext, uuidStr string,
	config types.BaseOsConfig, status *types.BaseOsStatus) bool {

	var (
		changed bool
		proceed bool
		err     error
	)
	log.Functionf("doBaseOsActivate(%s) uuid %s",
		config.BaseOsVersion, uuidStr)

	if status.PartitionLabel == "" {
		log.Functionf("doBaseOsActivate(%s) for %s, unassigned partition",
			config.BaseOsVersion, uuidStr)
		return changed
	}

	// Sanity check the partition label of the current root and
	// the partition state

	if !zboot.IsOtherPartition(status.PartitionLabel) {
		return changed
	}
	partStatus := getZbootStatus(ctx, status.PartitionLabel)
	if partStatus == nil {
		log.Functionf("doBaseOsActivate(%s) for %s, partition status %s not found",
			config.BaseOsVersion, uuidStr, status.PartitionLabel)
		return changed
	}
	switch partStatus.PartitionState {
	case "unused":
		log.Functionf("Installing %s over unused",
			config.BaseOsVersion)
	case "inprogress":
		log.Functionf("Installing %s over inprogress",
			config.BaseOsVersion)
	case "updating":
		log.Functionf("Installing %s over updating",
			config.BaseOsVersion)
	default:
		errString := fmt.Sprintf("Wrong partition state %s for %s",
			partStatus.PartitionState, status.PartitionLabel)
		log.Error(errString)
		status.SetErrorNow(errString)
		changed = true
		return changed
	}

	log.Functionf("doBaseOsActivate: %s activating", uuidStr)

	// Before writing to partition lets make sure we have enough space on the partition
	// 1. Get the size of the image using contenttree status
	// 2. Get the size of the partition using zboot
	// 3. If partition size is < image size, error out

	cts := lookupContentTreeStatus(ctx, status.ContentTreeUUID)

	if cts == nil {
		errString := fmt.Sprintf("doBaseOsActivate: ContentTreeStatus not found for %s", status.ContentTreeUUID)
		log.Error(errString)
		status.SetErrorNow(errString)
		changed = true
		return changed
	}

	if cts.State == types.LOADED {
		partSize := zboot.GetPartitionSizeInBytes(status.PartitionLabel)
		imageSize := cts.MaxDownloadSize
		if partSize < imageSize {
			errString := fmt.Sprintf("doBaseOsActivate: Image size %v bytes greater than partition size %v bytes", imageSize, partSize)
			log.Error(errString)
			status.SetErrorNow(errString)
			changed = true
			return changed
		}
	}

	// install the image at proper partition; dd etc
	changed, proceed, err = installDownloadedObjects(ctx, uuidStr, status.PartitionLabel,
		status.ContentTreeUUID)
	if err != nil {
		status.SetErrorNow(err.Error())
		changed = true
		return changed
	}
	if proceed {
		// Update version etc
		updateAndPublishZbootStatus(ctx, status.PartitionLabel, true)
		changed = true
		// Match the version string inside image
		if errString := checkInstalledVersion(ctx, *status); errString != "" {
			log.Error(errString)
			status.SetErrorNow(errString)
			zboot.SetOtherPartitionStateUnused(log)
			updateAndPublishZbootStatus(ctx,
				status.PartitionLabel, false)
			baseOsSetPartitionInfoInStatus(ctx, status,
				status.PartitionLabel)
			publishBaseOsStatus(ctx, status)
			return changed
		}
		zboot.SetOtherPartitionStateUpdating(log)
		// move the state from VERIFIED to INSTALLED
		status.State = types.INSTALLED
		updateAndPublishZbootStatus(ctx,
			status.PartitionLabel, false)
		baseOsSetPartitionInfoInStatus(ctx, status,
			status.PartitionLabel)
		publishBaseOsStatus(ctx, status)
	} else {
		log.Functionf("Waiting for image to be mounted")
		return changed
	}
	return changed
}

func doBaseOsInstall(ctx *baseOsMgrContext, uuidStr string,
	config types.BaseOsConfig, status *types.BaseOsStatus) (bool, bool) {

	log.Functionf("doBaseOsInstall(%s) %s", uuidStr, config.BaseOsVersion)
	changed := false
	proceed := false

	// Check if we should proceed to ask volumemgr
	changed, proceed = validatePartition(ctx, config, status)
	if !proceed {
		return changed, false
	}
	// check for the volume status change
	c, done := checkBaseOsVolumeStatus(ctx, status.Key(),
		config, status)
	changed = changed || c
	if !done {
		log.Functionf(" %s, volume still not done", config.BaseOsVersion)
		return changed, false
	}

	// XXX can we check the version before installing to the partition?
	// XXX requires loopback mounting the image; not part of syscall.Mount
	// Note that we XXX dd as part of the installDownloadedObjects call
	// in doBaseOsActivate
	log.Functionf("doBaseOsInstall(%s), Done", config.BaseOsVersion)
	return changed, true
}

// Prefer to get the published value to reduce use of zboot calls into Linux
func getPartitionState(ctx *baseOsMgrContext, partname string) string {
	partStatus := getZbootStatus(ctx, partname)
	if partStatus != nil {
		return partStatus.PartitionState
	}
	return zboot.GetPartitionState(partname)
}

// Returns changed, proceed as above
func validatePartition(ctx *baseOsMgrContext,
	config types.BaseOsConfig, status *types.BaseOsStatus) (bool, bool) {
	var otherPartVersion string

	log.Functionf("validatePartition(%s) for %s",
		config.Key(), config.BaseOsVersion)
	changed := false
	otherPartName := zboot.GetOtherPartition()
	otherPartStatus := getZbootStatus(ctx, otherPartName)
	if otherPartStatus != nil {
		otherPartVersion = otherPartStatus.ShortVersion
	}
	otherPartState := getPartitionState(ctx, otherPartName)

	// Does the other partition contain a failed update with the same
	// version?
	if otherPartState == "inprogress" &&
		otherPartVersion == config.BaseOsVersion {
		// we are going to quote the same error, while doing baseos
		// upgrade validation.
		// first pick up from the partition
		handleOtherPartRebootReason(ctx, status)
		log.Errorln(status.Error)
		changed = true
		return changed, false
	}
	return changed, true
}

// Assign a free partition label; called when we activate
// Returns changed, proceed as above
func validateAndAssignPartition(ctx *baseOsMgrContext,
	config types.BaseOsConfig, status *types.BaseOsStatus) (bool, bool) {
	var curPartState, curPartVersion string

	log.Functionf("validateAndAssignPartition(%s) for %s",
		config.Key(), config.BaseOsVersion)
	changed := false
	proceed := false
	curPartName := zboot.GetCurrentPartition()
	otherPartName := zboot.GetOtherPartition()
	curPartStatus := getZbootStatus(ctx, curPartName)
	otherPartStatus := getZbootStatus(ctx, otherPartName)
	if curPartStatus != nil {
		curPartVersion = curPartStatus.ShortVersion
		curPartState = curPartStatus.PartitionState
	}
	otherPartState := getPartitionState(ctx, otherPartName)
	if curPartState == "inprogress" || otherPartState == "active" {
		// Must still be testing the current version; don't overwrite
		// fallback
		// If there is no change to the other we don't log error
		// but still retry later
		status.TooEarly = true
		log.Errorf("Attempt to install baseOs update %s while testing is in progress for %s: deferred",
			config.BaseOsVersion, curPartVersion)

		changed = true
		return changed, proceed
	}

	// XXX should we check that this is the only one marked as Activate?
	// XXX or check that other isn't marked as updating?
	if config.Activate && status.PartitionLabel == "" {
		log.Functionf("validateAndAssignPartition(%s) assigning with partition %s",
			config.BaseOsVersion, otherPartName)
		status.PartitionLabel = otherPartName
		status.PartitionState = otherPartStatus.PartitionState
		status.PartitionDevice = otherPartStatus.PartitionDevname
		changed = true
	}
	proceed = true
	return changed, proceed
}

func checkBaseOsVolumeStatus(ctx *baseOsMgrContext, uuidStr string,
	config types.BaseOsConfig,
	status *types.BaseOsStatus) (bool, bool) {

	log.Functionf("checkBaseOsVolumeStatus(%s) for %s",
		config.BaseOsVersion, uuidStr)
	ret := checkContentTreeStatus(ctx, status.State, status.ContentTreeUUID)

	status.State = ret.MinState

	if ret.AllErrors != "" {
		status.SetError(ret.AllErrors, ret.ErrorTime)
		log.Errorf("checkBaseOsVolumeStatus(%s) for %s, volumemgr error at %v: %v",
			config.BaseOsVersion, uuidStr, status.ErrorTime, status.Error)
		return ret.Changed, false
	}

	if ret.MinState < types.LOADED {
		log.Functionf("checkBaseOsVolumeStatus(%s) for %s, Waiting for volumemgr",
			config.BaseOsVersion, uuidStr)
		return ret.Changed, false
	}
	log.Functionf("checkBaseOsVolumeStatus(%s) for %s, done",
		config.BaseOsVersion, uuidStr)
	return ret.Changed, true
}

func removeBaseOsConfig(ctx *baseOsMgrContext, uuidStr string) {

	log.Functionf("removeBaseOsConfig for %s", uuidStr)
	removeBaseOsStatus(ctx, uuidStr)
	log.Functionf("removeBaseOSConfig for %s, done", uuidStr)
}

func removeBaseOsStatus(ctx *baseOsMgrContext, uuidStr string) {

	log.Functionf("removeBaseOsStatus for %s", uuidStr)
	status := lookupBaseOsStatus(ctx, uuidStr)
	if status == nil {
		log.Functionf("removeBaseOsStatus: no status")
		return
	}

	changed, del := doBaseOsRemove(ctx, uuidStr, status)
	if changed {
		log.Functionf("removeBaseOsStatus for %s, Status change", uuidStr)
		publishBaseOsStatus(ctx, status)
	}

	if del {
		log.Functionf("removeBaseOsStatus %s, Deleting", uuidStr)

		// Write out what we modified to BaseOsStatus aka delete
		unpublishBaseOsStatus(ctx, status.Key())
	}
	log.Functionf("removeBaseOsStatus %s, Done", uuidStr)
}

func doBaseOsRemove(ctx *baseOsMgrContext, uuidStr string,
	status *types.BaseOsStatus) (bool, bool) {

	log.Functionf("doBaseOsRemove(%s) for %s", status.BaseOsVersion, uuidStr)

	changed := false
	del := false

	changed = doBaseOsInactivate(uuidStr, status)

	changed, del = doBaseOsUninstall(ctx, uuidStr, status)

	log.Functionf("doBaseOsRemove(%s) for %s, Done",
		status.BaseOsVersion, uuidStr)
	return changed, del
}

func doBaseOsInactivate(uuidStr string, status *types.BaseOsStatus) bool {
	log.Functionf("doBaseOsInactivate(%s) %v",
		status.BaseOsVersion, status.Activated)

	// nothing to be done, flip will happen on reboot
	return true
}

func doBaseOsUninstall(ctx *baseOsMgrContext, uuidStr string,
	status *types.BaseOsStatus) (bool, bool) {

	log.Functionf("doBaseOsUninstall(%s) for %s",
		status.BaseOsVersion, uuidStr)

	del := false
	changed := false
	removedAll := true

	// In case this was a failed update we make sure we mark
	// that !active partition as unused (in case it is inprogress),
	// so that we can retry the same update.
	if status.PartitionLabel != "" {
		partName := status.PartitionLabel
		partStatus := getZbootStatus(ctx, partName)
		if partStatus == nil {
			log.Functionf("doBaseOsUninstall(%s) for %s, partitionStatus not found",
				status.BaseOsVersion, uuidStr)
			return changed, del
		}
		if status.BaseOsVersion == partStatus.ShortVersion &&
			!partStatus.CurrentPartition {
			log.Functionf("doBaseOsUninstall(%s) for %s, currently on other %s",
				status.BaseOsVersion, uuidStr, partName)
			curPartState := getPartitionState(ctx,
				zboot.GetCurrentPartition())
			if curPartState == "active" {
				log.Functionf("Mark other partition %s, unused", partName)
				zboot.SetOtherPartitionStateUnused(log)
				updateAndPublishZbootStatus(ctx,
					status.PartitionLabel, false)
				baseOsSetPartitionInfoInStatus(ctx, status,
					status.PartitionLabel)
				publishBaseOsStatus(ctx, status)
			} else {
				log.Warnf("Not mark other partition %s unused since curpart is %s",
					partName, curPartState)
			}
		}
		status.PartitionLabel = ""
		changed = true
	}

	contentStatus := lookupContentTreeStatus(ctx, status.ContentTreeUUID)
	if contentStatus != nil {
		log.Functionf("doBaseOsUninstall(%s) for %s, Content %s not yet gone;",
			status.BaseOsVersion, uuidStr, status.ContentTreeUUID)
		removedAll = false
	}

	if !removedAll {
		log.Functionf("doBaseOsUninstall(%s) for %s, Waiting for volumemgr purge",
			status.BaseOsVersion, uuidStr)
		return changed, del
	}

	del = true
	log.Functionf("doBaseOsUninstall(%s), Done", status.BaseOsVersion)
	return changed, del
}

// validate whether the image version matches with
// config version string
func checkInstalledVersion(ctx *baseOsMgrContext, status types.BaseOsStatus) string {

	log.Functionf("checkInstalledVersion(%s) %s %s",
		status.Key(), status.PartitionLabel,
		status.BaseOsVersion)

	if status.PartitionLabel == "" {
		errStr := fmt.Sprintf("checkInstalledVersion(%s) invalid partition", status.BaseOsVersion)
		log.Errorln(errStr)
		return errStr
	}

	// Check the configured Image name is the same as the one just installed image
	partStatus := getZbootStatus(ctx, status.PartitionLabel)
	var shortVer = ""
	if partStatus != nil {
		shortVer = partStatus.ShortVersion
	}
	log.Functionf("checkInstalledVersion: Cfg baseVer %s, Image shortVer %s",
		status.BaseOsVersion, shortVer)
	if status.BaseOsVersion != shortVer {
		errString := fmt.Sprintf("checkInstalledVersion: image name not match. config %s, image ver %s\n",
			status.BaseOsVersion, shortVer)
		return errString
	}
	return ""
}

func lookupBaseOsStatusesByContentID(ctx *baseOsMgrContext, contentID string) []*types.BaseOsStatus {

	var statuses []*types.BaseOsStatus
	sub := ctx.pubBaseOsStatus
	sts := sub.GetAll()
	for _, el := range sts {
		status := el.(types.BaseOsStatus)
		if status.ContentTreeUUID == contentID {
			statuses = append(statuses, &status)
		}
	}
	if len(statuses) == 0 {
		log.Functionf("lookupBaseOsStatusesByContentID(%s) not found", contentID)
	}
	return statuses
}

func lookupBaseOsConfig(ctx *baseOsMgrContext, key string) *types.BaseOsConfig {

	sub := ctx.subBaseOsConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Functionf("lookupBaseOsConfig(%s) not found", key)
		return nil
	}
	config := c.(types.BaseOsConfig)
	return &config
}

func lookupBaseOsStatus(ctx *baseOsMgrContext, key string) *types.BaseOsStatus {
	pub := ctx.pubBaseOsStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Functionf("lookupBaseOsStatus(%s) not found", key)
		return nil
	}
	status := st.(types.BaseOsStatus)
	return &status
}

func lookupBaseOsStatusByPartLabel(ctx *baseOsMgrContext, partLabel string) *types.BaseOsStatus {
	pub := ctx.pubBaseOsStatus
	st, _ := pub.Get(partLabel)
	if st == nil {
		log.Functionf("lookupBaseOsStatusByPartLabel(%s) not found", partLabel)
		return nil
	}
	status := st.(types.BaseOsStatus)
	if status.Key() != partLabel {
		log.Errorf("lookupBaseOsStatus(%s) got %s; ignored %+v",
			partLabel, status.Key(), status)
		return nil
	}
	return &status
}

func publishBaseOsStatus(ctx *baseOsMgrContext, status *types.BaseOsStatus) {

	key := status.Key()
	log.Tracef("Publishing BaseOsStatus %s", key)
	pub := ctx.pubBaseOsStatus
	pub.Publish(key, *status)
}

func unpublishBaseOsStatus(ctx *baseOsMgrContext, key string) {

	log.Tracef("Unpublishing BaseOsStatus %s", key)
	pub := ctx.pubBaseOsStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishBaseOsStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

// Check content tree provided in this config
func validateBaseOsConfig(_ *baseOsMgrContext, config types.BaseOsConfig) error {
	if config.ContentTreeUUID == "" {
		return fmt.Errorf("baseOs(%s) empty ContentTreeUUID",
			config.BaseOsVersion)
	}

	return nil
}

func handleZbootTestComplete(ctx *baseOsMgrContext, config types.ZbootConfig,
	status types.ZbootStatus) {

	log.Functionf("handleZbootTestComplete(%s)", config.Key())
	if config.TestComplete == status.TestComplete {
		// nothing to do
		log.Functionf("handleZbootTestComplete(%s) nothing to do",
			config.Key())
		return
	}
	if config.TestComplete {
		curPart := zboot.GetCurrentPartition()
		if curPart != config.Key() {
			log.Functionf("handleZbootTestComplete(%s) not current partition; current %s",
				config.Key(), curPart)
			return
		}
		curPartState := getPartitionState(ctx, curPart)
		if curPartState != "inprogress" {
			log.Warnf("handleZbootTestComplete(%s) not Inprogress",
				config.Key())
			return
		}
		if err := zboot.MarkCurrentPartitionStateActive(log); err != nil {
			bs := lookupBaseOsStatusByPartLabel(ctx, config.Key())
			if bs == nil {
				log.Errorf("handleZbootTestComplete(%s) error by not BaseOsStatus in which to report it: %s",
					config.Key(), err)
				return
			}
			bs.SetErrorNow(err.Error())
			// Need partition update from zboot?
			publishBaseOsStatus(ctx, bs)
			// publish the updated partition information
			updateAndPublishZbootStatusAll(ctx)
			log.Functionf("handleZbootTestComplete(%s) to True failed",
				config.Key())
			return
		}
		status.TestComplete = true
		publishZbootStatus(ctx, status)

		// XXX duplicate? Need to do the BaseOs presumably
		// publish the updated partition information
		updateAndPublishZbootStatusAll(ctx)
		updateAndPublishBaseOsStatusAll(ctx)

		// Check if we have a failed update which needs a kick
		maybeRetryInstall(ctx)

		//sync currentUpdateRetry
		handleUpdateRetryCounter(ctx, ctx.configUpdateRetry)

		log.Functionf("handleZbootTestComplete(%s) to True done",
			config.Key())
		return
	}

	// completed state transition, mark TestComplete as false
	log.Functionf("handleZbootTestComplete(%s) to False done", config.Key())
	status.TestComplete = false
	publishZbootStatus(ctx, status)
	updateAndPublishBaseOsStatusAll(ctx)
}

func updateAndPublishBaseOsStatusAll(ctx *baseOsMgrContext) {
	pub := ctx.pubBaseOsStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.BaseOsStatus)
		if status.PartitionLabel == "" {
			continue
		}
		baseOsSetPartitionInfoInStatus(ctx, &status, status.PartitionLabel)
		publishBaseOsStatus(ctx, &status)
	}
}

func maybeRetryInstall(ctx *baseOsMgrContext) {
	pub := ctx.pubBaseOsStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.BaseOsStatus)
		if !status.TooEarly {
			log.Functionf("maybeRetryInstall(%s) skipped",
				status.Key())
			continue
		}
		config := lookupBaseOsConfig(ctx, status.Key())
		if config == nil {
			log.Functionf("maybeRetryInstall(%s) no config",
				status.Key())
			continue
		}

		log.Functionf("maybeRetryInstall(%s) redoing after %s %v",
			status.Key(), status.Error, status.ErrorTime)
		status.TooEarly = false
		status.ClearError()
		baseOsHandleStatusUpdate(ctx, config, &status)
	}
}

func baseOsSetPartitionInfoInStatus(ctx *baseOsMgrContext, status *types.BaseOsStatus, partName string) {

	partStatus := getZbootStatus(ctx, partName)
	if partStatus != nil {
		log.Functionf("baseOsSetPartitionInfoInStatus(%s) %s found %+v",
			status.Key(), partName, partStatus)
		status.PartitionLabel = partName
		status.PartitionState = partStatus.PartitionState
		status.PartitionDevice = partStatus.PartitionDevname
	}
}

// updateAndPublishZbootStatusAll checks if the status exists
// and if so updates the current and state. Otherwise it creates from
// scratch
func updateAndPublishZbootStatusAll(ctx *baseOsMgrContext) {
	log.Functionf("updateAndPublishZbootStatusAll")
	partitionNames := []string{"IMGA", "IMGB"}
	for _, partName := range partitionNames {
		status := getZbootStatus(ctx, partName)
		if status == nil {
			status = createZbootStatus(ctx, partName)
		} else {
			status.PartitionState = zboot.GetPartitionState(partName)
			status.CurrentPartition = zboot.IsCurrentPartition(partName)
		}
		publishZbootStatus(ctx, *status)
	}
	syscall.Sync()
}

func createZbootStatus(ctx *baseOsMgrContext, partName string) *types.ZbootStatus {
	var err error
	partName = strings.TrimSpace(partName)
	if !isValidBaseOsPartitionLabel(partName) {
		return nil
	}
	testComplete := false
	status := types.ZbootStatus{}
	status.PartitionLabel = partName
	status.PartitionDevname = zboot.GetPartitionDevname(partName)
	status.PartitionState = zboot.GetPartitionState(partName)
	status.ShortVersion, err = zboot.GetShortVersion(log, partName)
	if err != nil {
		log.Errorln(err)
	}
	status.LongVersion = zboot.GetLongVersion(partName)
	status.CurrentPartition = zboot.IsCurrentPartition(partName)
	status.TestComplete = testComplete
	return &status
}

// Updates current and partitionstate by default. If updateVersions
// is set the version strings are also updated.
func updateAndPublishZbootStatus(ctx *baseOsMgrContext, partName string, updateVersions bool) {
	if !isValidBaseOsPartitionLabel(partName) {
		log.Errorf("Invalid partname %s", partName)
		return
	}
	status := getZbootStatus(ctx, partName)
	if status == nil {
		log.Errorf("no ZbootStatus for partname %s", partName)
		return
	}
	status.PartitionState = zboot.GetPartitionState(partName)
	status.CurrentPartition = zboot.IsCurrentPartition(partName)
	if updateVersions {
		short, err := zboot.GetShortVersion(log, partName)
		if err != nil {
			log.Errorln(err)
		} else {
			status.ShortVersion = short
		}
		status.LongVersion = zboot.GetLongVersion(partName)
	}
	publishZbootStatus(ctx, *status)
}

func publishZbootStatus(ctx *baseOsMgrContext, status types.ZbootStatus) {

	pub := ctx.pubZbootStatus
	pub.Publish(status.PartitionLabel, status)
	syscall.Sync()
}

func getZbootStatus(ctx *baseOsMgrContext, partName string) *types.ZbootStatus {
	partName = strings.TrimSpace(partName)
	if !isValidBaseOsPartitionLabel(partName) {
		return nil
	}
	pub := ctx.pubZbootStatus
	st, err := pub.Get(partName)
	if err != nil {
		log.Errorf("getZbootStatus(%s) not found", partName)
		return nil
	}
	status := st.(types.ZbootStatus)
	return &status
}

func isValidBaseOsPartitionLabel(name string) bool {
	partitionNames := []string{"IMGA", "IMGB"}
	name = strings.TrimSpace(name)
	for _, partName := range partitionNames {
		if name == partName {
			return true
		}
	}
	return false
}

// only thing to do is to look at the other partition and update
// error status into the baseos status
func updateBaseOsStatusOnReboot(ctxPtr *baseOsMgrContext) {
	partName := zboot.GetOtherPartition()
	partStatus := getZbootStatus(ctxPtr, partName)
	if partStatus != nil &&
		partStatus.PartitionState == "inprogress" {
		status := lookupBaseOsStatusByPartLabel(ctxPtr, partName)
		if status != nil &&
			status.BaseOsVersion == partStatus.ShortVersion {
			handleOtherPartRebootReason(ctxPtr, status)
			publishBaseOsStatus(ctxPtr, status)
		}
	}
}

// Assumes the callers verify that the other partition is "inprogress" which means
// we most recently booted that partition.
func handleOtherPartRebootReason(ctxPtr *baseOsMgrContext, status *types.BaseOsStatus) {
	curPart := zboot.GetCurrentPartition()
	if curPart == ctxPtr.rebootImage {
		return
	}
	if ctxPtr.rebootReason != "" {
		status.SetError(ctxPtr.rebootReason, ctxPtr.rebootTime)
	} else {
		dateStr := ctxPtr.rebootTime.Format(time.RFC3339Nano)
		reason := fmt.Sprintf("Unknown reboot reason - power failure or crash - at %s\n",
			dateStr)
		status.SetError(reason, ctxPtr.rebootTime)
	}
}

// isImageInErrorState returns true if we try to update to not-active image without success
// also returns ZbootStatus
func isImageInErrorState(ctxPtr *baseOsMgrContext) (bool, *types.ZbootStatus) {
	curPartName := zboot.GetCurrentPartition()
	partStatus := getZbootStatus(ctxPtr, curPartName)
	if partStatus == nil {
		log.Functionf("No current partition status for %s", curPartName)
		return false, nil
	}
	if partStatus.PartitionState != "active" {
		log.Functionf("Current partition status for %s is not active: %s",
			curPartName, partStatus.PartitionState)
		return false, nil
	}
	otherPartName := zboot.GetOtherPartition()
	partStatus = getZbootStatus(ctxPtr, otherPartName)
	if partStatus == nil {
		log.Functionf("No other partition status for %s",
			otherPartName)
		return false, nil
	}
	shortVerOtherPart := partStatus.ShortVersion
	if shortVerOtherPart == "" {
		log.Functionf("Other partition has no version")
		return false, partStatus
	}
	if partStatus.PartitionState != "inprogress" {
		log.Functionf("Other partition state %s not inprogress",
			partStatus.PartitionState)
		return false, partStatus
	}
	baseOSConfig := lookupBaseOsConfigByVersion(ctxPtr, shortVerOtherPart)
	if baseOSConfig == nil {
		log.Functionf("Cannot found BaseOsConfig with %s version; ignoring RetryUpdateCounter",
			shortVerOtherPart)
		return false, partStatus
	}
	if !baseOSConfig.Activate {
		log.Functionf("BaseOsConfig %s has no activate; ignoring RetryUpdateCounter", baseOSConfig.Key())
		return false, partStatus
	}
	return true, partStatus
}

// handleUpdateRetryCounter checks
// if current partition is not active: just update configUpdateRetry
// if other partition is in failed state: if retryUpdateCounter changed: save current counters and initiate re-update
// in other case update configUpdateRetry and currentUpdateRetry, save them and publish
func handleUpdateRetryCounter(ctxPtr *baseOsMgrContext, retryUpdateCounter uint32) {
	curPartName := zboot.GetCurrentPartition()
	partStatus := getZbootStatus(ctxPtr, curPartName)
	if partStatus == nil {
		log.Warnf("handleUpdateRetryCounter: No current partition status for %s; failed RetryUpdateCounter",
			curPartName)
		return
	}
	if partStatus.PartitionState != "active" {
		if ctxPtr.configUpdateRetry == retryUpdateCounter {
			log.Functionf("No change in retryUpdateCounter: %d", retryUpdateCounter)
			return
		}
		log.Noticef("handleUpdateRetryCounter: configUpdateRetry changed "+
			"with no active partition: %d to %d; ignoring it",
			ctxPtr.configUpdateRetry, retryUpdateCounter)
		return
	}
	if failed, failedPartStatus := isImageInErrorState(ctxPtr); failed {
		if ctxPtr.configUpdateRetry == retryUpdateCounter {
			log.Functionf("No change in retryUpdateCounter: %d", retryUpdateCounter)
			return
		}
		log.Noticef("handleUpdateRetryCounter: configUpdateRetry change: %d to %d",
			ctxPtr.configUpdateRetry, retryUpdateCounter)
		ctxPtr.configUpdateRetry = retryUpdateCounter
		// save it to avoid loop of re-upgrade - failing - re-upgrade
		saveConfigRetryUpdateCounter(ctxPtr)
		log.Noticef("UpdateRetry from %s to %s",
			partStatus.ShortVersion, failedPartStatus.ShortVersion)
		zboot.SetOtherPartitionStateUpdating(log)
		updateAndPublishZbootStatus(ctxPtr, failedPartStatus.PartitionLabel, false)
		baseOsStatus := lookupBaseOsStatusByPartLabel(ctxPtr, failedPartStatus.PartitionLabel)
		if baseOsStatus != nil {
			baseOsSetPartitionInfoInStatus(ctxPtr, baseOsStatus, failedPartStatus.PartitionLabel)
			publishBaseOsStatus(ctxPtr, baseOsStatus)
		}
		return
	}
	if ctxPtr.configUpdateRetry != retryUpdateCounter {
		log.Noticef("handleUpdateRetryCounter: configUpdateRetry change: %d to %d",
			ctxPtr.configUpdateRetry, retryUpdateCounter)
		ctxPtr.configUpdateRetry = retryUpdateCounter
		saveConfigRetryUpdateCounter(ctxPtr)
	}
	if ctxPtr.currentUpdateRetry != retryUpdateCounter {
		log.Noticef("handleUpdateRetryCounter: currentUpdateRetry change: %d to %d",
			ctxPtr.currentUpdateRetry, retryUpdateCounter)
		ctxPtr.currentUpdateRetry = retryUpdateCounter
		saveCurrentRetryUpdateCounter(ctxPtr)
	}
	publishBaseOSMgrStatus(ctxPtr)
}

func lookupBaseOsConfigByVersion(ctxPtr *baseOsMgrContext, shortVersion string) *types.BaseOsConfig {
	sub := ctxPtr.subBaseOsConfig
	items := sub.GetAll()
	for _, cfg := range items {
		baseOSConfig := cfg.(types.BaseOsConfig)
		if baseOSConfig.BaseOsVersion == shortVersion {
			return &baseOSConfig
		}
	}
	return nil
}

func saveCurrentRetryUpdateCounter(ctxPtr *baseOsMgrContext) {
	log.Functionf("saveCurrentRetryUpdateCounter (%s) - counter: %d",
		currentRetryUpdateCounterFile, ctxPtr.currentUpdateRetry)
	err := fileutils.WriteRename(currentRetryUpdateCounterFile,
		[]byte(fmt.Sprintf("%d", ctxPtr.currentUpdateRetry)))
	if err != nil {
		log.Errorf("saveCurrentRetryUpdateCounter write to %s: %s", currentRetryUpdateCounterFile, err)
	}
}

func saveConfigRetryUpdateCounter(ctxPtr *baseOsMgrContext) {
	log.Functionf("saveConfigRetryUpdateCounter (%s) - counter: %d",
		configRetryUpdateCounterFile, ctxPtr.configUpdateRetry)
	err := fileutils.WriteRename(configRetryUpdateCounterFile,
		[]byte(fmt.Sprintf("%d", ctxPtr.configUpdateRetry)))
	if err != nil {
		log.Errorf("saveConfigRetryUpdateCounter write to %s: %s", configRetryUpdateCounterFile, err)
	}
}

func readSavedConfigRetryUpdateCounter() uint32 {
	fileName := configRetryUpdateCounterFile
	log.Tracef("readSavedConfigRetryUpdateCounter - reading %s", fileName)
	counter, _ := fileutils.ReadSavedCounter(log, fileName)
	return counter
}

func readSavedCurrentRetryUpdateCounter() uint32 {
	fileName := currentRetryUpdateCounterFile
	log.Tracef("readSavedCurrentRetryUpdateCounter - reading %s", fileName)
	counter, _ := fileutils.ReadSavedCounter(log, fileName)
	return counter
}
