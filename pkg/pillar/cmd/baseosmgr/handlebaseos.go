// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// base os event handlers

package baseosmgr

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	uuid "github.com/satori/go.uuid"
)

const (
	BaseOsImageCount     = 1
	LastImageVersionFile = types.PersistStatusDir + "/last-image-version"
)

func lookupBaseOsImageSha(ctx *baseOsMgrContext, imageSha string) *types.BaseOsConfig {
	items := ctx.subBaseOsConfig.GetAll()
	for _, c := range items {
		config := c.(types.BaseOsConfig)
		for _, ctc := range config.ContentTreeConfigList {
			if ctc.ContentSha256 == imageSha {
				return &config
			}
		}
	}
	return nil
}

func baseOsHandleStatusUpdateImageSha(ctx *baseOsMgrContext, imageSha string) {

	log.Infof("baseOsHandleStatusUpdateImageSha for %s", imageSha)
	config := lookupBaseOsImageSha(ctx, imageSha)
	if config == nil {
		log.Infof("baseOsHandleStatusUpdateImageSha(%s) not found",
			imageSha)
		return
	}
	uuidStr := config.Key()
	status := lookupBaseOsStatus(ctx, uuidStr)
	if status == nil {
		log.Infof("baseOsHandleStatusUpdateImageSha(%s) no status",
			imageSha)
		return
	}
	log.Infof("baseOsHandleStatusUpdateImageSha(%s) found %s",
		imageSha, uuidStr)

	// handle the change event for this base os config
	baseOsHandleStatusUpdate(ctx, config, status)
}

// Returns changed; caller needs to publish
func baseOsGetActivationStatus(ctx *baseOsMgrContext,
	status *types.BaseOsStatus) bool {

	log.Infof("baseOsGetActivationStatus(%s): partitionLabel %s",
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
	log.Infof("baseOsHandleStatusUpdate(%s)", uuidStr)

	changed := baseOsGetActivationStatus(ctx, status)

	c := doBaseOsStatusUpdate(ctx, uuidStr, *config, status)
	changed = changed || c

	if changed {
		log.Infof("baseOsHandleStatusUpdate(%s) for %s, Status changed",
			config.BaseOsVersion, uuidStr)
		publishBaseOsStatus(ctx, status)
	}
}

func doBaseOsStatusUpdate(ctx *baseOsMgrContext, uuidStr string,
	config types.BaseOsConfig, status *types.BaseOsStatus) bool {

	log.Infof("doBaseOsStatusUpdate(%s) Activate %v for %s",
		config.BaseOsVersion, config.Activate, uuidStr)

	changed := false

	// XXX status should tell us this since we baseOsGetActivationStatus
	// Are we already running this version? If so nothing to do.
	// Note that we don't return errors if someone tries to deactivate
	// the running version, but we don't act on it either.
	curPartName := zboot.GetCurrentPartition()
	shortVerCurPart, err := zboot.GetShortVersion(log, curPartName)
	if err != nil {
		log.Errorln(err)
	}
	if status.BaseOsVersion == shortVerCurPart {
		log.Infof("doBaseOsStatusUpdate(%s) for %s found in current %s",
			config.BaseOsVersion, uuidStr, curPartName)
		baseOsSetPartitionInfoInStatus(ctx, status, curPartName)
		setProgressDone(status, types.INSTALLED)
		status.Activated = true
		return true
	}

	// Is this already in otherPartName? If so we update status
	// but proceed in case we need to overwrite the partition.
	// Implies re-downloading as opposed to reusing that unused
	// partition; other partition could have failed so safest to
	// re-download and overwrite.
	otherPartName := zboot.GetOtherPartition()
	shortVerOtherPart, err := zboot.GetShortVersion(log, otherPartName)
	if err != nil {
		log.Errorln(err)
	}
	if (status.PartitionLabel == "" || status.PartitionLabel == otherPartName) &&
		status.BaseOsVersion == shortVerOtherPart {
		log.Infof("doBaseOsStatusUpdate(%s) for %s found in other %s",
			config.BaseOsVersion, uuidStr, otherPartName)
		baseOsSetPartitionInfoInStatus(ctx, status, otherPartName)
		if !config.Activate {
			return true
		}
		// Might be corrupt? XXX should we verify sha? But modified!!
		setProgressDone(status, types.DOWNLOADED)
		status.Activated = false
		changed = true
	}

	c, proceed := doBaseOsInstall(ctx, uuidStr, config, status)
	changed = changed || c
	if !proceed {
		return changed
	}

	if !config.Activate {
		log.Infof("doBaseOsStatusUpdate(%s) for %s, Activate is not set",
			config.BaseOsVersion, uuidStr)
		if status.Activated {
			c := doBaseOsInactivate(uuidStr, status)
			changed = changed || c
		}
		return changed
	}

	if status.Activated {
		log.Infof("doBaseOsStatusUpdate(%s) for %s, is already activated",
			config.BaseOsVersion, uuidStr)
		return changed
	}

	c, proceed = validateAndAssignPartition(ctx, config, status)
	changed = changed || c
	if !proceed {
		return changed
	}
	changed = doBaseOsActivate(ctx, uuidStr, config, status)
	log.Infof("doBaseOsStatusUpdate(%s) done for %s",
		config.BaseOsVersion, uuidStr)
	return changed
}

func setProgressDone(status *types.BaseOsStatus, state types.SwState) {
	status.State = state
	for i := range status.ContentTreeStatusList {
		cts := &status.ContentTreeStatusList[i]
		cts.Progress = 100
		cts.State = state
	}
}

// Returns changed boolean when the status was changed
func doBaseOsActivate(ctx *baseOsMgrContext, uuidStr string,
	config types.BaseOsConfig, status *types.BaseOsStatus) bool {

	var (
		changed bool
		proceed bool
		err     error
	)
	log.Infof("doBaseOsActivate(%s) uuid %s",
		config.BaseOsVersion, uuidStr)

	if status.PartitionLabel == "" {
		log.Infof("doBaseOsActivate(%s) for %s, unassigned partition",
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
		log.Infof("doBaseOsActivate(%s) for %s, partition status %s not found",
			config.BaseOsVersion, uuidStr, status.PartitionLabel)
		return changed
	}
	switch partStatus.PartitionState {
	case "unused":
		log.Infof("Installing %s over unused",
			config.BaseOsVersion)
	case "inprogress":
		agentlog.DiscardOtherRebootReason(log)
		log.Infof("Installing %s over inprogress",
			config.BaseOsVersion)
	case "updating":
		log.Infof("Installing %s over updating",
			config.BaseOsVersion)
	default:
		errString := fmt.Sprintf("Wrong partition state %s for %s",
			partStatus.PartitionState, status.PartitionLabel)
		log.Error(errString)
		status.SetErrorNow(errString)
		changed = true
		return changed
	}

	log.Infof("doBaseOsActivate: %s activating", uuidStr)

	// install the image at proper partition; dd etc
	changed, proceed, err = installDownloadedObjects(ctx, uuidStr, status.PartitionLabel,
		&status.ContentTreeStatusList)
	if err != nil {
		status.SetErrorNow(err.Error())
		changed = true
		return changed
	}
	if proceed {
		changed = true
		// Match the version string inside image
		if errString := checkInstalledVersion(ctx, *status); errString != "" {
			log.Error(errString)
			status.SetErrorNow(errString)
			zboot.SetOtherPartitionStateUnused(log)
			publishZbootPartitionStatus(ctx,
				status.PartitionLabel)
			baseOsSetPartitionInfoInStatus(ctx, status,
				status.PartitionLabel)
			publishBaseOsStatus(ctx, status)
			return changed
		}
		zboot.SetOtherPartitionStateUpdating(log)
		// move the state from VERIFIED to INSTALLED
		setProgressDone(status, types.INSTALLED)
		publishZbootPartitionStatus(ctx, status.PartitionLabel)
		baseOsSetPartitionInfoInStatus(ctx, status,
			status.PartitionLabel)
		publishBaseOsStatus(ctx, status)
	} else {
		log.Infof("Waiting for image to be mounted")
		return changed
	}

	// Remove any old log files for a previous instance
	logdir := fmt.Sprintf("%s/%s/log", types.PersistDir,
		status.PartitionLabel)
	log.Infof("Clearing old logs in %s", logdir)
	// Clear content but not directory since logmanager expects dir
	if err := removeContent(logdir); err != nil {
		log.Errorln(err)
	}

	// if it is installed, flip the activated status
	if status.State == types.INSTALLED && !status.Reboot {
		// trigger, zedagent to start reboot process
		status.Reboot = true
		changed = true
	}

	return changed
}

func removeContent(dirName string) error {
	locations, err := ioutil.ReadDir(dirName)
	if err != nil {
		return err
	}

	for _, location := range locations {
		filelocation := dirName + "/" + location.Name()
		err := os.RemoveAll(filelocation)
		if err != nil {
			return err
		}
	}
	return nil
}

func doBaseOsInstall(ctx *baseOsMgrContext, uuidStr string,
	config types.BaseOsConfig, status *types.BaseOsStatus) (bool, bool) {

	log.Infof("doBaseOsInstall(%s) %s", uuidStr, config.BaseOsVersion)
	changed := false
	proceed := false

	for i, ctc := range config.ContentTreeConfigList {
		cts := &status.ContentTreeStatusList[i]
		if cts.RelativeURL != ctc.RelativeURL || !uuid.Equal(cts.ContentID, ctc.ContentID) {
			// Report to zedcloud
			errString := fmt.Sprintf("%s, for %s, Content tree config mismatch:\n\t%s\n\t%s\n\t%s\n\t%s\n\n", uuidStr,
				config.BaseOsVersion,
				ctc.RelativeURL, cts.RelativeURL,
				ctc.ContentID, cts.ContentID)
			log.Error(errString)
			status.SetErrorNow(errString)
			changed = true
			return changed, proceed
		}
	}

	// Check if we should proceed to ask volumemgr
	changed, proceed = validatePartition(ctx, config, status)
	if !proceed {
		return changed, false
	}
	// check for the volume status change
	c, done := checkBaseOsVolumeStatus(ctx, status.UUIDandVersion.UUID,
		config, status)
	changed = changed || c
	if !done {
		log.Infof(" %s, volume still not done", config.BaseOsVersion)
		return changed, false
	}

	// XXX can we check the version before installing to the partition?
	// XXX requires loopback mounting the image; not part of syscall.Mount
	// Note that we dd as part of the installDownloadedObjects call
	// in doBaseOsActivate
	log.Infof("doBaseOsInstall(%s), Done", config.BaseOsVersion)
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

	log.Infof("validatePartition(%s) for %s",
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
	var curPartState, curPartVersion, otherPartVersion string

	log.Infof("validateAndAssignPartition(%s) for %s",
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
	if otherPartStatus != nil {
		otherPartVersion = otherPartStatus.ShortVersion
	}
	otherPartState := getPartitionState(ctx, otherPartName)
	if curPartState == "inprogress" || otherPartState == "active" {
		// Must still be testing the current version; don't overwrite
		// fallback
		// If there is no change to the other we don't log error
		// but still retry later
		status.TooEarly = true
		errStr := fmt.Sprintf("Attempt to install baseOs update %s while testing is in progress for %s: deferred",
			config.BaseOsVersion, curPartVersion)
		if otherPartVersion == config.BaseOsVersion {
			log.Infoln(errStr)
		} else {
			log.Error(errStr)
			status.SetErrorNow(errStr)
		}
		changed = true
		return changed, proceed
	}

	// XXX should we check that this is the only one marked as Activate?
	// XXX or check that other isn't marked as updating?
	if config.Activate && status.PartitionLabel == "" {
		log.Infof("validateAndAssignPartition(%s) assigning with partition %s",
			config.BaseOsVersion, otherPartName)
		status.PartitionLabel = otherPartName
		status.PartitionState = otherPartStatus.PartitionState
		status.PartitionDevice = otherPartStatus.PartitionDevname
		changed = true
	}
	proceed = true
	return changed, proceed
}

func checkBaseOsVolumeStatus(ctx *baseOsMgrContext, baseOsUUID uuid.UUID,
	config types.BaseOsConfig,
	status *types.BaseOsStatus) (bool, bool) {

	uuidStr := baseOsUUID.String()
	log.Infof("checkBaseOsVolumeStatus(%s) for %s",
		config.BaseOsVersion, uuidStr)
	ret := checkContentTreeStatus(ctx, baseOsUUID, config.ContentTreeConfigList,
		status.ContentTreeStatusList)

	status.State = ret.MinState

	if ret.AllErrors != "" {
		status.SetError(ret.AllErrors, ret.ErrorTime)
		log.Errorf("checkBaseOsVolumeStatus(%s) for %s, volumemgr error at %v: %v",
			config.BaseOsVersion, uuidStr, status.ErrorTime, status.Error)
		return ret.Changed, false
	}

	if ret.MinState < types.VERIFIED {
		log.Infof("checkBaseOsVolumeStatus(%s) for %s, Waiting for volumemgr",
			config.BaseOsVersion, uuidStr)
		return ret.Changed, false
	}
	log.Infof("checkBaseOsVolumeStatus(%s) for %s, done",
		config.BaseOsVersion, uuidStr)
	return ret.Changed, true
}

func removeBaseOsConfig(ctx *baseOsMgrContext, uuidStr string) {

	log.Infof("removeBaseOsConfig for %s", uuidStr)
	removeBaseOsStatus(ctx, uuidStr)
	log.Infof("removeBaseOSConfig for %s, done", uuidStr)
}

func removeBaseOsStatus(ctx *baseOsMgrContext, uuidStr string) {

	log.Infof("removeBaseOsStatus for %s", uuidStr)
	status := lookupBaseOsStatus(ctx, uuidStr)
	if status == nil {
		log.Infof("removeBaseOsStatus: no status")
		return
	}

	changed, del := doBaseOsRemove(ctx, uuidStr, status)
	if changed {
		log.Infof("removeBaseOsStatus for %s, Status change", uuidStr)
		publishBaseOsStatus(ctx, status)
	}

	if del {
		log.Infof("removeBaseOsStatus %s, Deleting", uuidStr)

		// Write out what we modified to BaseOsStatus aka delete
		unpublishBaseOsStatus(ctx, status.Key())
	}
	log.Infof("removeBaseOsStatus %s, Done", uuidStr)
}

func doBaseOsRemove(ctx *baseOsMgrContext, uuidStr string,
	status *types.BaseOsStatus) (bool, bool) {

	log.Infof("doBaseOsRemove(%s) for %s", status.BaseOsVersion, uuidStr)

	changed := false
	del := false

	changed = doBaseOsInactivate(uuidStr, status)

	changed, del = doBaseOsUninstall(ctx, uuidStr, status)

	log.Infof("doBaseOsRemove(%s) for %s, Done",
		status.BaseOsVersion, uuidStr)
	return changed, del
}

func doBaseOsInactivate(uuidStr string, status *types.BaseOsStatus) bool {
	log.Infof("doBaseOsInactivate(%s) %v",
		status.BaseOsVersion, status.Activated)

	// nothing to be done, flip will happen on reboot
	return true
}

func doBaseOsUninstall(ctx *baseOsMgrContext, uuidStr string,
	status *types.BaseOsStatus) (bool, bool) {

	log.Infof("doBaseOsUninstall(%s) for %s",
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
			log.Infof("doBaseOsUninstall(%s) for %s, partitionStatus not found",
				status.BaseOsVersion, uuidStr)
			return changed, del
		}
		if status.BaseOsVersion == partStatus.ShortVersion &&
			!partStatus.CurrentPartition {
			log.Infof("doBaseOsUninstall(%s) for %s, currently on other %s",
				status.BaseOsVersion, uuidStr, partName)
			curPartState := getPartitionState(ctx,
				zboot.GetCurrentPartition())
			if curPartState == "active" {
				log.Infof("Mark other partition %s, unused", partName)
				// we will erase the older reboot reason
				if zboot.IsOtherPartitionStateInProgress() {
					agentlog.DiscardOtherRebootReason(log)
				}
				zboot.SetOtherPartitionStateUnused(log)
				publishZbootPartitionStatus(ctx, partName)
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
	for i := range status.ContentTreeStatusList {
		cts := &status.ContentTreeStatusList[i]
		log.Infof("doBaseOsUninstall(%s) for %s",
			status.BaseOsVersion, uuidStr)
		c := MaybeRemoveContentTreeConfig(ctx, cts.Key())
		if c {
			changed = true
		}

		contentStatus := lookupContentTreeStatus(ctx, cts.Key())
		if contentStatus != nil {
			log.Infof("doBaseOsUninstall(%s) for %s, Content %s not yet gone;",
				status.BaseOsVersion, uuidStr, cts.ContentID)
			removedAll = false
			continue
		}
	}

	if !removedAll {
		log.Infof("doBaseOsUninstall(%s) for %s, Waiting for volumemgr purge",
			status.BaseOsVersion, uuidStr)
		return changed, del
	}

	del = true
	log.Infof("doBaseOsUninstall(%s), Done", status.BaseOsVersion)
	return changed, del
}

// validate whether the image version matches with
// config version string
func checkInstalledVersion(ctx *baseOsMgrContext, status types.BaseOsStatus) string {

	log.Infof("checkInstalledVersion(%s) %s %s",
		status.UUIDandVersion.UUID.String(), status.PartitionLabel,
		status.BaseOsVersion)

	if status.PartitionLabel == "" {
		errStr := fmt.Sprintf("checkInstalledVersion(%s) invalid partition", status.BaseOsVersion)
		log.Errorln(errStr)
		return errStr
	}

	// Check the configured Image name is the same as the one just installed image
	shortVer, err := zboot.GetShortVersion(log, status.PartitionLabel)
	log.Infof("checkInstalledVersion: Cfg baseVer %s, Image shortVer %s: %v",
		status.BaseOsVersion, shortVer, err)
	if err != nil {
		errString := fmt.Sprintf("checkInstalledVersion %s, %v\n",
			status.BaseOsVersion, err)
		return errString
	} else if status.BaseOsVersion != shortVer {
		errString := fmt.Sprintf("checkInstalledVersion: image name not match. config %s, image ver %s\n",
			status.BaseOsVersion, shortVer)
		return errString
	}
	return ""
}

func lookupBaseOsConfig(ctx *baseOsMgrContext, key string) *types.BaseOsConfig {

	sub := ctx.subBaseOsConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupBaseOsConfig(%s) not found", key)
		return nil
	}
	config := c.(types.BaseOsConfig)
	return &config
}

func lookupBaseOsStatus(ctx *baseOsMgrContext, key string) *types.BaseOsStatus {
	pub := ctx.pubBaseOsStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Infof("lookupBaseOsStatus(%s) not found", key)
		return nil
	}
	status := st.(types.BaseOsStatus)
	return &status
}

func lookupBaseOsStatusByPartLabel(ctx *baseOsMgrContext, partLabel string) *types.BaseOsStatus {
	pub := ctx.pubBaseOsStatus
	st, _ := pub.Get(partLabel)
	if st == nil {
		log.Infof("lookupBaseOsStatusByPartLabel(%s) not found", partLabel)
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
	log.Debugf("Publishing BaseOsStatus %s", key)
	pub := ctx.pubBaseOsStatus
	pub.Publish(key, *status)
}

func unpublishBaseOsStatus(ctx *baseOsMgrContext, key string) {

	log.Debugf("Unpublishing BaseOsStatus %s", key)
	pub := ctx.pubBaseOsStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishBaseOsStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

// Check the number of image in this config
func validateBaseOsConfig(ctx *baseOsMgrContext, config types.BaseOsConfig) error {

	imageCount := len(config.ContentTreeConfigList)
	if imageCount > BaseOsImageCount {
		errStr := fmt.Sprintf("baseOs(%s) invalid image count %d",
			config.BaseOsVersion, imageCount)
		return errors.New(errStr)
	}

	return nil
}

func handleZbootTestComplete(ctx *baseOsMgrContext, config types.ZbootConfig,
	status types.ZbootStatus) {

	log.Infof("handleZbootTestComplete(%s)", config.Key())
	if config.TestComplete == status.TestComplete {
		// nothing to do
		log.Infof("handleZbootTestComplete(%s) nothing to do",
			config.Key())
		return
	}
	if config.TestComplete {
		curPart := zboot.GetCurrentPartition()
		if curPart != config.Key() {
			log.Infof("handleZbootTestComplete(%s) not current partition; current %s",
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
			publishBaseOsStatus(ctx, bs)
			// publish the updated partition information
			publishZbootPartitionStatusAll(ctx)
			updateAndPublishBaseOsStatusAll(ctx)
			log.Infof("handleZbootTestComplete(%s) to True failed",
				config.Key())
			return
		}
		status.TestComplete = true
		publishZbootStatus(ctx, status)

		// publish the updated partition information
		publishZbootPartitionStatusAll(ctx)
		updateAndPublishBaseOsStatusAll(ctx)

		// Check if we have a failed update which needs a kick
		maybeRetryInstall(ctx)

		log.Infof("handleZbootTestComplete(%s) to True done",
			config.Key())
		return
	}

	// completed state transition, mark TestComplete as false
	log.Infof("handleZbootTestComplete(%s) to False done", config.Key())
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
			log.Infof("maybeRetryInstall(%s) skipped",
				status.Key())
			continue
		}
		config := lookupBaseOsConfig(ctx, status.Key())
		if config == nil {
			log.Infof("maybeRetryInstall(%s) no config",
				status.Key())
			continue
		}

		log.Infof("maybeRetryInstall(%s) redoing after %s %v",
			status.Key(), status.Error, status.ErrorTime)
		status.TooEarly = false
		status.ClearError()
		baseOsHandleStatusUpdate(ctx, config, &status)
	}
}

func baseOsSetPartitionInfoInStatus(ctx *baseOsMgrContext, status *types.BaseOsStatus, partName string) {

	partStatus := getZbootStatus(ctx, partName)
	if partStatus != nil {
		log.Infof("baseOsSetPartitionInfoInStatus(%s) %s found %+v",
			status.Key(), partName, partStatus)
		status.PartitionLabel = partName
		status.PartitionState = partStatus.PartitionState
		status.PartitionDevice = partStatus.PartitionDevname
	}
}

func publishZbootPartitionStatusAll(ctx *baseOsMgrContext) {
	log.Infof("publishZbootStatusAll")
	partitionNames := []string{"IMGA", "IMGB"}
	for _, partName := range partitionNames {
		publishZbootPartitionStatus(ctx, partName)
	}
	syscall.Sync()
}

func publishZbootPartitionStatus(ctx *baseOsMgrContext, partName string) {
	var err error
	partName = strings.TrimSpace(partName)
	if !isValidBaseOsPartitionLabel(partName) {
		return
	}
	testComplete := false
	partStatus := getZbootStatus(ctx, partName)
	if partStatus != nil {
		testComplete = partStatus.TestComplete
	}
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
	log.Infof("publishZbootPartitionStatus: %v", status)
	publishZbootStatus(ctx, status)
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
