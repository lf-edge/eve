// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
)

func handleVolumeCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleVolumeCreate(%s)", key)
	config := configArg.(types.VolumeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupVolumeStatus(ctx, config.Key())
	if status != nil {
		log.Fatalf("status exists at handleVolumeCreate for %s", config.Key())
	}
	status = &types.VolumeStatus{
		VolumeID:                config.VolumeID,
		ContentID:               config.ContentID,
		VolumeContentOriginType: config.VolumeContentOriginType,
		MaxVolSize:              config.MaxVolSize,
		ReadOnly:                config.ReadOnly,
		GenerationCounter:       config.GenerationCounter,
		VolumeDir:               config.VolumeDir,
		DisplayName:             config.DisplayName,
		RefCount:                config.RefCount,
		LastUse:                 time.Now(),
		State:                   types.INITIAL,
	}
	updateVolumeStatusRefCount(ctx, status)
	status.ContentFormat = volumeFormat[status.Key()]
	if _, err := os.Stat(status.PathName()); err == nil {
		status.State = types.CREATED_VOLUME
		status.Progress = 100
		status.FileLocation = status.PathName()
		status.VolumeCreated = true
		if status.MaxVolSize == 0 {
			var err error
			_, status.MaxVolSize, err = utils.GetVolumeSize(status.FileLocation)
			if err != nil {
				log.Error(err)
			}
		}
		publishVolumeStatus(ctx, status)
		updateVolumeRefStatus(ctx, status)
		return
	}
	publishVolumeStatus(ctx, status)
	if !ctx.globalConfig.GlobalValueBool(types.IgnoreDiskCheckForApps) {
		// Check disk usage
		remaining, volumeDiskSizeList, err := getRemainingVolumeDiskSpace(ctx)
		if err != nil {
			errStr := fmt.Sprintf("getRemainingVolumeDiskSpace failed: %s\n",
				err)
			status.SetError(errStr, time.Now())
			publishVolumeStatus(ctx, status)
			updateVolumeRefStatus(ctx, status)
			return
		} else if remaining < status.MaxVolSize {
			errStr := fmt.Sprintf("Remaining disk space %d volume needs %d\n"+
				"Current volume disk size list:\n%s\n",
				remaining, status.MaxVolSize, volumeDiskSizeList)
			status.SetError(errStr, time.Now())
			publishVolumeStatus(ctx, status)
			updateVolumeRefStatus(ctx, status)
			return
		}
	}
	changed, _ := doUpdateVol(ctx, status)
	if changed {
		publishVolumeStatus(ctx, status)
		updateVolumeRefStatus(ctx, status)
	}
	log.Infof("handleVolumeCreate(%s) Done", key)
}

func handleVolumeModify(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleVolumeModify(%s)", key)
	config := configArg.(types.VolumeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupVolumeStatus(ctx, config.Key())
	if status == nil {
		log.Fatalf("status doesn't exist at handleVolumeModify for %s", config.Key())
	}
	needRegeneration, regenerationReason := quantifyChanges(config, *status)
	if needRegeneration {
		errStr := fmt.Sprintf("Need volume regeneration due to %s but generation counter not incremented",
			regenerationReason)
		log.Errorf("handleVolumeModify(%s) failed: %s", status.Key(), errStr)
		status.SetError(errStr, time.Now())
		publishVolumeStatus(ctx, status)
		updateVolumeRefStatus(ctx, status)
		return
	}
	if config.DisplayName != status.DisplayName {
		log.Infof("DisplayName changed from %s to %s for %s",
			status.DisplayName, config.DisplayName, config.VolumeID)
		status.DisplayName = config.DisplayName
	}
	if config.RefCount != status.RefCount {
		log.Infof("RefCount changed from %d to %d for %s",
			status.RefCount, config.RefCount, config.DisplayName)
		status.RefCount = config.RefCount
	}
	updateVolumeStatusRefCount(ctx, status)
	publishVolumeStatus(ctx, status)
	updateVolumeRefStatus(ctx, status)
	log.Infof("handleVolumeModify(%s) Done", key)
}

func handleVolumeDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleVolumeDelete(%s)", key)
	config := configArg.(types.VolumeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupVolumeStatus(ctx, config.Key())
	if status == nil {
		log.Infof("handleVolumeDelete for %v, VolumeStatus not found", key)
		return
	}
	updateVolumeStatusRefCount(ctx, status)
	maybeDeleteVolume(ctx, status)
	log.Infof("handleVolumeDelete(%s) Done", key)
}

func publishVolumeStatus(ctx *volumemgrContext,
	status *types.VolumeStatus) {

	key := status.Key()
	log.Debugf("publishVolumeStatus(%s)", key)
	pub := ctx.pubVolumeStatus
	pub.Publish(key, *status)
	log.Debugf("publishVolumeStatus(%s) Done", key)
}

func unpublishVolumeStatus(ctx *volumemgrContext,
	status *types.VolumeStatus) {

	key := status.Key()
	log.Debugf("unpublishVolumeStatus(%s)", key)
	pub := ctx.pubVolumeStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishVolumeStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Debugf("unpublishVolumeStatus(%s) Done", key)
}

func lookupVolumeStatus(ctx *volumemgrContext,
	key string) *types.VolumeStatus {

	log.Debugf("lookupVolumeStatus(%s)", key)
	pub := ctx.pubVolumeStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Debugf("lookupVolumeStatus(%s) not found", key)
		return nil
	}
	status := c.(types.VolumeStatus)
	log.Debugf("lookupVolumeStatus(%s) Done", key)
	return &status
}

func lookupVolumeConfig(ctx *volumemgrContext,
	key string) *types.VolumeConfig {

	log.Debugf("lookupVolumeConfig(%s)", key)
	sub := ctx.subVolumeConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Debugf("lookupVolumeConfig(%s) not found", key)
		return nil
	}
	config := c.(types.VolumeConfig)
	log.Debugf("lookupVolumeConfig(%s) Done", key)
	return &config
}

func maybeDeleteVolume(ctx *volumemgrContext, status *types.VolumeStatus) {

	log.Infof("maybeDeleteVolume for %v", status.Key())
	if status.RefCount != 0 {
		publishVolumeStatus(ctx, status)
		log.Infof("maybeDeleteVolume for %v Done", status.Key())
		return
	}
	if status.VolumeCreated {
		// Asynch destruction; make sure we have a request for the work
		MaybeAddWorkDestroy(ctx, status)
		vr := lookupVolumeWorkResult(ctx, status.Key())
		if vr != nil {
			log.Infof("VolumeWorkResult(%s) location %s, created %t",
				status.Key(), vr.FileLocation, vr.VolumeCreated)
			deleteVolumeWorkResult(ctx, status.Key())
			status.VolumeCreated = vr.VolumeCreated
			status.FileLocation = vr.FileLocation
			if vr.Error != nil {
				status.SetErrorWithSource(vr.Error.Error(),
					types.VolumeStatus{}, vr.ErrorTime)
			} else if status.IsErrorSource(types.VolumeStatus{}) {
				log.Infof("Clearing volume error %s",
					status.Error)
				status.ClearErrorWithSource()
			}
			if !status.VolumeCreated {
				DeleteWorkDestroy(ctx, status)
			}
		} else {
			log.Infof("VolumeWorkResult(%s) not found", status.Key())
			// XXX what happens when VolumeWork is done?
		}
	}
	publishVolumeStatus(ctx, status)
	unpublishVolumeStatus(ctx, status)
	log.Infof("maybeDeleteVolume for %v Done", status.Key())
}

// updateVolumeStatusRefCount updates the refcount in volume status
// Refcount in volume status is sum of refount in volume config and volume ref config
func updateVolumeStatusRefCount(ctx *volumemgrContext, vs *types.VolumeStatus) {
	log.Debugf("updateVolumeStatusRefCount(%s)", vs.Key())
	var vcRefCount, vrcRefCount uint
	vc := lookupVolumeConfig(ctx, vs.Key())
	if vc == nil {
		log.Infof("updateVolumeStatusRefCount: VolumeConfig not present for %s", vs.Key())
	} else {
		vcRefCount = vc.RefCount
	}
	vrc := lookupVolumeRefConfig(ctx, vs.Key())
	if vrc == nil {
		log.Infof("updateVolumeStatusRefCount: VolumeRefConfig not present for %s", vs.Key())
	} else {
		vrcRefCount = vrc.RefCount
	}
	old := vs.RefCount
	new := vcRefCount + vrcRefCount
	if new != old {
		vs.RefCount = new
		log.Infof("updateVolumeStatusRefCount(%s) updated from %d to %d",
			vs.Key(), old, new)
	}
	log.Debugf("updateVolumeStatusRefCount(%s) Done", vs.Key())
}

// Returns needRegeneration, plus a reason string.
func quantifyChanges(config types.VolumeConfig,
	status types.VolumeStatus) (bool, string) {

	needRegeneration := false
	var regenerationReason string
	log.Infof("quantifyChanges for %s %s",
		config.Key(), config.DisplayName)
	if config.ContentID != status.ContentID {
		str := fmt.Sprintf("ContentID changed from %s to %s for %s",
			status.ContentID, config.ContentID, config.DisplayName)
		log.Infof(str)
		needRegeneration = true
		regenerationReason += str + "\n"
	}
	if config.VolumeContentOriginType != status.VolumeContentOriginType {
		str := fmt.Sprintf("VolumeContentOriginType changed from %v to %v for %s",
			status.VolumeContentOriginType, config.VolumeContentOriginType, config.DisplayName)
		log.Infof(str)
		needRegeneration = true
		regenerationReason += str + "\n"
	}
	if config.MaxVolSize != status.MaxVolSize {
		str := fmt.Sprintf("MaxVolSize changed from %d to %d for %s",
			status.MaxVolSize, config.MaxVolSize, config.DisplayName)
		log.Infof(str)
		needRegeneration = true
		regenerationReason += str + "\n"
	}
	if config.ReadOnly != status.ReadOnly {
		str := fmt.Sprintf("ReadOnly changed from %v to %v for %s",
			status.ReadOnly, config.ReadOnly, config.DisplayName)
		log.Infof(str)
		needRegeneration = true
		regenerationReason += str + "\n"
	}

	log.Infof("quantifyChanges for %s %s returns %v, %s",
		config.Key(), config.DisplayName, needRegeneration, regenerationReason)
	return needRegeneration, regenerationReason
}
