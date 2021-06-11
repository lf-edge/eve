// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

func handleVolumeCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleVolumeCreate(%s)", key)
	config := configArg.(types.VolumeConfig)
	ctx := ctxArg.(*volumemgrContext)
	//defer creation to restart handler
	ctx.volumeConfigCreateDeferredMap[key] = &config
	log.Functionf("handleVolumeCreate(%s) Done", key)
}

func handleVolumeModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	log.Functionf("handleVolumeModify(%s)", key)
	config := configArg.(types.VolumeConfig)
	ctx := ctxArg.(*volumemgrContext)
	if _, deferred := ctx.volumeConfigCreateDeferredMap[key]; deferred {
		//update deferred creation if exists
		ctx.volumeConfigCreateDeferredMap[key] = &config
	} else {
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
			if err := createOrUpdateAppDiskMetrics(ctx, status); err != nil {
				log.Errorf("handleVolumeModify(%s): exception while publishing diskmetric. %s", key, err.Error())
			}
			return
		}
		if config.DisplayName != status.DisplayName {
			log.Functionf("DisplayName changed from %s to %s for %s",
				status.DisplayName, config.DisplayName, config.VolumeID)
			status.DisplayName = config.DisplayName
		}
		if config.RefCount != status.RefCount {
			log.Functionf("RefCount changed from %d to %d for %s",
				status.RefCount, config.RefCount, config.DisplayName)
			status.RefCount = config.RefCount
			status.LastRefCountChangeTime = time.Now()
		}
		updateVolumeStatusRefCount(ctx, status)
		publishVolumeStatus(ctx, status)
		updateVolumeRefStatus(ctx, status)
		if err := createOrUpdateAppDiskMetrics(ctx, status); err != nil {
			log.Errorf("handleVolumeModify(%s): exception while publishing diskmetric. %s", key, err.Error())
		}
	}
	log.Functionf("handleVolumeModify(%s) Done", key)
}

func handleVolumeDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleVolumeDelete(%s)", key)
	config := configArg.(types.VolumeConfig)
	ctx := ctxArg.(*volumemgrContext)
	if _, deferred := ctx.volumeConfigCreateDeferredMap[key]; deferred {
		//remove deferred creation if exists
		delete(ctx.volumeConfigCreateDeferredMap, key)
	} else {
		status := lookupVolumeStatus(ctx, config.Key())
		if status == nil {
			log.Functionf("handleVolumeDelete for %v, VolumeStatus not found", key)
			return
		}
		updateVolumeStatusRefCount(ctx, status)
		maybeDeleteVolume(ctx, status)
	}
	log.Functionf("handleVolumeDelete(%s) Done", key)
}

func handleDeferredVolumeCreate(ctx *volumemgrContext, key string, config *types.VolumeConfig) {

	log.Tracef("handleDeferredVolumeCreate(%s)", key)
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
		LastRefCountChangeTime:  time.Now(),
		LastUse:                 time.Now(),
		State:                   types.INITIAL,
	}
	updateVolumeStatusRefCount(ctx, status)
	status.ContentFormat = volumeFormat[status.Key()]

	created := false

	persistFsType := ctx.persistType

	if persistFsType == types.PersistZFS {
		zvolName := status.ZVolName(types.VolumeZFSPool)
		if _, err := zfs.GetDatasetOptions(log, zvolName); err == nil {
			zVolDevice := zfs.GetZVolDeviceByDataset(zvolName)
			if zVolDevice == "" {
				errStr := fmt.Sprintf("cannot find device for zvol %s of %s", zvolName, status.Key())
				status.SetError(errStr, time.Now())
				publishVolumeStatus(ctx, status)
				updateVolumeRefStatus(ctx, status)
				if err := createOrUpdateAppDiskMetrics(ctx, status); err != nil {
					log.Errorf("handleDeferredVolumeCreate(%s): exception while publishing diskmetric. %s", key, err.Error())
				}
				return
			}
			created = true
			status.FileLocation = zVolDevice
		}
	} else {
		if _, err := os.Stat(status.PathName()); err == nil {
			created = true
			status.FileLocation = status.PathName()
		}
	}

	if created {
		status.State = types.CREATED_VOLUME
		status.Progress = 100
		status.SubState = types.VolumeSubStateCreated
		status.CreateTime = time.Now()
		actualSize, maxSize, _, _, err := utils.GetVolumeSize(log, status.FileLocation)
		if err != nil {
			log.Error(err)
		} else {
			if status.MaxVolSize == 0 {
				status.MaxVolSize = maxSize
			}
			// XXX this is not the same as what we downloaded
			// and created but the best we know
			status.TotalSize = int64(actualSize)
			status.CurrentSize = int64(actualSize)
		}
		updateStatusByPersistType(status, persistFsType)
		publishVolumeStatus(ctx, status)
		updateVolumeRefStatus(ctx, status)
		if err := createOrUpdateAppDiskMetrics(ctx, status); err != nil {
			log.Errorf("handleDeferredVolumeCreate(%s): exception while publishing diskmetric. %s", key, err.Error())
		}
		return
	}
	publishVolumeStatus(ctx, status)
	if !ctx.globalConfig.GlobalValueBool(types.IgnoreDiskCheckForApps) {
		// Check disk usage
		remaining, err := getRemainingDiskSpace(ctx)
		if err != nil {
			errStr := fmt.Sprintf("getRemainingDiskSpace failed: %s\n",
				err)
			status.SetError(errStr, time.Now())
			publishVolumeStatus(ctx, status)
			updateVolumeRefStatus(ctx, status)
			if err := createOrUpdateAppDiskMetrics(ctx, status); err != nil {
				log.Errorf("handleDeferredVolumeCreate(%s): exception while publishing diskmetric. %s", key, err.Error())
			}
			return
		} else if remaining < status.MaxVolSize {
			errStr := fmt.Sprintf("Remaining disk space %d volume needs %d\n",
				remaining, status.MaxVolSize)
			status.SetError(errStr, time.Now())
			publishVolumeStatus(ctx, status)
			updateVolumeRefStatus(ctx, status)
			if err := createOrUpdateAppDiskMetrics(ctx, status); err != nil {
				log.Errorf("handleDeferredVolumeCreate(%s): exception while publishing diskmetric. %s", key, err.Error())
			}
			return
		}
	}
	changed, _ := doUpdateVol(ctx, status)
	if changed {
		publishVolumeStatus(ctx, status)
		updateVolumeRefStatus(ctx, status)
	}
	if err := createOrUpdateAppDiskMetrics(ctx, status); err != nil {
		log.Errorf("handleDeferredVolumeCreate(%s): exception while publishing diskmetric. %s", key, err.Error())
	}
	log.Tracef("handleDeferredVolumeCreate(%s) done", key)
}

func handleVolumeRestart(ctxArg interface{}, restartCount int) {

	log.Tracef("handleVolumeRestart: %d", restartCount)
	ctx := ctxArg.(*volumemgrContext)
	for key, config := range ctx.volumeConfigCreateDeferredMap {
		handleDeferredVolumeCreate(ctx, key, config)
		delete(ctx.volumeConfigCreateDeferredMap, key)
	}
	log.Tracef("handleVolumeRestart done: %d", restartCount)
}

func publishVolumeStatus(ctx *volumemgrContext,
	status *types.VolumeStatus) {

	key := status.Key()
	log.Tracef("publishVolumeStatus(%s)", key)
	pub := ctx.pubVolumeStatus
	pub.Publish(key, *status)
	log.Tracef("publishVolumeStatus(%s) Done", key)
}

func unpublishVolumeStatus(ctx *volumemgrContext,
	status *types.VolumeStatus) {

	key := status.Key()
	log.Tracef("unpublishVolumeStatus(%s)", key)
	pub := ctx.pubVolumeStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishVolumeStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Tracef("unpublishVolumeStatus(%s) Done", key)
}

func lookupVolumeStatus(ctx *volumemgrContext,
	key string) *types.VolumeStatus {

	log.Tracef("lookupVolumeStatus(%s)", key)
	pub := ctx.pubVolumeStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Tracef("lookupVolumeStatus(%s) not found", key)
		return nil
	}
	status := c.(types.VolumeStatus)
	log.Tracef("lookupVolumeStatus(%s) Done", key)
	return &status
}

func getAllVolumeStatus(ctx *volumemgrContext) []*types.VolumeStatus {
	var retList []*types.VolumeStatus
	log.Tracef("getAllVolumeStatus")
	pub := ctx.pubVolumeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.VolumeStatus)
		retList = append(retList, &status)
	}
	log.Tracef("getAllVolumeStatus: Done")
	return retList
}

func lookupVolumeConfig(ctx *volumemgrContext,
	key string) *types.VolumeConfig {

	log.Tracef("lookupVolumeConfig(%s)", key)
	sub := ctx.subVolumeConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Tracef("lookupVolumeConfig(%s) not found", key)
		return nil
	}
	config := c.(types.VolumeConfig)
	log.Tracef("lookupVolumeConfig(%s) Done", key)
	return &config
}

func maybeDeleteVolume(ctx *volumemgrContext, status *types.VolumeStatus) {

	log.Functionf("maybeDeleteVolume for %v", status.Key())
	if status.RefCount != 0 {
		publishVolumeStatus(ctx, status)
		log.Functionf("maybeDeleteVolume for %v Done", status.Key())
		return
	}
	if status.SubState == types.VolumeSubStateCreated {
		// Asynch destruction; make sure we have a request for the work
		AddWorkDestroy(ctx, status)
		vr := popVolumeWorkResult(ctx, status.Key())
		if vr != nil {
			log.Functionf("VolumeWorkResult(%s) location %s, created %t",
				status.Key(), vr.FileLocation, vr.VolumeCreated)
			if vr.VolumeCreated {
				status.SubState = types.VolumeSubStateCreated
				status.CreateTime = vr.CreateTime
			} else {
				status.SubState = types.VolumeSubStateInitial
			}
			status.FileLocation = vr.FileLocation
			if vr.Error != nil {
				status.SetErrorWithSource(vr.Error.Error(),
					types.VolumeStatus{}, vr.ErrorTime)
			} else if status.IsErrorSource(types.VolumeStatus{}) {
				log.Functionf("Clearing volume error %s",
					status.Error)
				status.ClearErrorWithSource()
			}
			if status.SubState != types.VolumeSubStateCreated {
				DeleteWorkDestroy(ctx, status)
			}
		} else {
			log.Functionf("VolumeWorkResult(%s) not found", status.Key())
			// XXX what happens when VolumeWork is done?
		}
	}
	publishVolumeStatus(ctx, status)
	unpublishVolumeStatus(ctx, status)
	if appDiskMetric := lookupAppDiskMetric(ctx, status.FileLocation); appDiskMetric != nil {
		unpublishAppDiskMetrics(ctx, appDiskMetric)
	}
	log.Functionf("maybeDeleteVolume for %v Done", status.Key())
}

// updateVolumeStatusRefCount updates the refcount in volume status
// Refcount in volume status is sum of refount in volume config and volume ref config
func updateVolumeStatusRefCount(ctx *volumemgrContext, vs *types.VolumeStatus) {
	log.Tracef("updateVolumeStatusRefCount(%s)", vs.Key())
	var vcRefCount, vrcRefCount uint
	vc := lookupVolumeConfig(ctx, vs.Key())
	if vc == nil {
		log.Functionf("updateVolumeStatusRefCount: VolumeConfig not present for %s", vs.Key())
	} else {
		vcRefCount = vc.RefCount
	}
	vrc := lookupVolumeRefConfig(ctx, vs.Key())
	if vrc == nil {
		log.Functionf("updateVolumeStatusRefCount: VolumeRefConfig not present for %s", vs.Key())
	} else {
		vrcRefCount = vrc.RefCount
	}
	oldRefCount := vs.RefCount
	newRefCount := vcRefCount + vrcRefCount
	if newRefCount != oldRefCount {
		vs.RefCount = newRefCount
		vs.LastRefCountChangeTime = time.Now()
		log.Functionf("updateVolumeStatusRefCount(%s) updated from %d to %d",
			vs.Key(), oldRefCount, newRefCount)
	}
	log.Tracef("updateVolumeStatusRefCount(%s) Done", vs.Key())
}

// Returns needRegeneration, plus a reason string.
func quantifyChanges(config types.VolumeConfig,
	status types.VolumeStatus) (bool, string) {

	needRegeneration := false
	var regenerationReason string
	log.Functionf("quantifyChanges for %s %s",
		config.Key(), config.DisplayName)
	if config.ContentID != status.ContentID {
		str := fmt.Sprintf("ContentID changed from %s to %s for %s",
			status.ContentID, config.ContentID, config.DisplayName)
		log.Functionf(str)
		needRegeneration = true
		regenerationReason += str + "\n"
	}
	if config.VolumeContentOriginType != status.VolumeContentOriginType {
		str := fmt.Sprintf("VolumeContentOriginType changed from %v to %v for %s",
			status.VolumeContentOriginType, config.VolumeContentOriginType, config.DisplayName)
		log.Functionf(str)
		needRegeneration = true
		regenerationReason += str + "\n"
	}
	if config.MaxVolSize != status.MaxVolSize {
		str := fmt.Sprintf("MaxVolSize changed from %d to %d for %s",
			status.MaxVolSize, config.MaxVolSize, config.DisplayName)
		log.Functionf(str)
		needRegeneration = true
		regenerationReason += str + "\n"
	}
	if config.ReadOnly != status.ReadOnly {
		str := fmt.Sprintf("ReadOnly changed from %v to %v for %s",
			status.ReadOnly, config.ReadOnly, config.DisplayName)
		log.Functionf(str)
		needRegeneration = true
		regenerationReason += str + "\n"
	}

	log.Functionf("quantifyChanges for %s %s returns %v, %s",
		config.Key(), config.DisplayName, needRegeneration, regenerationReason)
	return needRegeneration, regenerationReason
}

func handleZVolStatusCreate(ctxArg interface{}, key string, configArg interface{}) {
	log.Functionf("handleZVolStatusCreate for %s", key)
	ctx := ctxArg.(*volumemgrContext)
	status := configArg.(types.ZVolStatus)
	for _, s := range ctx.pubVolumeStatus.GetAll() {
		volumeStatus := s.(types.VolumeStatus)
		if volumeStatus.ZVolName(types.VolumeZFSPool) == status.Dataset {
			updateVolumeStatus(ctx, volumeStatus.VolumeID)
			break
		}
	}
	log.Functionf("handleZVolStatusCreate for %s, done", key)
}

func lookupZVolStatusByDataset(ctxPtr *volumemgrContext, dataset string) *types.ZVolStatus {
	for _, s := range ctxPtr.subZVolStatus.GetAll() {
		zVolStatus := s.(types.ZVolStatus)
		if zVolStatus.Dataset == dataset {
			return &zVolStatus
		}
	}
	log.Functionf("lookupZVolStatusByDataset: not found for dataset %s", dataset)
	return nil
}
