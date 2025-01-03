// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"time"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"github.com/lf-edge/eve/pkg/pillar/volumehandlers"
)

func handleVolumeCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleVolumeCreate(%s)", key)
	config := configArg.(types.VolumeConfig)
	ctx := ctxArg.(*volumemgrContext)
	// we received volume configuration
	// clean of vault is not safe from now
	// note that we wait for vault before start this handler
	if err := vault.DisallowVaultCleanup(); err != nil {
		log.Errorf("cannot disallow vault cleanup: %s", err)
	}
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
		status := ctx.LookupVolumeStatus(config.Key())
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
			if err := createOrUpdateAppDiskMetrics(ctx, agentName, status); err != nil {
				log.Errorf("handleVolumeModify(%s): exception while publishing diskmetric. %s", key, err.Error())
			}
			return
		}
		if config.DisplayName != status.DisplayName {
			log.Functionf("DisplayName changed from %s to %s for %s",
				status.DisplayName, config.DisplayName, config.VolumeID)
			status.DisplayName = config.DisplayName
		}
		updateVolumeStatusRefCount(ctx, status)
		publishVolumeStatus(ctx, status)
		updateVolumeRefStatus(ctx, status)
		if err := createOrUpdateAppDiskMetrics(ctx, agentName, status); err != nil {
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
		status := ctx.LookupVolumeStatus(config.Key())
		if status == nil {
			log.Functionf("handleVolumeDelete for %v, VolumeStatus not found", key)
			return
		}
		updateVolumeStatusRefCount(ctx, status)
		maybeDeleteVolume(ctx, status)
		maybeSpaceAvailable(ctx)
	}
	log.Functionf("handleVolumeDelete(%s) Done", key)
}

func handleDeferredVolumeCreate(ctx *volumemgrContext, key string, config *types.VolumeConfig) {

	log.Tracef("handleDeferredVolumeCreate(%s)", key)
	status := ctx.LookupVolumeStatus(config.Key())
	if status != nil {
		if config.IsReplicated {
			// Objects are replicated across cluster nodes, just exit.
			return
		}
		log.Fatalf("status exists at handleVolumeCreate for %s", config.Key())
	}
	status = &types.VolumeStatus{
		VolumeID:                config.VolumeID,
		ContentID:               config.ContentID,
		VolumeContentOriginType: config.VolumeContentOriginType,
		MaxVolSize:              config.MaxVolSize,
		ReadOnly:                config.ReadOnly,
		GenerationCounter:       config.GenerationCounter,
		LocalGenerationCounter:  config.LocalGenerationCounter,
		Encrypted:               config.Encrypted,
		DisplayName:             config.DisplayName,
		RefCount:                1,
		Target:                  config.Target,
		CustomMeta:              config.CustomMeta,
		LastRefCountChangeTime:  time.Now(),
		LastUse:                 time.Now(),
		State:                   types.INITIAL,
		IsReplicated:            config.IsReplicated,
		IsNativeContainer:       config.IsNativeContainer,
	}
	updateVolumeStatusRefCount(ctx, status)
	log.Noticef("handleDeferredVolumeCreate(%s) setting contentFormat to %s", key, volumeFormat[status.Key()])
	status.ContentFormat = volumeFormat[status.Key()]

	created, err := volumehandlers.GetVolumeHandler(log, ctx, status).Populate()
	if err != nil {
		status.SetError(err.Error(), time.Now())
		publishVolumeStatus(ctx, status)
		updateVolumeRefStatus(ctx, status)
		if err := createOrUpdateAppDiskMetrics(ctx, agentName, status); err != nil {
			log.Errorf("handleDeferredVolumeCreate(%s): exception while publishing diskmetric. %s", key, err.Error())
		}
		return
	}

	if created {
		status.State = types.CREATED_VOLUME
		status.Progress = 100
		status.SubState = types.VolumeSubStateCreated
		status.CreateTime = time.Now()
		actualSize, maxSize, _, _, err := volumehandlers.GetVolumeHandler(log, ctx, status).GetVolumeDetails()
		if err != nil {
			log.Error(err)
		} else {
			if status.MaxVolSize == 0 {
				status.MaxVolSize = maxSize
			}
			// XXX this is not the same as what we downloaded
			// and created but the best we know
			if (status.TotalSize != 0) && (status.TotalSize != int64(actualSize)) {
				log.Warnf("handleDeferredVolumeCreate(%s) from ds set status.TotalSize %d, was %d", key, actualSize, status.TotalSize)
			}
			status.TotalSize = int64(actualSize)
			status.CurrentSize = int64(actualSize)
		}

		// Fill the ReferenceName which will be used by domainmgr to launch native containers.
		ctStatus := ctx.LookupContentTreeStatus(status.ContentID.String())

		if ctStatus != nil {
			status.ReferenceName = ctStatus.ReferenceID()
			// In kubevirt eve though we created PVC from container image, we still set the content format as container.
			// This will help domainmgr to load the external boot kernel (support shim VM container)
			if ctStatus.Format == zconfig.Format_CONTAINER {
				status.ContentFormat = zconfig.Format_CONTAINER
			}
		}
		publishVolumeStatus(ctx, status)
		updateVolumeRefStatus(ctx, status)
		if err := createOrUpdateAppDiskMetrics(ctx, agentName, status); err != nil {
			log.Errorf("handleDeferredVolumeCreate(%s): exception while publishing diskmetric. %s", key, err.Error())
		}
		return
	}
	publishVolumeStatus(ctx, status)
	changed, _ := doUpdateVol(ctx, status)
	if changed {
		publishVolumeStatus(ctx, status)
		updateVolumeRefStatus(ctx, status)
	}
	if err := createOrUpdateAppDiskMetrics(ctx, agentName, status); err != nil {
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

// LookupVolumeStatus returns VolumeStatus based on key
func (ctxPtr *volumemgrContext) LookupVolumeStatus(key string) *types.VolumeStatus {
	log.Tracef("lookupVolumeStatus(%s)", key)
	pub := ctxPtr.pubVolumeStatus
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

// LookupVolumeConfig returns VolumeConfig based on key
func (ctxPtr *volumemgrContext) LookupVolumeConfig(key string) *types.VolumeConfig {
	log.Tracef("lookupVolumeConfig(%s)", key)
	sub := ctxPtr.subVolumeConfig
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
	var readyToUnPublish bool
	if status.SubState == types.VolumeSubStateCreated {
		// we are not interested in result
		_ = popVolumeWorkResult(ctx, status.Key())
		status.SubState = types.VolumeSubStateDeleting
		publishVolumeStatus(ctx, status)
		// Asynch destruction; make sure we have a request for the work
		AddWorkDestroy(ctx, status)
	} else if status.SubState == types.VolumeSubStateDeleting {
		vr := popVolumeWorkResult(ctx, status.Key())
		if vr != nil {
			log.Functionf("VolumeWorkResult(%s) location %s, created %t",
				status.Key(), vr.FileLocation, vr.VolumeCreated)
			if !vr.VolumeCreated {
				readyToUnPublish = true
			} else {
				var err string
				if vr.Error != nil {
					err = vr.Error.Error()
				} else {
					err = fmt.Sprintf("unexpected WorkDestroy return for %s", status.Key())
				}
				log.Errorf("maybeDeleteVolume: %s", err)
				status.SetErrorDescription(types.ErrorDescription{Error: vr.Error.Error()})
				// we have no retrial mechanism for volume delete now
				// so let publish error in status and log and unpublish the volume
				readyToUnPublish = true
			}
		}
	} else {
		readyToUnPublish = true
	}
	if readyToUnPublish {
		// we are not interested in result
		_ = popVolumeWorkResult(ctx, status.Key())
		publishVolumeStatus(ctx, status)
		unpublishVolumeStatus(ctx, status)
		if appDiskMetric := lookupAppDiskMetric(ctx, status.FileLocation); appDiskMetric != nil {
			unpublishAppDiskMetrics(ctx, appDiskMetric)
		}
	}
	log.Functionf("maybeDeleteVolume for %v Done", status.Key())
}

// maybeSpaceAvailable iterates over VolumeStatus and call doUpdateVol if state is less than CREATING_VOLUME
func maybeSpaceAvailable(ctx *volumemgrContext) {
	for _, s := range ctx.pubVolumeStatus.GetAll() {
		status := s.(types.VolumeStatus)
		if status.State >= types.CREATING_VOLUME {
			continue
		}
		if vc := ctx.LookupVolumeConfig(status.Key()); vc == nil {
			continue
		}
		changed, _ := doUpdateVol(ctx, &status)
		if changed {
			publishVolumeStatus(ctx, &status)
			updateVolumeRefStatus(ctx, &status)
			if err := createOrUpdateAppDiskMetrics(ctx, agentName, &status); err != nil {
				log.Errorf("maybeSpaceAvailable(%s): exception while publishing diskmetric. %s", status.Key(), err.Error())
			}
		}
	}
}

// updateVolumeStatusRefCount updates the refcount in volume status
// Refcount in volume status is the number of all received VolumeConfigs and VolumeRefConfigs
func updateVolumeStatusRefCount(ctx *volumemgrContext, vs *types.VolumeStatus) {
	log.Tracef("updateVolumeStatusRefCount(%s)", vs.Key())
	var vcRefCount, vrcRefCount uint // initialize to 0

	// count refcount from volume config itself (should be one at max)
	vc := ctx.LookupVolumeConfig(vs.Key())
	if vc == nil {
		log.Functionf("updateVolumeStatusRefCount: VolumeConfig not present for %s", vs.Key())
	} else {
		vcRefCount++
	}

	// count references from apps
	for _, s := range ctx.subVolumeRefConfig.GetAll() {
		vrc := s.(types.VolumeRefConfig)
		if vrc.VolumeKey() == vs.Key() {
			vrcRefCount++
		}
	}
	if vrcRefCount == 0 {
		log.Functionf("updateVolumeStatusRefCount: no VolumeRefConfigs present for %s", vs.Key())
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
		if volumeStatus.ZVolName() == status.Dataset {
			updateVolumeStatus(ctx, volumeStatus.VolumeID)
			break
		}
	}
	log.Functionf("handleZVolStatusCreate for %s, done", key)
}

// LookupZVolStatusByDataset returns ZVolStatus based on dataset
func (ctxPtr *volumemgrContext) LookupZVolStatusByDataset(dataset string) *types.ZVolStatus {
	for _, s := range ctxPtr.subZVolStatus.GetAll() {
		zVolStatus := s.(types.ZVolStatus)
		if zVolStatus.Dataset == dataset {
			return &zVolStatus
		}
	}
	log.Functionf("lookupZVolStatusByDataset: not found for dataset %s", dataset)
	return nil
}
