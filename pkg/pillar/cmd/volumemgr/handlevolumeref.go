// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleVolumeRefCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleVolumeRefCreate(%s)", key)
	config := configArg.(types.VolumeRefConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupVolumeRefStatus(ctx, key)
	if status != nil {
		log.Fatalf("VolumeRefStatus exists at handleVolumeRefCreate for %s", key)
	}
	needUpdateVol := false
	vs := ctx.LookupVolumeStatus(config.VolumeKey())
	if vs != nil {
		updateVolumeStatusRefCount(ctx, vs)
		publishVolumeStatus(ctx, vs)
		status = &types.VolumeRefStatus{
			VolumeID:               config.VolumeID,
			GenerationCounter:      config.GenerationCounter,
			LocalGenerationCounter: config.LocalGenerationCounter,
			RefCount:               config.RefCount,
			MountDir:               config.MountDir,
			State:                  vs.State,
			ActiveFileLocation:     vs.FileLocation,
			ContentFormat:          vs.ContentFormat,
			ReadOnly:               vs.ReadOnly,
			DisplayName:            vs.DisplayName,
			MaxVolSize:             vs.MaxVolSize,
			WWN:                    vs.WWN,
			VerifyOnly:             config.VerifyOnly,
			Target:                 vs.Target,
			CustomMeta:             vs.CustomMeta,
		}
		if vs.HasError() {
			description := vs.ErrorDescription
			description.ErrorEntities = []*types.ErrorEntity{{EntityID: vs.VolumeID.String(), EntityType: types.ErrorEntityVolume}}
			status.SetErrorWithSourceAndDescription(description, types.VolumeStatus{})
		} else if status.IsErrorSource(types.VolumeStatus{}) {
			status.ClearErrorWithSource()
		}
		needUpdateVol = true
	} else {
		status = &types.VolumeRefStatus{
			VolumeID:               config.VolumeID,
			GenerationCounter:      config.GenerationCounter,
			LocalGenerationCounter: config.LocalGenerationCounter,
			RefCount:               config.RefCount,
			MountDir:               config.MountDir,
			State:                  types.INITIAL, // Waiting for VolumeConfig from zedagent
			VerifyOnly:             config.VerifyOnly,
		}
	}
	publishVolumeRefStatus(ctx, status)
	if needUpdateVol {
		changed, _ := doUpdateVol(ctx, vs)
		if changed {
			publishVolumeStatus(ctx, vs)
			updateVolumeRefStatus(ctx, vs)
			if err := createOrUpdateAppDiskMetrics(ctx, vs); err != nil {
				log.Errorf("handleVolumeRefCreate(%s): exception while publishing diskmetric. %s",
					status.Key(), err.Error())
			}
		}
	}
	log.Functionf("handleVolumeRefCreate(%s) Done", key)
}

func handleVolumeRefModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	log.Functionf("handleVolumeRefModify(%s)", key)
	config := configArg.(types.VolumeRefConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupVolumeRefStatus(ctx, config.Key())
	if status == nil {
		log.Fatalf("VolumeRefStatus doesn't exist at handleVolumeRefModify for %s", key)
	}
	status.RefCount = config.RefCount
	needUpdateVol := false
	if status.VerifyOnly != config.VerifyOnly {
		status.VerifyOnly = config.VerifyOnly
		needUpdateVol = true
	}
	publishVolumeRefStatus(ctx, status)
	vs := ctx.LookupVolumeStatus(config.VolumeKey())
	if vs != nil {
		if needUpdateVol {
			doUpdateVol(ctx, vs)
		}
		updateVolumeStatusRefCount(ctx, vs)
		publishVolumeStatus(ctx, vs)
		if err := createOrUpdateAppDiskMetrics(ctx, vs); err != nil {
			log.Errorf("handleVolumeRefModify(%s): exception while publishing diskmetric. %s",
				status.Key(), err.Error())
		}
	}
	log.Functionf("handleVolumeRefModify(%s) Done", key)
}

func handleVolumeRefDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleVolumeRefDelete(%s)", key)
	config := configArg.(types.VolumeRefConfig)
	ctx := ctxArg.(*volumemgrContext)
	unpublishVolumeRefStatus(ctx, config.Key())
	vs := ctx.LookupVolumeStatus(config.VolumeKey())
	if vs != nil {
		updateVolumeStatusRefCount(ctx, vs)
		publishVolumeStatus(ctx, vs)
		maybeDeleteVolume(ctx, vs)
		maybeSpaceAvailable(ctx)
	}
	log.Functionf("handleVolumeRefDelete(%s) Done", key)
}

func lookupVolumeRefConfig(ctx *volumemgrContext, key string) *types.VolumeRefConfig {

	sub := ctx.subVolumeRefConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Tracef("lookupVolumeRefConfig(%s) not found", key)
		return nil
	}
	config := c.(types.VolumeRefConfig)
	return &config
}

func lookupVolumeRefStatus(ctx *volumemgrContext, key string) *types.VolumeRefStatus {

	pub := ctx.pubVolumeRefStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Tracef("lookupVolumeRefStatus(%s) not found", key)
		return nil
	}
	status := c.(types.VolumeRefStatus)
	return &status
}

func publishVolumeRefStatus(ctx *volumemgrContext, status *types.VolumeRefStatus) {

	key := status.Key()
	log.Tracef("publishVolumeRefStatus(%s)", key)
	pub := ctx.pubVolumeRefStatus
	pub.Publish(key, *status)
	log.Tracef("publishVolumeRefStatus(%s) Done", key)
}

func unpublishVolumeRefStatus(ctx *volumemgrContext, key string) {

	log.Tracef("unpublishVolumeRefStatus(%s)", key)
	pub := ctx.pubVolumeRefStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishVolumeRefStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Tracef("unpublishVolumeRefStatus(%s) Done", key)
}

func updateVolumeRefStatus(ctx *volumemgrContext, vs *types.VolumeStatus) {
	sub := ctx.subVolumeRefConfig
	items := sub.GetAll()
	for _, st := range items {
		config := st.(types.VolumeRefConfig)
		if config.Key() == vs.Key() {
			updateVolumeStatusRefCount(ctx, vs)
			publishVolumeStatus(ctx, vs)
			status := lookupVolumeRefStatus(ctx, config.Key())
			if status != nil {
				status.State = vs.State
				status.ActiveFileLocation = vs.FileLocation
				status.ContentFormat = vs.ContentFormat
				status.ReadOnly = vs.ReadOnly
				status.DisplayName = vs.DisplayName
				status.MaxVolSize = vs.MaxVolSize
				status.Target = vs.Target
				status.CustomMeta = vs.CustomMeta
				status.WWN = vs.WWN
				if vs.HasError() {
					description := vs.ErrorDescription
					description.ErrorEntities = []*types.ErrorEntity{{
						EntityID:   vs.VolumeID.String(),
						EntityType: types.ErrorEntityVolume,
					}}
					status.SetErrorWithSourceAndDescription(description, types.VolumeStatus{})
				} else if status.IsErrorSource(types.VolumeStatus{}) {
					status.ClearErrorWithSource()
				}
				publishVolumeRefStatus(ctx, status)
				return
			}
			status = &types.VolumeRefStatus{
				VolumeID:               config.VolumeID,
				GenerationCounter:      config.GenerationCounter,
				LocalGenerationCounter: config.LocalGenerationCounter,
				RefCount:               config.RefCount,
				MountDir:               config.MountDir,
				State:                  vs.State,
				ActiveFileLocation:     vs.FileLocation,
				ContentFormat:          vs.ContentFormat,
				ReadOnly:               vs.ReadOnly,
				DisplayName:            vs.DisplayName,
				MaxVolSize:             vs.MaxVolSize,
				WWN:                    vs.WWN,
				VerifyOnly:             config.VerifyOnly,
				Target:                 vs.Target,
			}
			if vs.HasError() {
				description := vs.ErrorDescription
				description.ErrorEntities = []*types.ErrorEntity{{
					EntityID:   vs.VolumeID.String(),
					EntityType: types.ErrorEntityVolume,
				}}
				status.SetErrorWithSourceAndDescription(description, types.VolumeStatus{})
			} else if status.IsErrorSource(types.VolumeStatus{}) {
				status.ClearErrorWithSource()
			}
			publishVolumeRefStatus(ctx, status)
		}
	}
}
