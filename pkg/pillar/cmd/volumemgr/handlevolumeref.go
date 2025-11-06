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
	vrs := lookupVolumeRefStatus(ctx, key)
	if vrs != nil {
		log.Fatalf("VolumeRefStatus exists at handleVolumeRefCreate for %s", key)
	}
	needUpdateVol := false
	vs := ctx.LookupVolumeStatus(config.VolumeKey())
	if vs != nil {
		updateVolumeStatusRefCount(ctx, vs)
		publishVolumeStatus(ctx, vs)
		vrs = &types.VolumeRefStatus{
			VolumeID:               config.VolumeID,
			GenerationCounter:      config.GenerationCounter,
			LocalGenerationCounter: config.LocalGenerationCounter,
			AppUUID:                config.AppUUID,
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
			ReferenceName:          vs.ReferenceName,
		}
		if vs.HasError() {
			description := vs.ErrorDescription
			description.ErrorEntities = []*types.ErrorEntity{{EntityID: vs.VolumeID.String(), EntityType: types.ErrorEntityVolume}}
			vrs.SetErrorWithSourceAndDescription(description, types.VolumeStatus{})
		} else if vrs.IsErrorSource(types.VolumeStatus{}) {
			vrs.ClearErrorWithSource()
		}
		needUpdateVol = true
	} else {
		vrs = &types.VolumeRefStatus{
			VolumeID:               config.VolumeID,
			GenerationCounter:      config.GenerationCounter,
			LocalGenerationCounter: config.LocalGenerationCounter,
			AppUUID:                config.AppUUID,
			State:                  types.INITIAL, // Waiting for VolumeConfig from zedagent
			VerifyOnly:             config.VerifyOnly,
		}
	}
	publishVolumeRefStatus(ctx, vrs)
	if needUpdateVol {
		changed, _ := doUpdateVol(ctx, vs)
		if changed {
			publishVolumeStatus(ctx, vs)
			updateVolumeRefStatus(ctx, vs)
			if err := createOrUpdateAppDiskMetrics(ctx, agentName, vs); err != nil {
				log.Errorf("handleVolumeRefCreate(%s): exception while publishing diskmetric. %s",
					vrs.Key(), err.Error())
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
	vrs := lookupVolumeRefStatus(ctx, config.Key())
	if vrs == nil {
		log.Fatalf("VolumeRefStatus doesn't exist at handleVolumeRefModify for %s", key)
	}
	needUpdateVol := false
	if vrs.VerifyOnly != config.VerifyOnly {
		vrs.VerifyOnly = config.VerifyOnly
		needUpdateVol = true
	}
	publishVolumeRefStatus(ctx, vrs)
	vs := ctx.LookupVolumeStatus(config.VolumeKey())
	if vs != nil {
		if needUpdateVol {
			changed, _ := doUpdateVol(ctx, vs)
			if changed {
				publishVolumeStatus(ctx, vs)
				updateVolumeRefStatus(ctx, vs)
				if err := createOrUpdateAppDiskMetrics(ctx, agentName, vs); err != nil {
					log.Errorf("handleVolumeRefModify(%s): exception while publishing diskmetric. %s",
						vrs.Key(), err.Error())
				}
			}
		}
		updateVolumeStatusRefCount(ctx, vs)
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
	vrs := c.(types.VolumeRefStatus)
	return &vrs
}

func publishVolumeRefStatus(ctx *volumemgrContext, vrs *types.VolumeRefStatus) {

	key := vrs.Key()
	log.Tracef("publishVolumeRefStatus(%s)", key)
	pub := ctx.pubVolumeRefStatus
	pub.Publish(key, *vrs)
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

	log.Functionf("updateVolumeRefStatus(%s)", vs.Key())
	sub := ctx.subVolumeRefConfig
	items := sub.GetAll()
	for _, st := range items {
		vrc := st.(types.VolumeRefConfig)
		if vrc.VolumeKey() == vs.Key() {
			updateVolumeStatusRefCount(ctx, vs)
			publishVolumeStatus(ctx, vs)
			vrs := lookupVolumeRefStatus(ctx, vrc.Key())
			if vrs != nil {
				vrs.State = vs.State
				vrs.ActiveFileLocation = vs.FileLocation
				vrs.ContentFormat = vs.ContentFormat
				vrs.ReadOnly = vs.ReadOnly
				vrs.DisplayName = vs.DisplayName
				vrs.MaxVolSize = vs.MaxVolSize
				vrs.Target = vs.Target
				vrs.CustomMeta = vs.CustomMeta
				vrs.WWN = vs.WWN
				vrs.ReferenceName = vs.ReferenceName
			} else {
				vrs = &types.VolumeRefStatus{
					VolumeID:               vrc.VolumeID,
					GenerationCounter:      vrc.GenerationCounter,
					LocalGenerationCounter: vrc.LocalGenerationCounter,
					AppUUID:                vrc.AppUUID,
					State:                  vs.State,
					ActiveFileLocation:     vs.FileLocation,
					ContentFormat:          vs.ContentFormat,
					ReadOnly:               vs.ReadOnly,
					DisplayName:            vs.DisplayName,
					MaxVolSize:             vs.MaxVolSize,
					WWN:                    vs.WWN,
					VerifyOnly:             vrc.VerifyOnly,
					Target:                 vs.Target,
					ReferenceName:          vs.ReferenceName,
				}
			}
			if vs.HasError() {
				description := vs.ErrorDescription
				description.ErrorEntities = []*types.ErrorEntity{{
					EntityID:   vs.VolumeID.String(),
					EntityType: types.ErrorEntityVolume,
				}}
				vrs.SetErrorWithSourceAndDescription(description, types.VolumeStatus{})
			} else if vrs.IsErrorSource(types.VolumeStatus{}) {
				vrs.ClearErrorWithSource()
			}
			publishVolumeRefStatus(ctx, vrs)
		}
	}
	log.Functionf("updateVolumeRefStatus(%s) Done", vs.Key())
}
