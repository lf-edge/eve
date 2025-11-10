// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"slices"

	"github.com/lf-edge/eve/pkg/pillar/activeapp"
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
		checkReferences(vs, vrs)
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
		updateVolumeRefStatus(ctx, vs)
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

			checkReferences(vs, vrs)

			publishVolumeRefStatus(ctx, vrs)
		}
	}
	log.Functionf("updateVolumeRefStatus(%s) Done", vs.Key())
}

func checkReferences(vs *types.VolumeStatus, vrs *types.VolumeRefStatus) {
	// without VolumeStatus or VolumeRefStatus, it doesn't make sense to check
	if vs == nil || vrs == nil {
		return
	}

	activeAppsUUIDs, err := activeapp.LoadActiveAppInstanceUUIDs(log)
	if err != nil {
		log.Warningf("checkReferences: failed to load active app instance UUIDs: %v", err)
		activeAppsUUIDs = []string{} // Fallback to an empty list
	}
	appIsActive := slices.Contains(activeAppsUUIDs, vrs.AppUUID.String())

	// when sharing a persistent volume between multiple apps, one must use a container-based volume
	// a file-based volume cannot be shared and would result in a race condition and error - thus we check for that and log error
	// this error takes precedence over the errors coming from the volume itself
	// also this error doesn't apply to the apps that were able to run successfully (active) - only to the new ones trying to start
	if vs.RefCount > 2 && !vs.IsContainer() && !vs.ReadOnly && !appIsActive {
		errStr := fmt.Sprintf("Multiple app instances (%d) are trying to use the same file-based volume %s",
			vs.RefCount-1, vs.DisplayName)
		// don't update the error time if nothing changed
		if vrs.Error != errStr {
			log.Functionf("updateVolumeRefStatus(%s): setting the error (previous error: %s, source: %s)", vrs.Key(), vrs.Error, vrs.ErrorSourceType)
			log.Errorf(errStr)
			vrs.SetErrorWithSourceAndDescription(types.ErrorDescription{Error: errStr}, types.VolumeRefConfig{})
		}
	} else if vrs.IsErrorSource(types.VolumeRefConfig{}) {
		log.Functionf("updateVolumeRefStatus: Clearing volume ref status error %s", vrs.Error)
		vrs.ClearErrorWithSource()
	}
}
