// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

// Code for the interface with VolumeMgr

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// MaybeAddVolumeRefConfig publishes volume ref config with refcount
// to the volumemgr
func MaybeAddVolumeRefConfig(ctx *zedmanagerContext, appInstID uuid.UUID,
	volumeID uuid.UUID, generationCounter int64, mountDir string) {

	key := fmt.Sprintf("%s#%d", volumeID.String(), generationCounter)
	log.Functionf("MaybeAddVolumeRefConfig for %s", key)
	m := lookupVolumeRefConfig(ctx, key)
	if m != nil {
		m.RefCount++
		log.Functionf("VolumeRefConfig exists for %s to refcount %d",
			key, m.RefCount)
		publishVolumeRefConfig(ctx, m)
	} else {
		log.Tracef("MaybeAddVolumeRefConfig: add for %s", key)
		vrc := types.VolumeRefConfig{
			VolumeID:          volumeID,
			GenerationCounter: generationCounter,
			RefCount:          1,
			MountDir:          mountDir,
		}
		publishVolumeRefConfig(ctx, &vrc)
	}
	base.NewRelationObject(log, base.AddRelationType, base.AppInstanceConfigLogType, appInstID.String(),
		base.VolumeRefConfigLogType, key).Noticef("App instance to volume relation.")
	log.Functionf("MaybeAddVolumeRefConfig done for %s", key)
}

// MaybeRemoveVolumeRefConfig decreases the RefCount and deletes the VolumeRefConfig
// when the RefCount reaches zero
func MaybeRemoveVolumeRefConfig(ctx *zedmanagerContext, appInstID uuid.UUID,
	volumeID uuid.UUID, generationCounter int64) {

	key := fmt.Sprintf("%s#%d", volumeID.String(), generationCounter)
	log.Functionf("MaybeRemoveVolumeRefConfig for %s", key)
	m := lookupVolumeRefConfig(ctx, key)
	if m == nil {
		log.Functionf("MaybeRemoveVolumeRefConfig: config missing for %s", key)
		return
	}
	if m.RefCount == 0 {
		log.Fatalf("MaybeRemoveVolumeRefConfig: Attempting to reduce "+
			"0 RefCount for %s", key)
	}
	m.RefCount--
	if m.RefCount == 0 {
		log.Functionf("MaybeRemoveVolumeRefConfig deleting %s", key)
		unpublishVolumeRefConfig(ctx, key)
	} else {
		log.Functionf("MaybeRemoveVolumeRefConfig remaining RefCount %d for %s",
			m.RefCount, key)
		publishVolumeRefConfig(ctx, m)
	}
	base.NewRelationObject(log, base.DeleteRelationType, base.AppInstanceConfigLogType, appInstID.String(),
		base.VolumeRefConfigLogType, key).Noticef("App instance to volume relation.")
	log.Functionf("MaybeRemoveVolumeRefConfig done for %s", key)
}

func lookupVolumeRefConfig(ctx *zedmanagerContext, key string) *types.VolumeRefConfig {

	pub := ctx.pubVolumeRefConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Tracef("lookupVolumeRefConfig(%s) not found", key)
		return nil
	}
	config := c.(types.VolumeRefConfig)
	return &config
}

func lookupVolumeRefStatus(ctx *zedmanagerContext, key string) *types.VolumeRefStatus {

	sub := ctx.subVolumeRefStatus
	c, _ := sub.Get(key)
	if c == nil {
		log.Tracef("lookupVolumeRefStatus(%s) not found", key)
		return nil
	}
	status := c.(types.VolumeRefStatus)
	return &status
}

func publishVolumeRefConfig(ctx *zedmanagerContext, config *types.VolumeRefConfig) {

	key := config.Key()
	log.Tracef("publishVolumeRefConfig(%s)", key)
	pub := ctx.pubVolumeRefConfig
	pub.Publish(key, *config)
	log.Tracef("publishVolumeRefConfig(%s) Done", key)
}

func unpublishVolumeRefConfig(ctx *zedmanagerContext, key string) {

	log.Tracef("unpublishVolumeRefConfig(%s)", key)
	pub := ctx.pubVolumeRefConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishVolumeRefConfig(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Tracef("unpublishVolumeRefConfig(%s) Done", key)
}

func handleVolumeRefStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleVolumeRefStatusImpl(ctxArg, key, statusArg)
}

func handleVolumeRefStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleVolumeRefStatusImpl(ctxArg, key, statusArg)
}

func handleVolumeRefStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.VolumeRefStatus)
	ctx := ctxArg.(*zedmanagerContext)
	log.Functionf("handleVolumeRefStatusImpl: key:%s, name:%s",
		key, status.DisplayName)
	pub := ctx.pubAppInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		aiStatus := st.(types.AppInstanceStatus)
		for _, vrs := range aiStatus.VolumeRefStatusList {
			if vrs.GenerationCounter == status.GenerationCounter &&
				vrs.VolumeID == status.VolumeID {

				updateAIStatusUUID(ctx, aiStatus.UUIDandVersion.UUID.String())
			}
		}
	}
	log.Functionf("handleVolumeRefStatusImpl done for %s", key)
}

func handleVolumeRefStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.VolumeRefStatus)
	ctx := ctxArg.(*zedmanagerContext)
	log.Functionf("handleVolumeRefStatusDelete: key:%s, name:%s",
		key, status.DisplayName)
	pub := ctx.pubAppInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		aiStatus := st.(types.AppInstanceStatus)
		for _, vrs := range aiStatus.VolumeRefStatusList {
			if vrs.GenerationCounter == status.GenerationCounter &&
				vrs.VolumeID == status.VolumeID {

				updateAIStatusUUID(ctx, aiStatus.UUIDandVersion.UUID.String())
			}
		}
	}
	log.Functionf("handleVolumeRefStatusDelete done for %s", key)
}

func getVolumeRefStatusFromAIStatus(status *types.AppInstanceStatus,
	vrc types.VolumeRefConfig) *types.VolumeRefStatus {

	log.Tracef("getVolumeRefStatusFromAIStatus(%v)", vrc.Key())
	for i := range status.VolumeRefStatusList {
		vrs := &status.VolumeRefStatusList[i]
		if vrs.VolumeID == vrc.VolumeID && vrs.GenerationCounter == vrc.GenerationCounter {
			log.Tracef("getVolumeRefStatusFromAIStatus(%v) found %s generationCounter %d",
				vrs.Key(), vrs.DisplayName, vrs.GenerationCounter)
			return vrs
		}
	}
	log.Tracef("getVolumeRefStatusFromAIStatus(%v) Done", vrc.Key())
	return nil
}

func getVolumeRefConfigFromAIConfig(config *types.AppInstanceConfig,
	vrs types.VolumeRefStatus) *types.VolumeRefConfig {

	log.Tracef("getVolumeRefConfigFromAIConfig(%v)", vrs.Key())
	for i := range config.VolumeRefConfigList {
		vrc := &config.VolumeRefConfigList[i]
		if vrc.VolumeID == vrs.VolumeID && vrc.GenerationCounter == vrs.GenerationCounter {
			log.Tracef("getVolumeRefConfigFromAIConfig(%v) found %s generationCounter %d",
				vrs.Key(), vrs.DisplayName, vrs.GenerationCounter)
			return vrc
		}
	}
	log.Tracef("getVolumeRefConfigFromAIConfig(%v) Done", vrs.Key())
	return nil
}
