// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleVolumeRefCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleVolumeRefCreate(%s)", key)
	config := configArg.(types.VolumeRefConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupVolumeRefStatus(ctx, key)
	if status != nil {
		log.Fatalf("VolumeRefStatus exists at handleVolumeRefCreate for %s", key)
	}
	vs := lookupVolumeStatus(ctx, config.VolumeKey())
	if vs != nil {
		updateVolumeStatusRefCount(ctx, vs)
		publishVolumeStatus(ctx, vs)
		status = &types.VolumeRefStatus{
			VolumeID:           config.VolumeID,
			GenerationCounter:  config.GenerationCounter,
			RefCount:           config.RefCount,
			MountDir:           config.MountDir,
			State:              vs.State,
			ActiveFileLocation: vs.FileLocation,
			ContentFormat:      vs.ContentFormat,
			ReadOnly:           vs.ReadOnly,
			DisplayName:        vs.DisplayName,
			MaxVolSize:         vs.MaxVolSize,
		}
		if vs.HasError() {
			status.SetErrorWithSource(vs.Error, types.VolumeStatus{}, vs.ErrorTime)
		} else if status.IsErrorSource(types.VolumeStatus{}) {
			status.ClearErrorWithSource()
		}
	} else {
		status = &types.VolumeRefStatus{
			VolumeID:          config.VolumeID,
			GenerationCounter: config.GenerationCounter,
			RefCount:          config.RefCount,
			State:             types.INITIAL, // Waiting for VolumeConfig from zedagent
		}
	}
	publishVolumeRefStatus(ctx, status)
	log.Infof("handleVolumeRefCreate(%s) Done", key)
}

func handleVolumeRefModify(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleVolumeRefModify(%s)", key)
	config := configArg.(types.VolumeRefConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupVolumeRefStatus(ctx, config.Key())
	if status == nil {
		log.Fatalf("VolumeRefStatus doesn't exist at handleVolumeRefModify for %s", key)
	}
	status.RefCount = config.RefCount
	publishVolumeRefStatus(ctx, status)
	vs := lookupVolumeStatus(ctx, config.VolumeKey())
	if vs != nil {
		updateVolumeStatusRefCount(ctx, vs)
		publishVolumeStatus(ctx, vs)
	}
	log.Infof("handleVolumeRefModify(%s) Done", key)
}

func handleVolumeRefDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleVolumeRefDelete(%s)", key)
	config := configArg.(types.VolumeRefConfig)
	ctx := ctxArg.(*volumemgrContext)
	unpublishVolumeRefStatus(ctx, config.Key())
	vs := lookupVolumeStatus(ctx, config.VolumeKey())
	if vs != nil {
		updateVolumeStatusRefCount(ctx, vs)
		publishVolumeStatus(ctx, vs)
		maybeDeleteVolume(ctx, vs)
	}
	log.Infof("handleVolumeRefDelete(%s) Done", key)
}

func lookupVolumeRefConfig(ctx *volumemgrContext, key string) *types.VolumeRefConfig {

	sub := ctx.subVolumeRefConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Debugf("lookupVolumeRefConfig(%s) not found", key)
		return nil
	}
	config := c.(types.VolumeRefConfig)
	return &config
}

func lookupVolumeRefStatus(ctx *volumemgrContext, key string) *types.VolumeRefStatus {

	pub := ctx.pubVolumeRefStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Debugf("lookupVolumeRefStatus(%s) not found", key)
		return nil
	}
	status := c.(types.VolumeRefStatus)
	return &status
}

func publishVolumeRefStatus(ctx *volumemgrContext, status *types.VolumeRefStatus) {

	key := status.Key()
	log.Debugf("publishVolumeRefStatus(%s)", key)
	pub := ctx.pubVolumeRefStatus
	pub.Publish(key, *status)
	log.Debugf("publishVolumeRefStatus(%s) Done", key)
}

func unpublishVolumeRefStatus(ctx *volumemgrContext, key string) {

	log.Debugf("unpublishVolumeRefStatus(%s)", key)
	pub := ctx.pubVolumeRefStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishVolumeRefStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Debugf("unpublishVolumeRefStatus(%s) Done", key)
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
				if vs.HasError() {
					status.SetErrorWithSource(vs.Error, types.VolumeStatus{}, vs.ErrorTime)
				} else if status.IsErrorSource(types.VolumeStatus{}) {
					status.ClearErrorWithSource()
				}
				publishVolumeRefStatus(ctx, status)
				return
			}
			status = &types.VolumeRefStatus{
				VolumeID:           config.VolumeID,
				GenerationCounter:  config.GenerationCounter,
				RefCount:           config.RefCount,
				MountDir:           config.MountDir,
				State:              vs.State,
				ActiveFileLocation: vs.FileLocation,
				ContentFormat:      vs.ContentFormat,
				ReadOnly:           vs.ReadOnly,
				DisplayName:        vs.DisplayName,
				MaxVolSize:         vs.MaxVolSize,
			}
			if vs.HasError() {
				status.SetErrorWithSource(vs.Error, types.VolumeStatus{}, vs.ErrorTime)
			} else if status.IsErrorSource(types.VolumeStatus{}) {
				status.ClearErrorWithSource()
			}
			publishVolumeRefStatus(ctx, status)
		}
	}
}
