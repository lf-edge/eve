// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func handleVolumeCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleVolumeCreate(%s)", key)
	config := configArg.(types.VolumeConfig)
	ctx := ctxArg.(*volumemgrContext)
	updateVolume(ctx, config)
	log.Infof("handleVolumeCreate(%s) Done", key)
}

func handleVolumeModify(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleVolumeModify(%s)", key)
	config := configArg.(types.VolumeConfig)
	ctx := ctxArg.(*volumemgrContext)
	updateVolume(ctx, config)
	log.Infof("handleVolumeModify(%s) Done", key)
}

func handleVolumeDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleVolumeDelete(%s)", key)
	config := configArg.(types.VolumeConfig)
	ctx := ctxArg.(*volumemgrContext)
	deleteVolume(ctx, config)
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

	log.Infof("lookupVolumeStatus(%s)", key)
	pub := ctx.pubVolumeStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupVolumeStatus(%s) not found", key)
		return nil
	}
	status := c.(types.VolumeStatus)
	log.Infof("lookupVolumeStatus(%s) Done", key)
	return &status
}

func updateVolume(ctx *volumemgrContext,
	config types.VolumeConfig) {

	log.Infof("updateVolume for %v", config.VolumeID)
	status := lookupVolumeStatus(ctx, config.Key())
	if status == nil {
		status = &types.VolumeStatus{
			VolumeID:                config.VolumeID,
			ContentID:               config.ContentID,
			VolumeContentOriginType: config.VolumeContentOriginType,
			MaxVolSize:              config.MaxVolSize,
			GenerationCounter:       config.GenerationCounter,
			VolumeDir:               config.VolumeDir,
			DisplayName:             config.DisplayName,
			ReadOnly:                config.ReadOnly,
			RefCount:                config.RefCount,
			LastUse:                 time.Now(),
		}
	}
	publishVolumeStatus(ctx, status)
	changed, _ := doUpdateVol(ctx, status)
	if changed {
		publishVolumeStatus(ctx, status)
	}
	log.Infof("updateVolume for %v Done", config.VolumeID)
}

func deleteVolume(ctx *volumemgrContext,
	config types.VolumeConfig) {

	log.Infof("deleteVolume for %v", config.VolumeID)
	status := lookupVolumeStatus(ctx, config.Key())
	if status == nil {
		log.Infof("deleteVolume for %v, VolumeStatus not found", config.VolumeID)
		return
	}
	if status.RefCount == 0 {
		log.Fatalf("deleteVolume: Attempting to reduce "+
			"0 RefCount. Volume Details - Name: %s, UUID: %v, ",
			status.DisplayName, status.VolumeID)
	}
	status.RefCount--
	if status.RefCount != 0 {
		publishVolumeStatus(ctx, status)
		log.Infof("deleteVolume for %v Done", config.VolumeID)
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
			// Compare to set changed?
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
		}
	}
	publishVolumeStatus(ctx, status)
	unpublishVolumeStatus(ctx, status)
	log.Infof("deleteVolume for %v Done", config.VolumeID)
}
