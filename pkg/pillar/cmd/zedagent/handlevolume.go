// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// volume specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
)

var volumeHash []byte

// volumeKey returns the key of the VM and OCI volumes
func volumeKey(volumeID string, generationCounter int64) string {
	return fmt.Sprintf("%s#%d", volumeID, generationCounter)
}

// volume parsing routine
func parseVolumeConfig(ctx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	log.Tracef("Started parsing volume config")
	cfgVolumeList := config.GetVolumes()
	h := sha256.New()
	for _, cfgVolume := range cfgVolumeList {
		computeConfigElementSha(h, cfgVolume)
	}
	newHash := h.Sum(nil)
	if bytes.Equal(newHash, volumeHash) {
		return
	}
	log.Functionf("parseVolumeConfig: Applying updated config "+
		"Last Sha: % x, "+
		"New  Sha: % x, "+
		"Num of cfgContentInfo: %d",
		volumeHash, newHash, len(cfgVolumeList))

	volumeHash = newHash

	// First look for deleted ones
	items := ctx.pubVolumeConfig.GetAll()
	for idStr, vc := range items {
		found := false
		var cfgVolume *zconfig.Volume
		for _, cfgVolume = range cfgVolumeList {
			vKey := volumeKey(cfgVolume.GetUuid(), cfgVolume.GetGenerationCount())
			if vKey == idStr {
				found = true
				break
			}
		}
		// content tree not found, delete
		if !found {
			log.Functionf("parseVolumeConfig: deleting %s\n", idStr)
			unpublishVolumeConfig(ctx, idStr)
		} else {
			// check links from apps
			volumeConfig := vc.(types.VolumeConfig)
			volumeConfig.HasNoAppReferences = checkVolumeHasNoAppReferences(ctx, cfgVolume, config)
			publishVolumeConfig(ctx, volumeConfig)
		}
	}

	for _, cfgVolume := range cfgVolumeList {
		volumeConfig := new(types.VolumeConfig)
		volumeConfig.VolumeID, _ = uuid.FromString(cfgVolume.GetUuid())
		volumeOrigin := cfgVolume.GetOrigin()
		if volumeOrigin != nil {
			volumeConfig.VolumeContentOriginType = volumeOrigin.GetType()
			volumeConfig.ContentID, _ = uuid.FromString(volumeOrigin.GetDownloadContentTreeID())
		}
		volumeConfig.MaxVolSize = uint64(cfgVolume.GetMaxsizebytes())
		volumeConfig.GenerationCounter = cfgVolume.GetGenerationCount()
		if cfgVolume.GetClearText() {
			volumeConfig.VolumeDir = types.VolumeClearDirName
		} else {
			volumeConfig.VolumeDir = types.VolumeEncryptedDirName
		}
		volumeConfig.DisplayName = cfgVolume.GetDisplayName()
		volumeConfig.ReadOnly = cfgVolume.GetReadonly()
		volumeConfig.RefCount = 1
		volumeConfig.HasNoAppReferences = checkVolumeHasNoAppReferences(ctx, cfgVolume, config)
		publishVolumeConfig(ctx, *volumeConfig)
	}

	//signal publisher restarted to apply deferred changes inside volumemgr
	signalVolumeConfigRestarted(ctx)
	log.Tracef("parsing volume config done\n")
}

func signalVolumeConfigRestarted(ctx *getconfigContext) {
	log.Trace("signalVolumeConfigRestarted")
	pub := ctx.pubVolumeConfig
	pub.SignalRestarted()
	log.Trace("signalVolumeConfigRestarted done")
}

// checkVolumeHasNoAppReferences returns true if there are no apps using this image in new config
func checkVolumeHasNoAppReferences(ctx *getconfigContext, cfgVolume *zconfig.Volume,
	devConfig *zconfig.EdgeDevConfig) bool {

	appInstanceList := devConfig.GetApps()
	for _, el := range appInstanceList {
		for _, vr := range el.VolumeRefList {
			if vr.Uuid == cfgVolume.GetUuid() {
				return false
			}
		}
	}
	return true
}

func publishVolumeConfig(ctx *getconfigContext,
	config types.VolumeConfig) {

	key := config.Key()
	log.Tracef("publishVolumeConfig(%s)\n", key)
	pub := ctx.pubVolumeConfig
	pub.Publish(key, config)
	log.Tracef("publishVolumeConfig(%s) done\n", key)
}

func unpublishVolumeConfig(ctx *getconfigContext,
	key string) {

	log.Tracef("unpublishVolumeConfig(%s)\n", key)
	pub := ctx.pubVolumeConfig
	config, _ := pub.Get(key)
	if config == nil {
		log.Errorf("unpublishVolumeConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
	log.Tracef("unpublishVolumeConfig(%s) done\n", key)
}

// volume event watch to capture transitions
// and publish to zedCloud
func handleVolumeStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleVolumeStatusImpl(ctxArg, key, statusArg)
}

func handleVolumeStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleVolumeStatusImpl(ctxArg, key, statusArg)
}

func handleVolumeStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.VolumeStatus)
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.VolumeID.String()
	PublishVolumeToZedCloud(ctx, uuidStr, &status, ctx.iteration)
	ctx.iteration++
}

func handleVolumeStatusDelete(ctxArg interface{},
	key string, statusArg interface{}) {

	status := statusArg.(types.VolumeStatus)
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.VolumeID.String()
	PublishVolumeToZedCloud(ctx, uuidStr, nil, ctx.iteration)
	ctx.iteration++
}
