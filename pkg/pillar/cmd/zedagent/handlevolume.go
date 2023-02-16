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
	uuid "github.com/satori/go.uuid"
)

var volumeHash []byte

// volumeKey returns the key of the VM and OCI volumes
func volumeKey(volumeID string, generationCounter, localGenCounter int64) string {
	return fmt.Sprintf("%s#%d", volumeID, generationCounter+localGenCounter)
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
	for _, vc := range items {
		volume := vc.(types.VolumeConfig)
		uuid := volume.VolumeID.String()
		genCounter := volume.GenerationCounter
		var foundVolume, sameGenCounter bool
		var cfgVolume *zconfig.Volume
		for _, cfgVolume = range cfgVolumeList {
			// Search by UUID and (remote) Generation counter, ignore local gen. counter.
			if cfgVolume.Uuid == uuid {
				foundVolume = true
				sameGenCounter = cfgVolume.GenerationCount == genCounter
				break
			}
		}
		if !foundVolume || !sameGenCounter {
			// volume not found, delete
			log.Functionf("parseVolumeConfig: deleting %s\n", volume.Key())
			unpublishVolumeConfig(ctx, volume.Key())
			if !foundVolume {
				delLocalVolumeConfig(ctx, uuid)
			}
		} else {
			// check links from apps
			volume.HasNoAppReferences = checkVolumeHasNoAppReferences(ctx, cfgVolume, config)
			publishVolumeConfig(ctx, volume)
		}
	}

	for _, cfgVolume := range cfgVolumeList {
		volumeConfig := new(types.VolumeConfig)
		volumeConfig.VolumeID, _ = uuid.FromString(cfgVolume.GetUuid())
		volumeOrigin := cfgVolume.GetOrigin()

		var contentTreeConfig types.ContentTreeConfig
		if volumeOrigin != nil {
			volumeConfig.VolumeContentOriginType = volumeOrigin.GetType()
			volumeConfig.ContentID, _ = uuid.FromString(volumeOrigin.GetDownloadContentTreeID())

			ContentTreePtr, err := ctx.pubContentTreeConfig.Get(volumeOrigin.GetDownloadContentTreeID())
			if err == nil && ContentTreePtr != nil {
				contentTreeConfig = ContentTreePtr.(types.ContentTreeConfig)
				volumeConfig.CustomMeta = contentTreeConfig.CustomMeta
			}
		}

		volumeConfig.MaxVolSize = uint64(cfgVolume.GetMaxsizebytes())
		volumeConfig.GenerationCounter = cfgVolume.GetGenerationCount()
		if cfgVolume.GetClearText() {
			volumeConfig.Encrypted = false
		} else {
			volumeConfig.Encrypted = true
		}
		volumeConfig.DisplayName = cfgVolume.GetDisplayName()
		volumeConfig.ReadOnly = cfgVolume.GetReadonly()
		volumeConfig.RefCount = 1
		volumeConfig.HasNoAppReferences = checkVolumeHasNoAppReferences(ctx, cfgVolume, config)
		volumeConfig.Target = cfgVolume.GetTarget()

		// Add config submitted via local profile server.
		addLocalVolumeConfig(ctx, volumeConfig)

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
			if vr.Uuid == cfgVolume.GetUuid() &&
				vr.GenerationCount == cfgVolume.GenerationCount {
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
	PublishVolumeToZedCloud(ctx, uuidStr, &status, ctx.iteration, AllDest)
	ctx.iteration++
}

func handleVolumeStatusDelete(ctxArg interface{},
	key string, statusArg interface{}) {

	status := statusArg.(types.VolumeStatus)
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.VolumeID.String()
	PublishVolumeToZedCloud(ctx, uuidStr, nil, ctx.iteration, AllDest)
	ctx.iteration++
}
