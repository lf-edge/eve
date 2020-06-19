// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// volume specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

var volumeHash []byte

// volume parsing routine
func parseVolumeConfig(ctx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	log.Debugf("Started parsing volume config")
	cfgVolumeList := config.GetVolumes()
	h := sha256.New()
	for _, cfgVolume := range cfgVolumeList {
		computeConfigElementSha(h, cfgVolume)
	}
	newHash := h.Sum(nil)
	if bytes.Equal(newHash, volumeHash) {
		return
	}
	log.Infof("parseVolumeConfig: Applying updated config "+
		"Last Sha: % x, "+
		"New  Sha: % x, "+
		"Num of cfgContentInfo: %d",
		volumeHash, newHash, len(cfgVolumeList))

	volumeHash = newHash

	// First look for deleted ones
	items := ctx.pubVolumeConfig.GetAll()
	for idStr := range items {
		found := false
		for _, cfgVolume := range cfgVolumeList {
			if cfgVolume.GetUuid() == idStr {
				found = true
				break
			}
		}
		// content tree not found, delete
		if !found {
			log.Infof("parseVolumeConfig: deleting %s\n", idStr)
			unpublishVolumeConfig(ctx, idStr)
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
		volumeConfig.VolumeDir = types.VolumeEncryptedDirName
		volumeConfig.DisplayName = cfgVolume.GetDisplayName()
		volumeConfig.ReadOnly = cfgVolume.GetReadonly()
		volumeConfig.RefCount = 1
		publishVolumeConfig(ctx, *volumeConfig)
	}
	log.Debugf("parsing volume config done\n")
}

func publishVolumeConfig(ctx *getconfigContext,
	config types.VolumeConfig) {

	key := config.Key()
	log.Debugf("publishVolumeConfig(%s)\n", key)
	pub := ctx.pubVolumeConfig
	pub.Publish(key, config)
	log.Debugf("publishVolumeConfig(%s) done\n", key)
}

func unpublishVolumeConfig(ctx *getconfigContext,
	key string) {

	log.Debugf("unpublishVolumeConfig(%s)\n", key)
	pub := ctx.pubVolumeConfig
	config, _ := pub.Get(key)
	if config == nil {
		log.Errorf("unpublishVolumeConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
	log.Debugf("unpublishVolumeConfig(%s) done\n", key)
}

// volume event watch to capture transitions
// and publish to zedCloud
// Handles both create and modify events
func handleVolumeStatusModify(ctxArg interface{},
	key string, statusArg interface{}) {

	status := statusArg.(types.VolumeStatus)
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.Key()
	PublishVolumeToZedCloud(ctx, uuidStr, &status, ctx.iteration)
	ctx.iteration++
}

func handleVolumeStatusDelete(ctxArg interface{},
	key string, statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	uuidStr := key
	PublishVolumeToZedCloud(ctx, uuidStr, nil, ctx.iteration)
	ctx.iteration++
}
