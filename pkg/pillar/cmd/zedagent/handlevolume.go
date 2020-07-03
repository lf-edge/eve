// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// volume specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/metrics"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

var volumeHash []byte

// volumeKey returns the key of the VM and OCI volumes
func volumeKey(volumeID string, generationCounter int64) string {
	return fmt.Sprintf("%s#%d", volumeID, generationCounter)
}

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
			vKey := volumeKey(cfgVolume.GetUuid(), cfgVolume.GetGenerationCount())
			if vKey == idStr {
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
		if cfgVolume.GetClearText() {
			volumeConfig.VolumeDir = types.VolumeClearDirName
		} else {
			volumeConfig.VolumeDir = types.VolumeEncryptedDirName
		}
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

func createVolumeInstanceMetrics(ctx *getconfigContext, reportMetrics *metrics.ZMetricMsg) {
	log.Debugf("Volume instance metrics started")
	sub := ctx.subVolumeStatus
	volumelist := sub.GetAll()
	if volumelist == nil || len(volumelist) == 0 {
		return
	}
	for _, volume := range volumelist {
		volumeStatus := volume.(types.VolumeStatus)
		volumeMetric := new(metrics.ZMetricVolume)
		volumeMetric.Uuid = volumeStatus.VolumeID.String()
		volumeMetric.DisplayName = volumeStatus.DisplayName
		if volumeStatus.FileLocation == "" {
			log.Infof("FileLocation is empty for %s", volumeStatus.Key())
		} else {
			getVolumeResourcesMetrics(volumeStatus.FileLocation, volumeMetric)
		}
		reportMetrics.Vm = append(reportMetrics.Vm, volumeMetric)
	}
	log.Debugf("Volume instance metrics done: %v", reportMetrics.Vm)
}

func getVolumeResourcesMetrics(name string, volumeMetric *metrics.ZMetricVolume) error {

	actualSize, maxSize, err := utils.GetVolumeSize(name)
	if err != nil {
		return err
	}
	volumeMetric.UsedBytes = actualSize
	volumeMetric.TotalBytes = maxSize
	volumeMetric.FreeBytes = maxSize - actualSize
	return nil
}
