// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// base os event handlers

package zedagent

import (
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	log "github.com/sirupsen/logrus"
	"strings"
	"time"
)

func lookupBaseOsConfig(ctx *getconfigContext, key string) *types.BaseOsConfig {
	pub := ctx.pubBaseOsConfig
	st, _ := pub.Get(key)
	if st == nil {
		log.Infof("lookupBaseOsConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastBaseOsConfig(st)
	if config.Key() != key {
		log.Errorf("lookupBaseOsConfig(%s) got %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

func lookupBaseOsStatus(ctx *zedagentContext, key string) *types.BaseOsStatus {
	sub := ctx.subBaseOsStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Infof("lookupBaseOsStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastBaseOsStatus(st)
	if status.Key() != key {
		log.Errorf("lookupBaseOsStatus(%s) got %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func lookupZbootConfig(ctx *zedagentContext, key string) *types.ZbootConfig {

	pub := ctx.pubZbootConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupZbootConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastZbootConfig(c)
	if config.Key() != key {
		log.Errorf("lookupZbootConfig(%s) got %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

func lookupZbootStatus(ctx *zedagentContext, key string) *types.ZbootStatus {
	sub := ctx.subZbootStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Infof("lookupZbootStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastZbootStatus(st)
	if status.Key() != key {
		log.Errorf("lookupZbootStatus(%s) got %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func publishZbootConfig(ctx *zedagentContext, config *types.ZbootConfig) {

	key := config.Key()
	log.Debugf("publishZbootConfig key %s TestComplete %v\n",
		key, config.TestComplete)
	pub := ctx.pubZbootConfig
	pub.Publish(key, config)
}

// mark the zedcloud health/connectivity test complete flag
// for baseosmgr to pick up and complete the partition activation
func initiateBaseOsZedCloudTestComplete(ctx *zedagentContext) {

	log.Infof("initiateBaseOsZedCloudTestComplete():\n")
	partitionNames := []string{"IMGA", "IMGB"}
	for _, key := range partitionNames {
		config := lookupZbootConfig(ctx, key)
		if config == nil {
			config = &types.ZbootConfig{PartitionLabel: key}
		}
		if config.TestComplete {
			continue
		}
		status := lookupZbootStatus(ctx, key)
		if status != nil && status.PartitionLabel != "" {
			if isBaseOsCurrentPartition(ctx, status.PartitionLabel) {
				log.Infof("initiateBaseOsZedCloudTestComplete(%s): done\n", key)
				config.TestComplete = true
				publishZbootConfig(ctx, config)
			}
		}
	}
}

func doZbootTestComplete(ctx *zedagentContext, status types.ZbootStatus) {
	key := status.Key()
	if !status.TestComplete {
		log.Infof("doZbootTestComplete(%s): not TestComplete\n",
			key)
	} else {
		log.Infof("doZbootTestComplete(%s):\n", key)
		config := lookupZbootConfig(ctx, key)
		if config == nil {
			config = &types.ZbootConfig{PartitionLabel: key}
		}
		config.TestComplete = false
		publishZbootConfig(ctx, config)
		log.Infof("doZbootTestComplete(%s): done\n", key)

		if ctx.rebootCmdDeferred {
			log.Infof("TestComplete and deferred reboot\n")
			ctx.rebootCmdDeferred = false
			duration := time.Second * time.Duration(rebootDelay)
			rebootTimer = time.NewTimer(duration)
			go handleReboot(ctx.getconfigCtx)
		}
	}
}

// on baseos install and activate set, the device reboot is initiated
func doBaseOsDeviceReboot(ctx *zedagentContext, status types.BaseOsStatus) {
	// if restart flag is set,
	// initiate the shutdown process
	if status.Reboot {
		log.Infof("doBaseOsDeviceReboot(%s)", status.Key())
		shutdownAppsGlobal(ctx)
		startExecReboot()
	}
}

// utility routines to access baseos partition status

func isBaseOsValidPartitionLabel(name string) bool {
	partitionNames := []string{"IMGA", "IMGB"}
	if !zboot.IsAvailable() {
		return false
	}
	for _, partName := range partitionNames {
		if name == partName {
			return true
		}
	}
	return false
}

func getBaseOsPartitionStatusAll(ctx *zedagentContext) map[string]interface{} {
	sub := ctx.subZbootStatus
	items := sub.GetAll()
	return items
}

func getBaseOsPartitionStatus(ctx *zedagentContext, partName string) *types.ZbootStatus {
	partName = strings.TrimSpace(partName)
	if !isBaseOsValidPartitionLabel(partName) {
		log.Errorf("getBaseOsPartitionStatus(%s) invalid partition\n", partName)
		return nil
	}
	items := getBaseOsPartitionStatusAll(ctx)
	for _, st := range items {
		status := cast.CastZbootStatus(st)
		if status.PartitionLabel == partName {
			return &status
		}
	}
	log.Errorf("getBaseOsPartitionStatus(%s) not found\n", partName)
	return nil
}

func getBaseOsCurrentPartition(ctx *zedagentContext) string {
	var partName string
	if !zboot.IsAvailable() {
		log.Errorf("getBaseOsCurrentPartition, zboot not available\n")
		return partName
	}
	items := getBaseOsPartitionStatusAll(ctx)
	for _, st := range items {
		status := cast.CastZbootStatus(st)
		if status.CurrentPartition {
			log.Debugf("getBaseOsCurrentPartition:%s\n", status.PartitionLabel)
			return status.PartitionLabel
		}
	}
	log.Errorf("getBaseOsCurrentPartition() not found\n")
	return partName
}

func getBaseOsOtherPartition(ctx *zedagentContext) string {
	var partName string
	if !zboot.IsAvailable() {
		log.Errorf("getBaseOsOtherPartition, zboot not available\n")
		return partName
	}
	items := getBaseOsPartitionStatusAll(ctx)
	for _, st := range items {
		status := cast.CastZbootStatus(st)
		if !status.CurrentPartition {
			log.Debugf("getBaseOsOtherPartition:%s\n", status.PartitionLabel)
			return status.PartitionLabel
		}
	}
	log.Errorf("getBaseOsOtherPartition() not found\n")
	return partName
}

func isBaseOsCurrentPartition(ctx *zedagentContext, partName string) bool {
	if status := getBaseOsPartitionStatus(ctx, partName); status != nil {
		return status.CurrentPartition
	}
	return false
}

func isBaseOsOtherPartition(ctx *zedagentContext, partName string) bool {
	if status := getBaseOsPartitionStatus(ctx, partName); status != nil {
		return !status.CurrentPartition
	}
	return false
}

func isBaseOsOtherPartitionStateUpdating(ctx *zedagentContext) bool {
	partName := getBaseOsOtherPartition(ctx)
	if status := getBaseOsPartitionStatus(ctx, partName); status != nil {
		if status.PartitionState == "updating" {
			return true
		}
	}
	return false
}

func isBaseOsOtherPartitionStateInProgress(ctx *zedagentContext) bool {
	partName := getBaseOsOtherPartition(ctx)
	if status := getBaseOsPartitionStatus(ctx, partName); status != nil {
		if status.PartitionState == "inprogress" {
			return true
		}
	}
	return false
}

func isBaseOsCurrentPartitionStateInProgress(ctx *zedagentContext) bool {
	partName := getBaseOsCurrentPartition(ctx)
	if status := getBaseOsPartitionStatus(ctx, partName); status != nil {
		if status.PartitionState == "inprogress" {
			return true
		}
	}
	return false
}
