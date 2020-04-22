// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// zboot config, status and util APIs

package nodeagent

import (
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	log "github.com/sirupsen/logrus"
	"strings"
)

func lookupZbootStatus(ctx *nodeagentContext, key string) *types.ZbootStatus {
	sub := ctx.subZbootStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Errorf("lookupZbootStatus(%s) not found", key)
		return nil
	}
	status := st.(types.ZbootStatus)
	return &status
}

func getZbootStatusAll(ctx *nodeagentContext) []types.ZbootStatus {
	var statuslist []types.ZbootStatus
	sub := ctx.subZbootStatus
	items := sub.GetAll()
	if len(items) == 0 {
		log.Errorf("status absent")
		return statuslist
	}
	for _, st := range items {
		status := st.(types.ZbootStatus)
		statuslist = append(statuslist, status)
	}
	return statuslist
}

func lookupZbootConfig(ctx *nodeagentContext, partName string) *types.ZbootConfig {
	partName = strings.TrimSpace(partName)
	pub := ctx.pubZbootConfig
	cg, _ := pub.Get(partName)
	if cg == nil {
		log.Errorf("lookupZbootConfig(%s) not found", partName)
		return nil
	}
	config := cg.(types.ZbootConfig)
	return &config
}

func getZbootConfigAll(ctx *nodeagentContext) []types.ZbootConfig {
	var configlist []types.ZbootConfig
	pub := ctx.pubZbootConfig
	items := pub.GetAll()
	if len(items) == 0 {
		log.Errorf("config absent")
		return configlist
	}
	for _, cg := range items {
		config := cg.(types.ZbootConfig)
		configlist = append(configlist, config)
	}
	return configlist
}

func publishZbootConfig(ctx *nodeagentContext, config types.ZbootConfig) {
	if !isValidZbootPartitionLabel(config.PartitionLabel) {
		return
	}
	pub := ctx.pubZbootConfig
	log.Debugf("publishZbootConfig: %v", config)
	pub.Publish(config.PartitionLabel, config)
	syscall.Sync()
}

func publishZbootConfigAll(ctx *nodeagentContext) {
	log.Debugf("publishZbootConfigAll")
	partitionNames := []string{"IMGA", "IMGB"}
	for _, partName := range partitionNames {
		config := types.ZbootConfig{}
		partName = strings.TrimSpace(partName)
		config.PartitionLabel = partName
		publishZbootConfig(ctx, config)
	}
	syscall.Sync()
}

func getZbootOtherPartition(ctx *nodeagentContext) string {
	items := getZbootStatusAll(ctx)
	for _, status := range items {
		if !status.CurrentPartition {
			log.Debugf("getZbootOtherPartition:%s", status.PartitionLabel)
			return status.PartitionLabel
		}
	}
	return zboot.GetOtherPartition()
}

func isZbootOtherPartitionStateUpdating(ctx *nodeagentContext) bool {
	partName := getZbootOtherPartition(ctx)
	if status := lookupZbootStatus(ctx, partName); status != nil {
		if status.PartitionState == "updating" {
			return true
		}
		return false
	}
	return zboot.IsOtherPartitionStateUpdating()
}

func isValidZbootPartitionLabel(name string) bool {
	partitionNames := []string{"IMGA", "IMGB"}
	name = strings.TrimSpace(name)
	for _, partName := range partitionNames {
		if name == partName {
			return true
		}
	}
	return false
}
