// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// base os event handlers

package zedagent

import (
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"strings"
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

func lookupZbootStatus(ctx *zedagentContext, key string) *types.ZbootStatus {
	sub := ctx.subZbootStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Infof("lookupZbootStatus(%s) not found\n", key)
		return nil
	}
	status := cast.ZbootStatus(st)
	if status.Key() != key {
		log.Errorf("lookupZbootStatus(%s) got %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

// on baseos install and activate set, the device reboot is initiated
func initiateDeviceReboot(ctx *zedagentContext, infoStr string) {
	log.Infof("handleDeviceReboot(%s)", infoStr)
	if ctx.deviceReboot {
		return
	}
	// reboot flag is set, initiate the shutdown process
	log.Infof("initiateDeviceReboot(%s)", infoStr)
	ctx.deviceReboot = true
	ctx.rebootReason = infoStr
}

func doDeviceReboot(ctx *zedagentContext) {
	if !ctx.deviceReboot {
		return
	}
	log.Infof("Executing device reboot (%s)", ctx.rebootReason)
	shutdownAppsGlobal(ctx)
	startExecReboot(ctx.rebootReason)
}

// utility routines to access baseos partition status

func isZbootValidPartitionLabel(name string) bool {
	partitionNames := []string{"IMGA", "IMGB"}
	for _, partName := range partitionNames {
		if name == partName {
			return true
		}
	}
	return false
}

func getZbootPartitionStatusAll(ctx *zedagentContext) map[string]interface{} {
	sub := ctx.subZbootStatus
	items := sub.GetAll()
	return items
}

func getZbootPartitionStatus(ctx *zedagentContext, partName string) *types.ZbootStatus {
	partName = strings.TrimSpace(partName)
	if !isZbootValidPartitionLabel(partName) {
		log.Errorf("getZbootPartitionStatus(%s) invalid partition\n", partName)
		return nil
	}
	sub := ctx.subZbootStatus
	st, err := sub.Get(partName)
	if err != nil {
		log.Errorf("getZbootPartitionStatus(%s) not found\n", partName)
		return nil
	}
	status := cast.ZbootStatus(st)
	return &status
}

func getZbootCurrentPartition(ctx *zedagentContext) string {
	var partName string
	items := getZbootPartitionStatusAll(ctx)
	for _, st := range items {
		status := cast.ZbootStatus(st)
		if status.CurrentPartition {
			log.Debugf("getZbootCurrentPartition:%s\n", status.PartitionLabel)
			return status.PartitionLabel
		}
	}
	log.Errorf("getZbootCurrentPartition() not found\n")
	return partName
}

func getZbootOtherPartition(ctx *zedagentContext) string {
	var partName string
	items := getZbootPartitionStatusAll(ctx)
	for _, st := range items {
		status := cast.ZbootStatus(st)
		if !status.CurrentPartition {
			log.Debugf("getZbootOtherPartition:%s\n", status.PartitionLabel)
			return status.PartitionLabel
		}
	}
	log.Errorf("getZbootOtherPartition() not found\n")
	return partName
}

func isBaseOsCurrentPartition(ctx *zedagentContext, partName string) bool {
	if status := getZbootPartitionStatus(ctx, partName); status != nil {
		return status.CurrentPartition
	}
	return false
}

func isBaseOsOtherPartition(ctx *zedagentContext, partName string) bool {
	if status := getZbootPartitionStatus(ctx, partName); status != nil {
		return !status.CurrentPartition
	}
	return false
}

func isBaseOsOtherPartitionStateUpdating(ctx *zedagentContext) bool {
	partName := getZbootOtherPartition(ctx)
	if status := getZbootPartitionStatus(ctx, partName); status != nil {
		if status.PartitionState == "updating" {
			return true
		}
	}
	return false
}

func isBaseOsOtherPartitionStateInProgress(ctx *zedagentContext) bool {
	partName := getZbootOtherPartition(ctx)
	if status := getZbootPartitionStatus(ctx, partName); status != nil {
		if status.PartitionState == "inprogress" {
			return true
		}
	}
	return false
}

func isBaseOsCurrentPartitionStateInProgress(ctx *zedagentContext) bool {
	partName := getZbootCurrentPartition(ctx)
	if status := getZbootPartitionStatus(ctx, partName); status != nil {
		if status.PartitionState == "inprogress" {
			return true
		}
	}
	return false
}
