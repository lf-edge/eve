// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// base os event handlers

package zedagent

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zboot"
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

// on baseos install and activate set, the device reboot is initiated
func handleBaseOsReboot(ctx *zedagentContext, status types.BaseOsStatus) {
	// if restart flag is set,
	// initiate the shutdown process
	if status.Reboot == true {
		log.Infof("handleBaseOsReboot for %s", status.Key())
		shutdownAppsGlobal(ctx)
		startExecReboot()
	}
}

// mark the zedcloud health/connectivity test complete flag
// for baseosmgr to pick up and complete the partition activation
func initiateBaseOsZedCloudTestComplete(ctx *getconfigContext) {
	log.Infof("initiateBaseOsZedCloudTestComplete():\n")
	pub := ctx.pubBaseOsConfig
	items := pub.GetAll()
	for key, c := range items {
		config := cast.CastBaseOsConfig(c)
		if config.TestComplete {
			continue
		}
		status := lookupBaseOsStatus(ctx.zedagentCtx, key)
		if status != nil && status.PartitionLabel != "" {
			if isBaseOsCurrentPartition(ctx.zedagentCtx, status.PartitionLabel) {
				log.Infof("initiateBaseOsZedCloudTestComplete(%s): done\n", key)
				config.TestComplete = true
				publishBaseOsConfig(ctx, &config)
			}
		}
	}
}

func handleBaseOsZedCloudTestComplete(ctx *zedagentContext, status types.BaseOsStatus) {
	if status.TestComplete {
		key := status.Key()
		log.Infof("handleBaseOsZedCloudTestComplete(%s):\n", key)
		if config := lookupBaseOsConfig(ctx.getconfigCtx, key); config != nil {
			config.TestComplete = false
			publishBaseOsConfig(ctx.getconfigCtx, config)
			log.Infof("handleBaseOsZedCloudTestComplete(%s): done\n", key)
		}
	}
}

func handleBaseOsDeviceReboot(ctx *zedagentContext, status types.BaseOsStatus) {
	// if restart flag is set,
	// initiate the shutdown process
	if status.Reboot {
		log.Infof("handleBaseOsDeviceReboot(%s)", status.Key())
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
