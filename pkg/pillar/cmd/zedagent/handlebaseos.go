// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// basic zboot partition status APIs

package zedagent

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	"strings"
)

// base os status event handlers
// Report BaseOsStatus to zedcloud
func handleBaseOsStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleBaseOsStatusImpl(ctxArg, key, statusArg)
}

func handleBaseOsStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleBaseOsStatusImpl(ctxArg, key, statusArg)
}

func handleBaseOsStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	triggerPublishDevInfo(ctx)
	log.Functionf("handleBaseOsStatusImpl(%s) done", key)
}

func handleBaseOsStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleBaseOsStatusDelete(%s)", key)
	ctx := ctxArg.(*zedagentContext)
	triggerPublishDevInfo(ctx)
	log.Functionf("handleBaseOsStatusDelete(%s) done", key)
}

func handleZbootStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleZbootStatusImpl(ctxArg, key, statusArg)
}

func handleZbootStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleZbootStatusImpl(ctxArg, key, statusArg)
}

func handleZbootStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	if !isZbootValidPartitionLabel(key) {
		log.Errorf("handleZbootStatusImpl: invalid key %s", key)
		return
	}
	log.Functionf("handleZbootStatusImpl: for %s", key)
	// nothing to do
	triggerPublishDevInfo(ctx)
}

func handleZbootStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	if !isZbootValidPartitionLabel(key) {
		log.Errorf("handleZbootStatusDelete: invalid key %s", key)
		return
	}
	log.Functionf("handleZbootStatusDelete: for %s", key)
	// Nothing to do
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
		log.Errorf("getZbootPartitionStatus(%s) invalid partition", partName)
		return nil
	}
	sub := ctx.subZbootStatus
	st, err := sub.Get(partName)
	if err != nil {
		log.Errorf("getZbootPartitionStatus(%s) not found", partName)
		return nil
	}
	status := st.(types.ZbootStatus)
	return &status
}

func getZbootCurrentPartition(ctx *zedagentContext) string {
	var partName string
	items := getZbootPartitionStatusAll(ctx)
	for _, st := range items {
		status := st.(types.ZbootStatus)
		if status.CurrentPartition {
			log.Tracef("getZbootCurrentPartition:%s", status.PartitionLabel)
			return status.PartitionLabel
		}
	}
	log.Errorf("getZbootCurrentPartition() not found")
	return partName
}

func getZbootOtherPartition(ctx *zedagentContext) string {
	var partName string
	items := getZbootPartitionStatusAll(ctx)
	for _, st := range items {
		status := st.(types.ZbootStatus)
		if !status.CurrentPartition {
			log.Tracef("getZbootOtherPartition:%s", status.PartitionLabel)
			return status.PartitionLabel
		}
	}
	log.Errorf("getZbootOtherPartition() not found")
	return partName
}
