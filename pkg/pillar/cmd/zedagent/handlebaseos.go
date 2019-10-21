// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// basic zboot partition status APIs

package zedagent

import (
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"strings"
)

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
