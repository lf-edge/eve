// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// base os event handlers

package nodeagent

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// mark the zedcloud health/connectivity test complete flag
// for baseosmgr to pick up and complete the partition activation
func initiateBaseOsZedCloudTestComplete(ctx *nodeagentContext) {
	if !ctx.updateInprogress {
		return
	}
	log.Infof("initiateBaseOsZedCloudTestComplete(%s)\n", ctx.curPart)
	// get the current partition zboot config and status
	zbootConfig := lookupZbootConfig(ctx, ctx.curPart)
	zbootStatus := lookupZbootStatus(ctx, ctx.curPart)
	if zbootStatus == nil || zbootConfig == nil {
		log.Errorf("zboot(%s) status/config get fail\n", ctx.curPart)
		return
	}
	if zbootConfig.TestComplete {
		log.Errorf("zboot(%s) testComplete is already set\n", ctx.curPart)
		return
	}
	log.Infof("baseOs(%s) upgrade validation testComplete, in %s\n",
		zbootStatus.ShortVersion, ctx.curPart)
	ctx.testComplete = true
	zbootConfig.TestComplete = true
	publishZbootConfig(ctx, *zbootConfig)
}

// baseosmgr has flipped the partition state to updating,
// inform zedagent to reboot
func doZbootBaseOsInstallationComplete(ctx *nodeagentContext,
	key string, zbootStatus types.ZbootStatus) {
	zbootConfig := lookupZbootConfig(ctx, key)
	if zbootConfig == nil {
		log.Errorf("Partition(%s) Config not found\n", key)
		return
	}
	if isZbootOtherPartitionStateUpdating(ctx) && !ctx.needsReboot {
		infoStr := fmt.Sprintf("NORMAL: baseos-update(%s) reboot\n", key)
		log.Infof(infoStr)
		execReboot(ctx, infoStr)
	}
}

// baseosmgr has acknowledged the baseos upgrade
// validation complete, by setting the partition
// state to active and setting TestComplete flag
// reset, indicating the upgrade process as complete
func doZbootBaseOsTestValidationComplete(ctx *nodeagentContext,
	key string, status types.ZbootStatus) {
	// nothing to be done
	if !status.TestComplete {
		log.Debugf("doZbootBaseOsTestValidationComplete(%s): not TestComplete\n", key)
		return
	}
	config := lookupZbootConfig(ctx, status.PartitionLabel)
	if config == nil || ctx.updateComplete {
		return
	}
	log.Infof("baseOs(%s) upgrade validation is acknowledged, Partition %s\n",
		status.ShortVersion, status.PartitionLabel)
	config.TestComplete = false
	ctx.updateComplete = true
	publishZbootConfig(ctx, *config)
	publishNodeAgentStatus(ctx)
}
