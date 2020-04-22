// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// base os event handlers

package nodeagent

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// baseos upgrade installation path
// baseosmgr has flipped the partition state to updating,
// inform zedagent to reboot
func doZbootBaseOsInstallationComplete(ctxPtr *nodeagentContext,
	key string, zbootStatus types.ZbootStatus) {
	zbootConfig := lookupZbootConfig(ctxPtr, key)
	if zbootConfig == nil {
		log.Errorf("Partition(%s) Config not found", key)
		return
	}
	if isZbootOtherPartitionStateUpdating(ctxPtr) && !ctxPtr.deviceReboot {
		infoStr := fmt.Sprintf("NORMAL: baseos-update(%s) reboot\n", key)
		log.Infof(infoStr)
		scheduleNodeReboot(ctxPtr, infoStr)
	}
}

// baseos upgrade validation and activation path
// mark the zedcloud health/connectivity test complete flag
// for baseosmgr to pick up and complete the partition activation
func initiateBaseOsZedCloudTestComplete(ctxPtr *nodeagentContext) {
	if !ctxPtr.updateInprogress {
		return
	}
	log.Infof("initiateBaseOsZedCloudTestComplete(%s)", ctxPtr.curPart)
	// get the current partition zboot config and status
	zbootConfig := lookupZbootConfig(ctxPtr, ctxPtr.curPart)
	zbootStatus := lookupZbootStatus(ctxPtr, ctxPtr.curPart)
	if zbootStatus == nil || zbootConfig == nil {
		log.Errorf("zboot(%s) status/config get fail", ctxPtr.curPart)
		return
	}
	if zbootConfig.TestComplete {
		log.Errorf("zboot(%s) testComplete is already set", ctxPtr.curPart)
		return
	}
	log.Infof("baseOs(%s) upgrade validation testComplete, in %s",
		zbootStatus.ShortVersion, ctxPtr.curPart)
	ctxPtr.testComplete = true
	zbootConfig.TestComplete = true
	publishZbootConfig(ctxPtr, *zbootConfig)
}

// baseosmgr has acknowledged the baseos upgrade
// validation complete, by setting the partition
// state to active and setting TestComplete flag
// reset, indicating the upgrade process as complete
func doZbootBaseOsTestValidationComplete(ctxPtr *nodeagentContext,
	key string, status types.ZbootStatus) {
	if !ctxPtr.updateInprogress {
		return
	}
	// nothing to be done
	if !status.TestComplete {
		log.Debugf("%s: not TestComplete", key)
		return
	}
	config := lookupZbootConfig(ctxPtr, status.PartitionLabel)
	if config == nil || ctxPtr.updateComplete {
		return
	}
	log.Infof("baseOs(%s) upgrade validation is acknowledged, Partition %s",
		status.ShortVersion, status.PartitionLabel)
	config.TestComplete = false
	ctxPtr.updateComplete = true
	publishZbootConfig(ctxPtr, *config)
}
