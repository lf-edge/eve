// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// base os event handlers

package nodeagent

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
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
	// This check will also handle forced fallback
	if isZbootOtherPartitionStateUpdating(ctxPtr) && !ctxPtr.deviceReboot &&
		!ctxPtr.devicePoweroff {
		var newVersion string

		partName := getZbootOtherPartition(ctxPtr)
		zbootStatus := lookupZbootStatus(ctxPtr, partName)
		if zbootStatus != nil {
			newVersion = zbootStatus.ShortVersion
		} else {
			newVersion = "(unknown)"
		}
		infoStr := fmt.Sprintf("NORMAL: baseos-update(%s) to EVE version %s reboot",
			key, newVersion)
		log.Function(infoStr)
		scheduleNodeOperation(ctxPtr, infoStr, types.BootReasonUpdate,
			types.DeviceOperationReboot)
	}
}

// baseos upgrade validation and activation path
// mark the controller health/connectivity test complete flag
// for baseosmgr to pick up and complete the partition activation
func initiateBaseOsControllerTestComplete(ctxPtr *nodeagentContext) {
	if !ctxPtr.updateInprogress {
		return
	}
	log.Functionf("initiateBaseOsControllerTestComplete(%s)", ctxPtr.curPart)
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
	log.Functionf("baseOs(%s) upgrade validation testComplete, in %s",
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
		log.Tracef("%s: not TestComplete", key)
		return
	}
	config := lookupZbootConfig(ctxPtr, status.PartitionLabel)
	if config == nil || ctxPtr.updateComplete {
		return
	}
	log.Functionf("baseOs(%s) upgrade validation is acknowledged, Partition %s",
		status.ShortVersion, status.PartitionLabel)
	config.TestComplete = false
	ctxPtr.updateComplete = true
	publishZbootConfig(ctxPtr, *config)
}
