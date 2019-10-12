// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"fmt"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	log "github.com/sirupsen/logrus"
)

// node health timer funcions

// ticker function
func handleDeviceTimers(ctxPtr *nodeagentContext) {
	updateTickerTime(ctxPtr)
	handleNetworkUpTimeoutExpiry(ctxPtr)
	handleUpgradeTestValidation(ctxPtr)
	handleFallbackOnCloudDisconnect(ctxPtr)
	handleResetOnCloudDisconnect(ctxPtr)
}

// for every ticker, based on the last config
// get status received from zedagent,
// update the timers
func updateTickerTime(ctxPtr *nodeagentContext) {
	// TBD:XXX time tick may skew, apply the diff value
	ctxPtr.timeTickCount += timeTickInterval

	// TBD:XXX get the zedagent status for connectivity health
	// rather than considering stored value
	switch ctxPtr.configGetStatus {
	case types.ConfigGetSuccess:
		ctxPtr.lastConfigReceivedTime = ctxPtr.timeTickCount

	case types.ConfigGetTemporaryFail:
		resetTestStartTime(ctxPtr)
		setTestStartTime(ctxPtr)
	}
}

// handleNetworkUpEvent
func handleNetworkUpTimeoutExpiry(ctxPtr *nodeagentContext) {
	if !ctxPtr.updateInprogress || ctxPtr.DNSinitialized {
		return
	}
	// wait for network address assignment timeout
	expiryLimit := networkUpTimeout
	timePassed := ctxPtr.timeTickCount - ctxPtr.lastConfigReceivedTime
	if timePassed > expiryLimit {
		errStr := fmt.Sprintf("Exceeded network up timeout %d by %d seconds; rebooting\n",
			expiryLimit, timePassed-expiryLimit)
		log.Errorf(errStr)
		scheduleNodeReboot(ctxPtr, errStr)
	}
}

// when baseos upgrade is inprogress
// on cloud disconnect for a specified amount of time, reset the node
func handleFallbackOnCloudDisconnect(ctxPtr *nodeagentContext) {
	if !ctxPtr.updateInprogress || !ctxPtr.DNSinitialized {
		return
	}
	// apply the fallback time function,wait for fallback timeout
	fallbackLimit := ctxPtr.globalConfig.FallbackIfCloudGoneTime
	timePassed := ctxPtr.timeTickCount - ctxPtr.lastConfigReceivedTime
	if timePassed > fallbackLimit {
		errStr := fmt.Sprintf("Exceeded fallback outage for cloud connectivity %d by %d seconds; rebooting\n",
			fallbackLimit, timePassed-fallbackLimit)
		log.Errorf(errStr)
		scheduleNodeReboot(ctxPtr, errStr)
	}
}

// on cloud disconnect for a specified amount time, reset the node
func handleResetOnCloudDisconnect(ctxPtr *nodeagentContext) {
	// apply the reset time function
	resetLimit := ctxPtr.globalConfig.ResetIfCloudGoneTime
	timePassed := ctxPtr.timeTickCount - ctxPtr.lastConfigReceivedTime
	if timePassed > resetLimit {
		errStr := fmt.Sprintf("Exceeded outage for cloud connectivity %d by %d seconds; rebooting\n",
			resetLimit, timePassed-resetLimit)
		log.Errorf(errStr)
		scheduleNodeReboot(ctxPtr, errStr)
	}
}

// on upgrade validation testing time expiry,
// initiate the validation completion procedure
func handleUpgradeTestValidation(ctxPtr *nodeagentContext) {
	if !ctxPtr.testInprogress {
		return
	}
	if checkUpgradeValidationTestTimeExpiry(ctxPtr) {
		log.Infof("CurPart: %s, Upgrade Validation Test Complete\n",
			ctxPtr.curPart)
		resetTestStartTime(ctxPtr)
		initiateBaseOsZedCloudTestComplete(ctxPtr)
		publishNodeAgentStatus(ctxPtr)
	}
}

// check for upgrade validation time expiry
func checkUpgradeValidationTestTimeExpiry(ctxPtr *nodeagentContext) bool {
	timePassed := ctxPtr.timeTickCount - ctxPtr.upgradeTestStartTime
	successLimit := ctxPtr.globalConfig.MintimeUpdateSuccess
	if timePassed < successLimit {
		ctxPtr.remainingTestTime = time.Second *
			time.Duration(successLimit-timePassed)
		log.Infof("CurPart: %s inprogress, waiting for %d seconds\n",
			ctxPtr.curPart, ctxPtr.remainingTestTime/time.Second)
		publishNodeAgentStatus(ctxPtr)
		return false
	}
	return true
}

// baseos upgrade test validation utilities
// set the upgrade validation test start time
func setTestStartTime(ctxPtr *nodeagentContext) {
	// only when current partition state is in progress
	// and satisfies the following conditions
	// start the test
	if !ctxPtr.updateInprogress || ctxPtr.testInprogress ||
		ctxPtr.testComplete || ctxPtr.updateComplete {
		return
	}
	log.Infof("Starting upgrade validation for %d seconds\n",
		ctxPtr.globalConfig.MintimeUpdateSuccess)
	ctxPtr.testInprogress = true
	ctxPtr.upgradeTestStartTime = ctxPtr.timeTickCount
	successLimit := ctxPtr.globalConfig.MintimeUpdateSuccess
	ctxPtr.remainingTestTime = time.Second * time.Duration(successLimit)
}

// reset the test start time
func resetTestStartTime(ctxPtr *nodeagentContext) {
	if !ctxPtr.testInprogress {
		return
	}
	log.Infof("Resetting upgrade validation\n")
	ctxPtr.testInprogress = false
	ctxPtr.remainingTestTime = time.Second * time.Duration(0)
}

// zedagent status modification event handler
func updateZedagentCloudConnectStatus(ctxPtr *nodeagentContext,
	status types.ZedAgentStatus) {

	// config Get Status has not changed
	if ctxPtr.configGetStatus == status.ConfigGetStatus {
		return
	}
	ctxPtr.configGetStatus = status.ConfigGetStatus
	switch ctxPtr.configGetStatus {
	case types.ConfigGetSuccess:
		log.Infof("Config get from controller, is successful\n")
		ctxPtr.lastConfigReceivedTime = ctxPtr.timeTickCount
		setTestStartTime(ctxPtr)

	case types.ConfigGetTemporaryFail:
		log.Infof("Config get from controller, has temporarily failed\n")
		resetTestStartTime(ctxPtr)
		setTestStartTime(ctxPtr)

	case types.ConfigGetReadSaved:
		log.Infof("Config is read from saved config\n")

	case types.ConfigGetFail:
		log.Infof("Config get from controller, has failed\n")
	}
}

func scheduleNodeReboot(ctxPtr *nodeagentContext, reasonStr string) {
	log.Infof("scheduleNodeReboot(): Reboot reason(%s)\n", reasonStr)
	if ctxPtr.needsReboot {
		log.Infof("reboot flag is already set\n")
		return
	}

	// publish, for zedagent to pick up the reboot event
	ctxPtr.needsReboot = true
	ctxPtr.rebootReason = reasonStr
	publishNodeAgentStatus(ctxPtr)

	// set the reboot reason
	agentlog.RebootReason(reasonStr)

	// in any case, execute the reboot procedure
	// with a delayed timer
	go handleNodeReboot()
}

func handleNodeReboot() {

	duration := time.Second * time.Duration(rebootDelay)
	rebootTimer := time.NewTimer(duration)
	log.Infof("handleNodeReboot: timer %d seconds\n",
		duration/time.Second)
	<-rebootTimer.C
	// do a sync
	log.Infof("Doing a sync..\n")
	syscall.Sync()
	log.Infof("Rebooting... Starting timer for Duration(secs): %d\n",
		duration/time.Second)

	rebootTimer = time.NewTimer(duration)
	log.Infof("Timer started. Wait to expire\n")
	<-rebootTimer.C
	rebootTimer = time.NewTimer(1)
	log.Infof("Timer Expired.. Zboot.Reset()\n")
	syscall.Sync()
	<-rebootTimer.C
	zboot.Reset()
}
