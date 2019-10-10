// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"fmt"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	log "github.com/sirupsen/logrus"
)

// node health timer funcions

// ticker function
func handleDeviceTimers(ctx *nodeagentContext) {
	updateTickerTime(ctx)
	handleUpgradeTestValidation(ctx)
	handleFallbackOnCloudDisconnect(ctx)
	handleResetOnCloudDisconnect(ctx)
}

// for every ticker, based on the last config
// get status received from zedagent,
// update the timers
func updateTickerTime(ctx *nodeagentContext) {
	// TBD:XXX time tick may skew, apply the diff value
	ctx.timeTickCount += timeTickInterval

	// TBD:XXX get the zedagent status for connectivity health
	// rather than considering stored value
	switch ctx.configGetStatus {
	case types.ConfigGetSuccess:
		ctx.lastConfigReceivedTime = ctx.timeTickCount

	case types.ConfigGetTemporaryFail:
		resetTestStartTime(ctx)
		setTestStartTime(ctx)
	}
}

// when baseos upgrade is inprogress
// on cloud disconnect for a specified amount of time, reset the node
func handleFallbackOnCloudDisconnect(ctx *nodeagentContext) {
	if !ctx.updateInprogress {
		return
	}
	// apply the fallback time function
	// fallback timeout + wait for network address timeout
	fallbackLimit := 2 * ctx.globalConfig.FallbackIfCloudGoneTime
	timePassed := ctx.timeTickCount - ctx.lastConfigReceivedTime
	if timePassed > fallbackLimit {
		errStr := fmt.Sprintf("Exceeded fallback outage for cloud connectivity %d by %d seconds; rebooting\n",
			fallbackLimit, timePassed-fallbackLimit)
		log.Errorf(errStr)
		execReboot(ctx, errStr)
	}
}

// on cloud disconnect for a specified amount time, reset the node
func handleResetOnCloudDisconnect(ctx *nodeagentContext) {
	// apply the reset time function
	resetLimit := ctx.globalConfig.ResetIfCloudGoneTime
	timePassed := ctx.timeTickCount - ctx.lastConfigReceivedTime
	if timePassed > resetLimit {
		errStr := fmt.Sprintf("Exceeded outage for cloud connectivity %d by %d seconds; rebooting\n",
			resetLimit, timePassed-resetLimit)
		log.Errorf(errStr)
		execReboot(ctx, errStr)
	}
}

// on upgrade validation testing time expiry,
// initiate the validation completion procedure
func handleUpgradeTestValidation(ctx *nodeagentContext) {
	if !ctx.testInprogress {
		return
	}
	if checkUpgradeValidationTestTimeExpiry(ctx) {
		log.Infof("CurPart: %s, Upgrade Validation Test Complete\n",
			ctx.curPart)
		resetTestStartTime(ctx)
		initiateBaseOsZedCloudTestComplete(ctx)
		publishNodeAgentStatus(ctx)
	}
}

// check for upgrade validation time expiry
func checkUpgradeValidationTestTimeExpiry(ctx *nodeagentContext) bool {
	timePassed := ctx.timeTickCount - ctx.upgradeTestStartTime
	successLimit := ctx.globalConfig.MintimeUpdateSuccess
	if timePassed < successLimit {
		ctx.remainingTestTime = time.Second *
			time.Duration(successLimit-timePassed)
		log.Infof("CurPart: %s inprogress, waiting for %d seconds\n",
			ctx.curPart, ctx.remainingTestTime/time.Second)
		publishNodeAgentStatus(ctx)
		return false
	}
	return true
}

// baseos upgrade test validation utilities
// set the upgrade validation test start time
func setTestStartTime(ctx *nodeagentContext) {
	// only when current partition state is in progress
	// and satisfies the following conditions
	// start the test
	if !ctx.updateInprogress || ctx.testInprogress ||
		ctx.testComplete || ctx.updateComplete {
		return
	}
	log.Infof("Starting upgrade validation for %d seconds\n",
		ctx.globalConfig.MintimeUpdateSuccess)
	ctx.testInprogress = true
	ctx.upgradeTestStartTime = ctx.timeTickCount
	successLimit := ctx.globalConfig.MintimeUpdateSuccess
	ctx.remainingTestTime = time.Duration(successLimit)
}

// reset the test start time
func resetTestStartTime(ctx *nodeagentContext) {
	if !ctx.testInprogress {
		return
	}
	log.Infof("Resetting upgrade validation\n")
	ctx.testInprogress = false
	ctx.remainingTestTime = time.Second * time.Duration(0)
}

// zedagent status modification event handler
func updateZedagentCloudConnectStatus(ctx *nodeagentContext,
	status types.ZedAgentStatus) {

	// config Get Status has not changed
	if ctx.configGetStatus == status.ConfigGetStatus {
		return
	}
	ctx.configGetStatus = status.ConfigGetStatus
	switch ctx.configGetStatus {
	case types.ConfigGetSuccess:
		log.Infof("Config get from controller, is successful\n")
		ctx.lastConfigReceivedTime = ctx.timeTickCount
		setTestStartTime(ctx)

	case types.ConfigGetTemporaryFail:
		log.Infof("Config get from controller, has temporarily failed\n")
		resetTestStartTime(ctx)
		setTestStartTime(ctx)

	case types.ConfigGetReadSaved:
		log.Infof("Config is read from saved config\n")

	case types.ConfigGetFail:
		log.Infof("Config get from controller, has failed\n")
	}
}

func execReboot(ctx *nodeagentContext, rebootStr string) {

	log.Infof("execReboot(): Reboot reason(%s)\n", rebootStr)
	if ctx.needsReboot {
		log.Infof("reboot flag is already set\n")
		return
	}

	ctx.needsReboot = true
	ctx.rebootReason = rebootStr
	publishNodeAgentStatus(ctx)

	// if zedagent is not alive, handle it here
	if !isZedAgentAlive(ctx) {
		// do a sync
		log.Infof("Doing a sync..\n")
		syscall.Sync()
		duration := time.Second * time.Duration(rebootDelay)
		log.Infof("Rebooting... Starting timer for Duration(secs): %d\n",
			duration/time.Second)

		timer := time.NewTimer(duration)
		log.Infof("Timer started. Wait to expire\n")
		<-timer.C
		timer = time.NewTimer(1)
		log.Infof("Timer Expired.. Zboot.Reset()\n")
		syscall.Sync()
		<-timer.C
		zboot.Reset()
	}
}
