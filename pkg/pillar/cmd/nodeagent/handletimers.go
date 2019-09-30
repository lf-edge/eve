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

// called periodically from agentwatch context
func handleDeviceTimers(ctx *nodeagentContext) {
	handleNetworkDisconnect(ctx)
	handleFallbackOnCloudDisconnect(ctx)
	handleResetOnCloudDisconnect(ctx)
}

// when the network is still not active, for connected adapter(s)
func handleNetworkDisconnect(ctx *nodeagentContext) {
	// still nim and other modules waiting for something
	if !ctx.updateInprogress || ctx.deviceRegistered {
		return
	}
	// apply the network disconnect function
	duration := globalConfig.NetworkTestBetterInterval + globalConfig.FallbackIfCloudGoneTime
	expiryLimit := time.Second * time.Duration(duration*2)
	timePassed := time.Since(ctx.networkSetupStartTime)
	if timePassed > expiryLimit {
		errStr := fmt.Sprintf("Exceeded netowrk outage %d by %d seconds; rebooting\n",
			expiryLimit/time.Second,
			(timePassed-expiryLimit)/time.Second)
		log.Errorf(errStr)
		execReboot(ctx, errStr)
	}
}

// when baseos upgrade is in progress
// on cloud disconnect for a specified amount of time, reset the node
func handleFallbackOnCloudDisconnect(ctx *nodeagentContext) {
	if !ctx.updateInprogress || !ctx.deviceRegistered ||
		ctx.testInprogress {
		return
	}
	// apply the fallback time function
	fallbackLimit := time.Second * time.Duration(globalConfig.FallbackIfCloudGoneTime)
	timePassed := time.Since(ctx.lastConfigReceivedTime)
	if timePassed < fallbackLimit {
		errStr := fmt.Sprintf("Exceeded fallback outage for cloud connectivity %d by %d seconds; rebooting\n",
			fallbackLimit/time.Second,
			(timePassed-fallbackLimit)/time.Second)
		log.Errorf(errStr)
		execReboot(ctx, errStr)
	}
}

// on cloud disconnect for a specified amount time, reset the node
func handleResetOnCloudDisconnect(ctx *nodeagentContext) {
	// apply the reset time function
	resetLimit := time.Second * time.Duration(globalConfig.ResetIfCloudGoneTime)
	timePassed := time.Since(ctx.lastConfigReceivedTime)
	if timePassed > resetLimit {
		errStr := fmt.Sprintf("Exceeded outage for cloud connectivity %d by %d seconds; rebooting\n",
			resetLimit/time.Second,
			(timePassed-resetLimit)/time.Second)
		log.Errorf(errStr)
		execReboot(ctx, errStr)
	}
}

// baseos upgrade test validation utilities
func setTestStartTime(ctx *nodeagentContext) {
	// test has already started or, the current
	// partition is not in inprogress state,
	// nothing to do
	if !ctx.updateInprogress || ctx.testInprogress {
		return
	}
	// only when current partition state is in progress
	// start the test
	ctx.upgradeTestStartTime = time.Now()
	ctx.testInprogress = true
	successLimit := time.Second *
		time.Duration(globalConfig.MintimeUpdateSuccess)
	ctx.remainingTestTime = successLimit
	ctx.testInprogress = true
}

func resetTestStartTime(ctx *nodeagentContext) {
	if !ctx.testInprogress {
		return
	}
	// the led status has changed, incase, the test is in progress,
	// we need to start the test again, reset first
	ctx.testInprogress = false
	ctx.remainingTestTime = 0
	ctx.testInprogress = false
	if ctx.configGetFail {
		ctx.configGetFailCount = 0
		ctx.configGetFail = false
	}
}

func checkUpgradeValidationTestTimeExpiry(ctx *nodeagentContext) bool {
	if !ctx.testInprogress {
		return false
	}
	timePassed := time.Since(ctx.upgradeTestStartTime)
	successLimit := time.Second *
		time.Duration(globalConfig.MintimeUpdateSuccess)
	if timePassed < successLimit {
		ctx.remainingTestTime = successLimit - timePassed
		log.Infof("CurPart: %s inprogress, waiting for %d seconds\n",
			ctx.curPart, ctx.remainingTestTime/time.Second)
		publishNodeAgentStatus(ctx)
		return false
	}
	return true
}

func handleConfigGetFail(ctx *nodeagentContext) {
	if !ctx.testInprogress {
		return
	}
	if !ctx.configGetFail {
		ctx.configGetFail = true
	}
	ctx.configGetFailCount += 1
	if ctx.configGetFailCount >= maxConfigGetFailCount {
		resetTestStartTime(ctx)
	}
}

func updateLastConfigReceivedTime(ctx *nodeagentContext,
	status types.ZedAgentStatus) {
	log.Debugf("lastConfigReceivedtime: %v, failCount: %d \n",
		status.LastConfigReceivedTime, status.ConfigGetFailCount)
	// time stamp has not changed, since last config receive
	if ctx.lastConfigReceivedTime == status.LastConfigReceivedTime {
		handleConfigGetFail(ctx)
		return
	}
	setTestStartTime(ctx)
	ctx.lastConfigReceivedTime = status.LastConfigReceivedTime
	if checkUpgradeValidationTestTimeExpiry(ctx) {
		log.Infof("CurPart: %s, Upgrade Validation Test Complete\n",
			ctx.curPart)
		resetTestStartTime(ctx)
		initiateBaseOsZedCloudTestComplete(ctx)
		publishNodeAgentStatus(ctx)
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
