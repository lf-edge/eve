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
	handleFallbackOnCloudDisconnect(ctxPtr)
	handleResetOnCloudDisconnect(ctxPtr)
	handleUpgradeTestValidation(ctxPtr)
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
	fallbackLimit := ctxPtr.globalConfig.GlobalValueInt(types.FallbackIfCloudGoneTime)
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
	resetLimit := ctxPtr.globalConfig.GlobalValueInt(types.ResetIfCloudGoneTime)
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
	if !ctxPtr.testInprogress || ctxPtr.deviceReboot {
		return
	}
	if checkUpgradeValidationTestTimeExpiry(ctxPtr) {
		log.Infof("CurPart: %s, Upgrade Validation Test Complete",
			ctxPtr.curPart)
		resetTestStartTime(ctxPtr)
		initiateBaseOsZedCloudTestComplete(ctxPtr)
		publishNodeAgentStatus(ctxPtr)
	}
}

// check for upgrade validation time expiry
func checkUpgradeValidationTestTimeExpiry(ctxPtr *nodeagentContext) bool {
	timePassed := ctxPtr.timeTickCount - ctxPtr.upgradeTestStartTime
	successLimit := ctxPtr.globalConfig.GlobalValueInt(types.MintimeUpdateSuccess)
	if timePassed < successLimit {
		ctxPtr.remainingTestTime = time.Second *
			time.Duration(successLimit-timePassed)
		log.Infof("CurPart: %s inprogress, waiting for %d seconds",
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
	mintimeUpdateSuccess := ctxPtr.globalConfig.GlobalValueInt(types.MintimeUpdateSuccess)
	log.Infof("Starting upgrade validation for %d seconds", mintimeUpdateSuccess)
	ctxPtr.testInprogress = true
	ctxPtr.upgradeTestStartTime = ctxPtr.timeTickCount
	successLimit := mintimeUpdateSuccess
	ctxPtr.remainingTestTime = time.Second * time.Duration(successLimit)
}

// reset the test start time
func resetTestStartTime(ctxPtr *nodeagentContext) {
	if !ctxPtr.testInprogress {
		return
	}
	log.Infof("Resetting upgrade validation")
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
		log.Infof("Config get from controller, is successful")
		ctxPtr.lastConfigReceivedTime = ctxPtr.timeTickCount
		setTestStartTime(ctxPtr)

	case types.ConfigGetTemporaryFail:
		log.Infof("Config get from controller, has temporarily failed")
		resetTestStartTime(ctxPtr)
		setTestStartTime(ctxPtr)

	case types.ConfigGetReadSaved:
		log.Infof("Config is read from saved config")

	case types.ConfigGetFail:
		log.Infof("Config get from controller, has failed")
	}
}

// zedagent is telling us to reboot
func handleRebootCmd(ctxPtr *nodeagentContext, status types.ZedAgentStatus) {
	if !status.RebootCmd || ctxPtr.rebootCmd {
		return
	}
	ctxPtr.rebootCmd = true
	scheduleNodeReboot(ctxPtr, status.RebootReason)
}

func scheduleNodeReboot(ctxPtr *nodeagentContext, reasonStr string) {
	if ctxPtr.deviceReboot {
		log.Infof("reboot flag is already set")
		return
	}
	log.Infof("scheduleNodeReboot(): current RebootReason: %s", reasonStr)

	// publish, for zedagent to pick up the reboot event
	// TBD:XXX, all other agents can subscribe to nodeagent or,
	// status to gracefully shutdown their states, for example
	// downloader can teardown the existing connections
	// and clean up its temporary states etc.
	ctxPtr.deviceReboot = true
	ctxPtr.currentRebootReason = reasonStr
	publishNodeAgentStatus(ctxPtr)

	// in any case, execute the reboot procedure
	// with a delayed timer
	go handleNodeReboot(ctxPtr, reasonStr)
}

func allDomainsHalted(ctxPtr *nodeagentContext) bool {
	// Check if all domains have been halted.
	items := ctxPtr.subDomainStatus.GetAll()
	for _, c := range items {
		ds := c.(types.DomainStatus)
		if ds.Activated {
			log.Debugf("allDomainsHalted: Domain (UUID: %s, name: %s) "+
				"not halted. State: %d",
				ds.UUIDandVersion.UUID.String(), ds.DisplayName, ds.State)
			return false
		}
		log.Debugf("allDomainsHalted: %s is deactivated", ds.DisplayName)
	}
	log.Infof("allDomainsHalted: All Domains Halted.")
	return true

}

// waitForAllDomainsHalted
//  blocks till all domains are halted. Should only be invoked from
//  a thread.
func waitForAllDomainsHalted(ctxPtr *nodeagentContext) {

	var totalWaitTime uint32
	for totalWaitTime = 0; totalWaitTime < ctxPtr.maxDomainHaltTime; totalWaitTime += ctxPtr.domainHaltWaitIncrement {
		if allDomainsHalted(ctxPtr) {
			return
		}

		duration := time.Second * time.Duration(ctxPtr.domainHaltWaitIncrement)
		domainHaltWaitTimer := time.NewTimer(duration)
		log.Debugf("waitForAllDomainsHalted: Waiting for all domains to be halted. "+
			"totalWaitTime: %d sec, domainHaltWaitIncrement: %d sec",
			totalWaitTime, domainHaltWaitIncrement)
		<-domainHaltWaitTimer.C
	}
	log.Infof("waitForAllDomainsHalted: Max waittime for DomainsHalted."+
		"totalWaitTime: %d sec, maxDomainHaltTime: %d sec. Proceeding "+
		"with reboot", totalWaitTime, maxDomainHaltTime)
}

func handleNodeReboot(ctxPtr *nodeagentContext, reasonStr string) {
	// Wait for MinRebootDelay time
	duration := time.Second * time.Duration(minRebootDelay)
	rebootTimer := time.NewTimer(duration)
	log.Infof("handleNodeReboot: minRebootDelay timer %d seconds",
		duration/time.Second)
	<-rebootTimer.C

	// set the reboot reason
	agentlog.RebootReason(ctxPtr.currentRebootReason, true)

	// Wait for All Domains Halted
	waitForAllDomainsHalted(ctxPtr)

	// do a sync
	log.Infof("Doing a sync..")
	syscall.Sync()
	log.Infof("Rebooting... Starting timer for Duration(secs): %d",
		duration/time.Second)

	rebootTimer = time.NewTimer(duration)
	log.Infof("Timer started. Wait to expire")
	<-rebootTimer.C
	rebootTimer = time.NewTimer(1)
	log.Infof("Timer Expired.. Zboot.Reset()")
	syscall.Sync()
	<-rebootTimer.C
	zboot.Reset()
}
