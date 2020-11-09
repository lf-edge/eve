// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

// node health timer funcions

// ticker function
func handleDeviceTimers(ctxPtr *nodeagentContext) {
	updateTickerTime(ctxPtr)

	handleFallbackOnCloudDisconnect(ctxPtr)
	handleRebootOnVaultLocked(ctxPtr)
	handleResetOnCloudDisconnect(ctxPtr)
	handleUpgradeTestValidation(ctxPtr)
}

// for every ticker, based on the last config
// get status received from zedagent since zedagent doesn't notify unless
// there is a change in the status.
// update the timers
func updateTickerTime(ctxPtr *nodeagentContext) {
	// We track relative time to avoid being confused if the year jumps from
	// 1970 when NTP sets the time.
	ctxPtr.timeTickCount += timeTickInterval

	switch ctxPtr.configGetStatus {
	case types.ConfigGetSuccess:
		ctxPtr.lastControllerReachableTime = ctxPtr.timeTickCount

	case types.ConfigGetTemporaryFail:
		// We know it is reachable even though it is not (yet) giving
		// us a config
		ctxPtr.lastControllerReachableTime = ctxPtr.timeTickCount

		// Make sure we test for N seconds after we have received a
		// config
		resetTestStartTime(ctxPtr)
		setTestStartTime(ctxPtr)
	}
}

// when baseos upgrade is inprogress
// on cloud disconnect for a specified amount of time, reset the node
func handleFallbackOnCloudDisconnect(ctxPtr *nodeagentContext) {
	if !ctxPtr.updateInprogress {
		return
	}
	// apply the fallback time function,wait for fallback timeout
	fallbackLimit := ctxPtr.globalConfig.GlobalValueInt(types.FallbackIfCloudGoneTime)
	timePassed := ctxPtr.timeTickCount - ctxPtr.lastControllerReachableTime
	if timePassed > fallbackLimit {
		errStr := fmt.Sprintf("Exceeded fallback outage for cloud connectivity %d by %d seconds; rebooting\n",
			fallbackLimit, timePassed-fallbackLimit)
		log.Errorf(errStr)
		scheduleNodeReboot(ctxPtr, errStr, types.BootReasonFallback)
	} else {
		log.Functionf("handleFallbackOnCloudDisconnect %d seconds remaining",
			fallbackLimit-timePassed)
	}
}

// on cloud disconnect for a specified amount time, reset the node
func handleResetOnCloudDisconnect(ctxPtr *nodeagentContext) {
	// apply the reset time function
	resetLimit := ctxPtr.globalConfig.GlobalValueInt(types.ResetIfCloudGoneTime)
	timePassed := ctxPtr.timeTickCount - ctxPtr.lastControllerReachableTime
	if timePassed > resetLimit {
		errStr := fmt.Sprintf("Exceeded outage for cloud connectivity %d by %d seconds; rebooting\n",
			resetLimit, timePassed-resetLimit)
		log.Errorf(errStr)
		scheduleNodeReboot(ctxPtr, errStr, types.BootReasonDisconnect)
	} else {
		log.Tracef("handleResetOnCloudDisconnect %d seconds remaining",
			resetLimit-timePassed)
	}
}

// on upgrade validation testing time expiry,
// initiate the validation completion procedure
func handleUpgradeTestValidation(ctxPtr *nodeagentContext) {
	if !ctxPtr.testInprogress || ctxPtr.deviceReboot {
		return
	}
	if checkUpgradeValidationTestTimeExpiry(ctxPtr) {
		log.Functionf("CurPart: %s, Upgrade Validation Test Complete",
			ctxPtr.curPart)
		resetTestStartTime(ctxPtr)
		initiateBaseOsZedCloudTestComplete(ctxPtr)
		publishNodeAgentStatus(ctxPtr)
	}
}

// when baseos upgrade is inprogress,
// check if vault is accessible, and if not reset the node
func handleRebootOnVaultLocked(ctxPtr *nodeagentContext) {
	if ctxPtr.vaultOperational {
		return
	}
	vaultCutOffTime := ctxPtr.globalConfig.GlobalValueInt(types.VaultReadyCutOffTime)
	timePassed := ctxPtr.timeTickCount
	if timePassed > vaultCutOffTime {
		errStr := fmt.Sprintf("Exceeded time for vault to be ready %d by %d seconds, rebooting",
			vaultCutOffTime, timePassed-vaultCutOffTime)
		log.Errorf(errStr)
		scheduleNodeReboot(ctxPtr, errStr, types.BootReasonVaultFailure)
	} else {
		log.Functionf("handleRebootOnVaultLocked %d seconds remaining",
			vaultCutOffTime-timePassed)
	}
}

// check for upgrade validation time expiry
func checkUpgradeValidationTestTimeExpiry(ctxPtr *nodeagentContext) bool {
	timePassed := ctxPtr.timeTickCount - ctxPtr.upgradeTestStartTime
	successLimit := ctxPtr.globalConfig.GlobalValueInt(types.MintimeUpdateSuccess)
	if timePassed < successLimit {
		ctxPtr.remainingTestTime = time.Second *
			time.Duration(successLimit-timePassed)
		log.Functionf("CurPart: %s inprogress, waiting for %d seconds",
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
	log.Functionf("Starting upgrade validation for %d seconds", mintimeUpdateSuccess)
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
	log.Functionf("Resetting upgrade validation")
	ctxPtr.testInprogress = false
	ctxPtr.remainingTestTime = time.Second * time.Duration(0)
}

// zedagent status modification event handler
func updateZedagentCloudConnectStatus(ctxPtr *nodeagentContext,
	status types.ZedAgentStatus) {

	log.Functionf("updateZedagentCloudConnectStatus from %d to %d",
		ctxPtr.configGetStatus, status.ConfigGetStatus)

	// config Get Status has not changed
	if ctxPtr.configGetStatus == status.ConfigGetStatus {
		return
	}
	ctxPtr.configGetStatus = status.ConfigGetStatus
	switch ctxPtr.configGetStatus {
	case types.ConfigGetSuccess:
		log.Functionf("Config get from controller, is successful")
		ctxPtr.lastControllerReachableTime = ctxPtr.timeTickCount
		setTestStartTime(ctxPtr)

	case types.ConfigGetTemporaryFail:
		log.Functionf("Config get from controller, has temporarily failed")
		// We know it is reachable even though it is not (yet) giving
		// us a config
		ctxPtr.lastControllerReachableTime = ctxPtr.timeTickCount

		// Make sure we test for N seconds after we have received a
		// config
		resetTestStartTime(ctxPtr)
		setTestStartTime(ctxPtr)

	case types.ConfigGetReadSaved:
		log.Functionf("Config is read from saved config")

	case types.ConfigGetFail:
		log.Functionf("Config get from controller has failed")
	}
}

// zedagent is telling us to reboot
func handleRebootCmd(ctxPtr *nodeagentContext, status types.ZedAgentStatus) {
	if !status.RebootCmd || ctxPtr.rebootCmd {
		return
	}
	log.Functionf("handleRebootCmd reason %s bootReason %s",
		status.RebootReason, status.BootReason.String())
	ctxPtr.rebootCmd = true
	scheduleNodeReboot(ctxPtr, status.RebootReason, status.BootReason)
}

func scheduleNodeReboot(ctxPtr *nodeagentContext, reasonStr string, bootReason types.BootReason) {
	if ctxPtr.deviceReboot {
		log.Functionf("reboot flag is already set")
		return
	}
	log.Functionf("scheduleNodeReboot(): current RebootReason: %s BootReason %s",
		reasonStr, bootReason.String())

	// publish, for zedagent to pick up the reboot event
	// TBD:XXX, all other agents can subscribe to nodeagent or,
	// status to gracefully shutdown their states, for example
	// downloader can teardown the existing connections
	// and clean up its temporary states etc.
	ctxPtr.deviceReboot = true
	ctxPtr.currentRebootReason = reasonStr
	ctxPtr.currentBootReason = bootReason
	publishNodeAgentStatus(ctxPtr)

	// in any case, execute the reboot procedure
	// with a delayed timer
	log.Functionf("Creating %s at %s", "handleNodeReboot", agentlog.GetMyStack())
	go handleNodeReboot(ctxPtr)
}

func allDomainsHalted(ctxPtr *nodeagentContext) bool {
	// Check if all domains have been halted.
	items := ctxPtr.subDomainStatus.GetAll()
	for _, c := range items {
		ds := c.(types.DomainStatus)
		if ds.Activated {
			log.Tracef("allDomainsHalted: Domain (UUID: %s, name: %s) "+
				"not halted. State: %d",
				ds.UUIDandVersion.UUID.String(), ds.DisplayName, ds.State)
			return false
		}
		log.Tracef("allDomainsHalted: %s is deactivated", ds.DisplayName)
	}
	log.Functionf("allDomainsHalted: All Domains Halted.")
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
		log.Tracef("waitForAllDomainsHalted: Waiting for all domains to be halted. "+
			"totalWaitTime: %d sec, domainHaltWaitIncrement: %d sec",
			totalWaitTime, domainHaltWaitIncrement)
		<-domainHaltWaitTimer.C
	}
	log.Functionf("waitForAllDomainsHalted: Max waittime for DomainsHalted."+
		"totalWaitTime: %d sec, maxDomainHaltTime: %d sec. Proceeding "+
		"with reboot", totalWaitTime, maxDomainHaltTime)
}

func handleNodeReboot(ctxPtr *nodeagentContext) {
	// Wait for MinRebootDelay time
	duration := time.Second * time.Duration(minRebootDelay)
	rebootTimer := time.NewTimer(duration)
	log.Functionf("handleNodeReboot: minRebootDelay timer %d seconds",
		duration/time.Second)
	<-rebootTimer.C

	// set the reboot reason
	agentlog.RebootReason(ctxPtr.currentRebootReason,
		ctxPtr.currentBootReason, agentName, os.Getpid(), true)

	// Wait for All Domains Halted
	waitForAllDomainsHalted(ctxPtr)

	// do a sync
	log.Functionf("Doing a sync..")
	syscall.Sync()
	log.Functionf("Rebooting... Starting timer for Duration(secs): %d",
		duration/time.Second)

	rebootTimer = time.NewTimer(duration)
	log.Functionf("Timer started. Wait to expire")
	<-rebootTimer.C
	rebootTimer = time.NewTimer(1)
	log.Functionf("Timer Expired.. Zboot.Reset()")
	syscall.Sync()
	<-rebootTimer.C
	zboot.Reset(log)
}
