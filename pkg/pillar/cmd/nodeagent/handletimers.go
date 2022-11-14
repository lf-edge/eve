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

// node health timer functions

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
		scheduleNodeOperation(ctxPtr, errStr, types.BootReasonFallback,
			types.DeviceOperationReboot)
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
		scheduleNodeOperation(ctxPtr, errStr, types.BootReasonDisconnect,
			types.DeviceOperationReboot)
	} else {
		log.Tracef("handleResetOnCloudDisconnect %d seconds remaining",
			resetLimit-timePassed)
	}
}

// on upgrade validation testing time expiry,
// initiate the validation completion procedure
func handleUpgradeTestValidation(ctxPtr *nodeagentContext) {
	if !ctxPtr.testInprogress || ctxPtr.deviceReboot || ctxPtr.devicePoweroff {
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
	if ctxPtr.vaultOperational != types.TS_DISABLED {
		//TriState is either NONE(vaultmgr is not running) or
		//ENABLED(vaultmgr has reported vault to be operational)
		//In both the cases, there is nothing to be done now.
		return
	}

	//Vault has been reported to be not operational
	//This could be due to remote attestation taking time
	//Check if we have crossed cut off time
	vaultCutOffTime := ctxPtr.globalConfig.GlobalValueInt(types.VaultReadyCutOffTime)
	var timePassed uint32
	if ctxPtr.vaultmgrReported && ctxPtr.configGetSuccess {
		timePassed = ctxPtr.timeTickCount - ctxPtr.vaultTestStartTime
	}
	if timePassed > vaultCutOffTime {
		if ctxPtr.updateInprogress {
			// fail the upgrade by rebooting now
			errStr := fmt.Sprintf("Exceeded time for vault to be ready %d by %d seconds, rebooting",
				vaultCutOffTime, timePassed-vaultCutOffTime)
			log.Errorf(errStr)
			scheduleNodeOperation(ctxPtr, errStr, types.BootReasonVaultFailure,
				types.DeviceOperationReboot)
		} else {
			log.Noticef("Setting %s",
				types.MaintenanceModeReasonVaultLockedUp)
			// there is no image update in progress, this happened after a normal
			// reboot. enter maintenance mode
			ctxPtr.maintMode = true
			ctxPtr.maintModeReason = types.MaintenanceModeReasonVaultLockedUp
			publishNodeAgentStatus(ctxPtr)
		}
	} else {
		log.Functionf("handleRebootOnVaultLocked: status(%s), (%d)seconds remaining or controller connection %v, vaultmgr report %v",
			types.FormatTriState(ctxPtr.vaultOperational),
			vaultCutOffTime-timePassed, ctxPtr.configGetSuccess, ctxPtr.vaultmgrReported)
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
		if !ctxPtr.configGetSuccess && ctxPtr.vaultmgrReported {
			// reset the tickCount if vaultMgr already reported and this is the first time get to controller
			ctxPtr.vaultTestStartTime = ctxPtr.timeTickCount
		}
		ctxPtr.configGetSuccess = true
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

// zedagent is telling us to reboot/shutdown/poweroff
func handleDeviceCmd(ctxPtr *nodeagentContext, status types.ZedAgentStatus, op types.DeviceOperation) {
	switch op {
	case types.DeviceOperationReboot:
		if !status.RebootCmd || ctxPtr.rebootCmd {
			return
		}
		ctxPtr.rebootCmd = true
	case types.DeviceOperationShutdown:
		if !status.ShutdownCmd || ctxPtr.shutdownCmd {
			return
		}
		ctxPtr.shutdownCmd = true
	case types.DeviceOperationPoweroff:
		if !status.PoweroffCmd || ctxPtr.poweroffCmd {
			return
		}
		ctxPtr.poweroffCmd = true
	default:
		log.Errorf("handleDeviceCmd unknown operation: %v", op)
		return
	}
	log.Functionf("handleDeviceCmd reason %s bootReason %s",
		status.RequestedRebootReason, status.RequestedBootReason)
	scheduleNodeOperation(ctxPtr, status.RequestedRebootReason,
		status.RequestedBootReason, op)
}

func scheduleNodeOperation(ctxPtr *nodeagentContext, requestedReasonStr string, requestedBootReason types.BootReason, op types.DeviceOperation) {
	switch op {
	case types.DeviceOperationReboot:
		if ctxPtr.deviceReboot {
			log.Functionf("reboot flag is already set")
			return
		}
		ctxPtr.deviceReboot = true
	case types.DeviceOperationShutdown:
		if ctxPtr.deviceShutdown {
			log.Functionf("shutdown flag is already set")
			return
		}
		ctxPtr.deviceShutdown = true
	case types.DeviceOperationPoweroff:
		if ctxPtr.devicePoweroff {
			log.Functionf("poweroff flag is already set")
			return
		}
		ctxPtr.devicePoweroff = true
	default:
		log.Errorf("scheduleNodeOperation unknown operation: %v", op)
		return
	}
	log.Functionf("scheduleNodeOperation(): current ReBootReason: %s BootReason %s",
		requestedReasonStr, requestedBootReason.String())

	// publish, for zedagent to pick up the event
	// TBD:XXX make other agents subscribe NodeAgentStatus to
	// gracefully shutdown their states, for example
	// downloader can teardown the existing connections
	// and clean up its temporary states etc.
	ctxPtr.requestedRebootReason = requestedReasonStr
	ctxPtr.requestedBootReason = requestedBootReason
	publishNodeAgentStatus(ctxPtr)

	// in any case, execute the reboot procedure
	// with a delayed timer
	log.Functionf("Creating %s at %s", "scheduleNodeOperation", agentlog.GetMyStack())
	go handleNodeOperation(ctxPtr, op)
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
//
//	blocks till all domains are halted. Should only be invoked from
//	a thread.
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

func handleNodeOperation(ctxPtr *nodeagentContext, op types.DeviceOperation) {
	// Wait for MinRebootDelay time
	duration := time.Second * time.Duration(minRebootDelay)
	rebootTimer := time.NewTimer(duration)
	log.Functionf("handleNodeOperation: minRebootDelay timer %d seconds",
		duration/time.Second)
	<-rebootTimer.C

	if op != types.DeviceOperationShutdown {
		// set the reboot reason
		agentlog.RebootReason(ctxPtr.requestedRebootReason,
			ctxPtr.requestedBootReason, agentName, os.Getpid(), true)
	}
	// Wait for All Domains Halted
	waitForAllDomainsHalted(ctxPtr)
	ctxPtr.allDomainsHalted = true
	publishNodeAgentStatus(ctxPtr)

	// do a sync
	log.Functionf("Doing a sync..")
	syscall.Sync()
	opStr := ""
	switch op {
	case types.DeviceOperationShutdown:
		log.Functionf("Shutting down done")
		return
	case types.DeviceOperationPoweroff:
		opStr = "Power off"
	case types.DeviceOperationReboot:
		opStr = "Rebooting"
	}
	log.Functionf("%s... Starting timer for Duration(secs): %d",
		opStr, duration/time.Second)

	rebootTimer = time.NewTimer(duration)
	log.Functionf("Timer started. Wait to expire")
	<-rebootTimer.C
	rebootTimer = time.NewTimer(1)
	log.Functionf("Timer Expired.. %s", opStr)
	syscall.Sync()
	<-rebootTimer.C
	go func() {
		// in case of problems inside zboot.Reset or zboot.Poweroff
		// we will stop zedbox process after delay of 120 seconds
		// and wait for watchdog to fire.
		// This time needs to be long; if there are disks in failed state
		// a single zboot commands can take more than 20 seconds
		<-time.After(time.Second * time.Duration(120))
		log.Errorf("Timer expired.. Exit %s", agentName)
		os.Exit(0)
	}()
	if op == types.DeviceOperationPoweroff {
		zboot.Poweroff(log)
	} else {
		zboot.Reset(log)
	}
}
