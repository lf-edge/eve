// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
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

	if ctxPtr.updateInprogress {
		log.Noticef("handleDeviceTimers: tick=%d testInprogress=%v configGetStatus=%d configGetSuccess=%v vaultOp=%s upgradeTestStart=%d",
			ctxPtr.timeTickCount, ctxPtr.testInprogress, ctxPtr.configGetStatus, ctxPtr.configGetSuccess,
			types.FormatTriState(ctxPtr.vaultOperational), ctxPtr.upgradeTestStartTime)
	}

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
		// Clean up Extension before rollback reboot (split-rootfs support).
		// This handles the case where Extension loaded fine but controller
		// connectivity was lost — the surviving monolithic partition won't
		// have cleanup code.
		cleanupCurrentExtension(ctxPtr)
		errStr := fmt.Sprintf("Exceeded fallback outage for controller connectivity %d by %d seconds; rebooting\n",
			fallbackLimit, timePassed-fallbackLimit)
		log.Error(errStr)
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
		errStr := fmt.Sprintf("Exceeded outage for controller connectivity %d by %d seconds; rebooting\n",
			resetLimit, timePassed-resetLimit)
		log.Error(errStr)
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
		// Before marking test complete, verify Extension loaded if expected.
		// Split-rootfs images have /etc/ext-verity-roothash in Core; if present,
		// extsloader must reach "ready" state for the update to succeed.
		if !checkExtsloaderReady(ctxPtr) {
			// Extension not ready after testing window. Clean up the failed
			// Extension image before rebooting — after rollback, the old
			// partition's baseosmgr may not have cleanup code.
			cleanupCurrentExtension(ctxPtr)

			errStr := fmt.Sprintf("CurPart: %s, Extension not ready after testing window — rebooting for rollback",
				ctxPtr.curPart)
			log.Error(errStr)
			scheduleNodeOperation(ctxPtr, errStr, types.BootReasonFallback,
				types.DeviceOperationReboot)
			return
		}
		log.Functionf("CurPart: %s, Upgrade Validation Test Complete",
			ctxPtr.curPart)
		resetTestStartTime(ctxPtr)
		initiateBaseOsControllerTestComplete(ctxPtr)
		publishNodeAgentStatus(ctxPtr)
	}
}

// cleanupCurrentExtension performs a full Extension cleanup before a rollback
// reboot. Handles both mounted and unmounted cases:
//  1. Lazy-unmount the Extension filesystem (MNT_DETACH: detaches from
//     namespace immediately; running services keep open fds until reboot
//     kills them — no need for graceful stop since we're rebooting)
//  2. Close the dm-verity mapper device
//  3. Remove the Extension image file from /persist
//
// This runs on the split image before rebooting into the previous partition,
// so the old (possibly monolithic) baseosmgr doesn't need cleanup code.
func cleanupCurrentExtension(ctxPtr *nodeagentContext) {
	imgPath, err := types.ExtensionImagePath(ctxPtr.curPart)
	if err != nil {
		log.Warnf("cleanupCurrentExtension: %v", err)
		return
	}

	// Step 1: Check if Extension mount point is active and unmount
	mounts, _ := os.ReadFile("/proc/mounts")
	mounted := strings.Contains(string(mounts), types.ExtMountPoint)

	if mounted {
		// Use lazy unmount (MNT_DETACH) — detaches the mount immediately
		// even if services still have open files. They'll die on reboot.
		// A regular unmount would fail with EBUSY if services are running.
		log.Noticef("cleanupCurrentExtension: lazy-unmounting %s", types.ExtMountPoint)
		if err := syscall.Unmount(types.ExtMountPoint, syscall.MNT_DETACH); err != nil {
			log.Errorf("cleanupCurrentExtension: lazy unmount %s failed: %v", types.ExtMountPoint, err)
		}

		// Step 2: Close dm-verity mapper device
		mapperName := types.ExtVerityMapperName(imgPath)
		log.Noticef("cleanupCurrentExtension: closing verity device %s", mapperName)
		cmd := exec.Command("veritysetup", "close", mapperName)
		if out, err := cmd.CombinedOutput(); err != nil {
			// May fail if lazy unmount hasn't fully released — not fatal,
			// the mapper will be orphaned and cleaned on next boot.
			log.Warnf("cleanupCurrentExtension: veritysetup close %s: %v (%s)",
				mapperName, err, string(out))
		}
	}

	// Step 3: Remove the Extension image file
	if err := os.Remove(imgPath); err != nil && !os.IsNotExist(err) {
		log.Errorf("cleanupCurrentExtension: failed to remove %s: %v", imgPath, err)
		return
	}
	// Also clean up any temp file from CAS extraction
	os.Remove(imgPath + ".tmp")

	log.Noticef("cleanupCurrentExtension: cleanup complete for %s (was mounted: %v)", imgPath, mounted)
}

// checkExtsloaderReady verifies that extsloader has loaded the Extension
// successfully. Returns true if Extension is not expected (monolithic image)
// or if extsloader has reached "ready" state.
func checkExtsloaderReady(ctxPtr *nodeagentContext) bool {
	// If no ext-verity-roothash, this is a monolithic image — no Extension expected.
	// Use HostPath because nodeagent runs inside the pillar container; host rootfs
	// is mounted at /hostfs/.
	if _, err := os.Stat(types.ExtVerityRootHashHostPath); os.IsNotExist(err) {
		return true
	}
	// Extension is expected — check extsloader status via pubsub
	if ctxPtr.subExtsloaderStatus == nil {
		log.Warnf("checkExtsloaderReady: subscription not available")
		return false
	}
	items := ctxPtr.subExtsloaderStatus.GetAll()
	for _, item := range items {
		status, ok := item.(types.ExtsloaderStatus)
		if !ok {
			continue
		}
		if status.State == types.ExtsloaderStateReady {
			log.Functionf("checkExtsloaderReady: Extension ready (partition=%s)", status.Partition)
			return true
		}
		log.Functionf("checkExtsloaderReady: Extension state=%s reason=%s",
			status.State, status.Reason)
	}
	return false
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
	} else {
		log.Warnf("handleRebootOnVaultLocked: vault timer NOT ticking: vaultmgrReported=%v configGetSuccess=%v updateInprogress=%v",
			ctxPtr.vaultmgrReported, ctxPtr.configGetSuccess, ctxPtr.updateInprogress)
	}
	if timePassed > vaultCutOffTime {
		if ctxPtr.updateInprogress {
			// fail the upgrade by rebooting now
			errStr := fmt.Sprintf("Exceeded time for vault to be ready %d by %d seconds, rebooting",
				vaultCutOffTime, timePassed-vaultCutOffTime)
			log.Error(errStr)
			scheduleNodeOperation(ctxPtr, errStr, types.BootReasonVaultFailure,
				types.DeviceOperationReboot)
		} else {
			// there is no image update in progress, this happened after a normal
			// reboot. enter maintenance mode
			addMaintenanceModeReason(ctxPtr, types.MaintenanceModeReasonVaultLockedUp, "handleRebootOnVaultLocked")
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
		log.Warnf("Config get from controller: temporary fail (testInprogress=%v updateInprogress=%v configGetSuccess=%v)",
			ctxPtr.testInprogress, ctxPtr.updateInprogress, ctxPtr.configGetSuccess)
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
