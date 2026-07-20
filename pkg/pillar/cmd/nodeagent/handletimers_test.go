// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// --- handleFallbackOnCloudDisconnect ---------------------------------

func TestFallbackOnCloudDisconnect_NoUpgrade(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.updateInprogress = false

	handleFallbackOnCloudDisconnect(tc.ctx)

	if len(tc.scheduledOps) != 0 {
		t.Fatalf("no upgrade in progress: should not schedule reboot")
	}
}

func TestFallbackOnCloudDisconnect_WithinLimit(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.updateInprogress = true
	limit := tc.ctx.globalConfig.GlobalValueInt(types.FallbackIfCloudGoneTime)
	tc.ctx.timeTickCount = limit / 2
	tc.ctx.lastControllerReachableTime = 0

	handleFallbackOnCloudDisconnect(tc.ctx)

	if len(tc.scheduledOps) != 0 {
		t.Fatalf("within fallback window: should not schedule reboot")
	}
}

func TestFallbackOnCloudDisconnect_Exceeded(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.updateInprogress = true
	limit := tc.ctx.globalConfig.GlobalValueInt(types.FallbackIfCloudGoneTime)
	tc.ctx.timeTickCount = limit + 100
	tc.ctx.lastControllerReachableTime = 0

	handleFallbackOnCloudDisconnect(tc.ctx)

	if len(tc.scheduledOps) != 1 {
		t.Fatalf("expected 1 reboot scheduled, got %d", len(tc.scheduledOps))
	}
	got := tc.scheduledOps[0]
	if got.op != types.DeviceOperationReboot {
		t.Errorf("expected reboot op, got %v", got.op)
	}
	if got.bootRsn != types.BootReasonFallback {
		t.Errorf("expected BootReasonFallback, got %v", got.bootRsn)
	}
}

// --- handleResetOnCloudDisconnect ------------------------------------

func TestResetOnCloudDisconnect_WithinLimit(t *testing.T) {
	tc := newTestCtx()
	limit := tc.ctx.globalConfig.GlobalValueInt(types.ResetIfCloudGoneTime)
	tc.ctx.timeTickCount = limit / 2

	handleResetOnCloudDisconnect(tc.ctx)

	if len(tc.scheduledOps) != 0 {
		t.Fatalf("within reset window: should not schedule reboot")
	}
}

func TestResetOnCloudDisconnect_Exceeded(t *testing.T) {
	tc := newTestCtx()
	limit := tc.ctx.globalConfig.GlobalValueInt(types.ResetIfCloudGoneTime)
	tc.ctx.timeTickCount = limit + 1
	tc.ctx.lastControllerReachableTime = 0

	handleResetOnCloudDisconnect(tc.ctx)

	if len(tc.scheduledOps) != 1 {
		t.Fatalf("expected reboot scheduled, got %d", len(tc.scheduledOps))
	}
	if got := tc.scheduledOps[0]; got.bootRsn != types.BootReasonDisconnect {
		t.Errorf("expected BootReasonDisconnect, got %v", got.bootRsn)
	}
}

// --- handleRebootOnVaultLocked ---------------------------------------

func TestRebootOnVaultLocked_VaultEnabled(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.vaultOperational = types.TS_ENABLED

	handleRebootOnVaultLocked(tc.ctx)

	if len(tc.scheduledOps) != 0 || tc.ctx.maintMode {
		t.Fatalf("vault enabled: should be no-op")
	}
}

func TestRebootOnVaultLocked_WithinCutoff(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.vaultOperational = types.TS_DISABLED
	tc.ctx.vaultmgrReported = true
	tc.ctx.configGetSuccess = true
	cutoff := tc.ctx.globalConfig.GlobalValueInt(types.VaultReadyCutOffTime)
	tc.ctx.vaultTestStartTime = 0
	tc.ctx.timeTickCount = cutoff / 2

	handleRebootOnVaultLocked(tc.ctx)

	if len(tc.scheduledOps) != 0 || tc.ctx.maintMode {
		t.Fatalf("within cutoff: should be no-op")
	}
}

func TestRebootOnVaultLocked_ExceededWithUpgrade(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.vaultOperational = types.TS_DISABLED
	tc.ctx.vaultmgrReported = true
	tc.ctx.configGetSuccess = true
	tc.ctx.updateInprogress = true
	cutoff := tc.ctx.globalConfig.GlobalValueInt(types.VaultReadyCutOffTime)
	tc.ctx.vaultTestStartTime = 0
	tc.ctx.timeTickCount = cutoff + 1

	handleRebootOnVaultLocked(tc.ctx)

	if len(tc.scheduledOps) != 1 {
		t.Fatalf("expected reboot, got %d ops", len(tc.scheduledOps))
	}
	if got := tc.scheduledOps[0]; got.bootRsn != types.BootReasonVaultFailure {
		t.Errorf("expected BootReasonVaultFailure, got %v", got.bootRsn)
	}
	if tc.ctx.maintMode {
		t.Errorf("maintMode should not be set when an upgrade is in flight")
	}
}

func TestRebootOnVaultLocked_ExceededWithoutUpgrade(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.vaultOperational = types.TS_DISABLED
	tc.ctx.vaultmgrReported = true
	tc.ctx.configGetSuccess = true
	tc.ctx.updateInprogress = false
	cutoff := tc.ctx.globalConfig.GlobalValueInt(types.VaultReadyCutOffTime)
	tc.ctx.vaultTestStartTime = 0
	tc.ctx.timeTickCount = cutoff + 1

	handleRebootOnVaultLocked(tc.ctx)

	if len(tc.scheduledOps) != 0 {
		t.Errorf("no upgrade: should enter maintenance, not reboot")
	}
	if !tc.ctx.maintMode {
		t.Errorf("expected MaintenanceMode set")
	}
	found := false
	for _, r := range tc.ctx.maintModeReasons {
		if r == types.MaintenanceModeReasonVaultLockedUp {
			found = true
		}
	}
	if !found {
		t.Errorf("expected VaultLockedUp reason, got %v",
			tc.ctx.maintModeReasons)
	}
}

// --- handleUpgradeTestValidation -------------------------------------

func TestUpgradeTestValidation_NotInProgress(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.testInprogress = false

	handleUpgradeTestValidation(tc.ctx)

	// Nothing to assert beyond no panic and no reboot scheduled.
	if len(tc.scheduledOps) != 0 {
		t.Fatalf("test not in progress: should not schedule reboot")
	}
}

func TestUpgradeTestValidation_StillCounting(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.testInprogress = true
	tc.ctx.updateInprogress = true
	tc.ctx.curPart = "IMGA"
	limit := tc.ctx.globalConfig.GlobalValueInt(types.MintimeUpdateSuccess)
	tc.ctx.upgradeTestStartTime = 0
	tc.ctx.timeTickCount = limit / 2

	handleUpgradeTestValidation(tc.ctx)

	if tc.ctx.testComplete {
		t.Errorf("test should not be complete yet")
	}
	if tc.ctx.remainingTestTime <= 0 {
		t.Errorf("remainingTestTime should be > 0, got %v",
			tc.ctx.remainingTestTime)
	}
}

func TestUpgradeTestValidation_Expires(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.testInprogress = true
	tc.ctx.updateInprogress = true
	tc.ctx.curPart = "IMGA"
	// Pre-populate the ZbootConfig that initiateBaseOsControllerTestComplete
	// will read+update.
	tc.pubZbootConfig.items["IMGA"] = types.ZbootConfig{
		PartitionLabel: "IMGA", TestComplete: false,
	}
	tc.subZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", CurrentPartition: true,
		PartitionState: "inprogress", ShortVersion: "v2",
	}
	limit := tc.ctx.globalConfig.GlobalValueInt(types.MintimeUpdateSuccess)
	tc.ctx.upgradeTestStartTime = 0
	tc.ctx.timeTickCount = limit + 1

	handleUpgradeTestValidation(tc.ctx)

	if !tc.ctx.testComplete {
		t.Errorf("expected testComplete=true after expiry")
	}
	got, _ := tc.pubZbootConfig.items["IMGA"].(types.ZbootConfig)
	if !got.TestComplete {
		t.Errorf("expected ZbootConfig.TestComplete=true, got %+v", got)
	}
}

// --- updateTickerTime + handleDeviceTimers integration ---------------

func TestUpdateTickerTime_Advances(t *testing.T) {
	tc := newTestCtx()
	before := tc.ctx.timeTickCount
	updateTickerTime(tc.ctx)
	if tc.ctx.timeTickCount != before+timeTickInterval {
		t.Errorf("timeTickCount should advance by %d, got %d → %d",
			timeTickInterval, before, tc.ctx.timeTickCount)
	}
}

func TestUpdateTickerTime_ConfigGetSuccessRefreshes(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.timeTickCount = 100
	tc.ctx.configGetStatus = types.ConfigGetSuccess

	updateTickerTime(tc.ctx)

	if tc.ctx.lastControllerReachableTime != tc.ctx.timeTickCount {
		t.Errorf("lastControllerReachableTime should be refreshed to %d, got %d",
			tc.ctx.timeTickCount, tc.ctx.lastControllerReachableTime)
	}
}

// --- pubsub publish smoke check --------------------------------------
//
// Ensures the recorded reason on a scheduled op survives the
// publishNodeAgentStatus call inside scheduleNodeOperation.
func TestScheduleNodeOperation_PublishesStatus(t *testing.T) {
	tc := newTestCtx()
	scheduleNodeOperation(tc.ctx, "test-reason",
		types.BootReasonRebootCmd, types.DeviceOperationReboot)

	if len(tc.scheduledOps) != 1 {
		t.Fatalf("expected exactly 1 scheduled op, got %d",
			len(tc.scheduledOps))
	}
	pub, _ := tc.pubNodeAgentStatus.items["nodeagent"].(types.NodeAgentStatus)
	if !pub.DeviceReboot {
		t.Errorf("expected DeviceReboot=true in published status")
	}
	if !strings.Contains(tc.scheduledOps[0].reason, "test-reason") {
		t.Errorf("expected scheduled reason to contain test-reason, got %q",
			tc.scheduledOps[0].reason)
	}
}

func TestScheduleNodeOperation_Idempotent(t *testing.T) {
	tc := newTestCtx()
	scheduleNodeOperation(tc.ctx, "r", types.BootReasonRebootCmd,
		types.DeviceOperationReboot)
	scheduleNodeOperation(tc.ctx, "r", types.BootReasonRebootCmd,
		types.DeviceOperationReboot)

	if len(tc.scheduledOps) != 1 {
		t.Errorf("second reboot schedule should be a no-op, got %d ops",
			len(tc.scheduledOps))
	}
}

// silence "imported and not used" if a future edit drops time usage
var _ = time.Second
