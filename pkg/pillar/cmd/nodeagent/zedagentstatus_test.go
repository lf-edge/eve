// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// --- updateZedagentCloudConnectStatus -------------------------------

func TestZedagentCloudConnect_FailToSuccess(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.timeTickCount = 100
	tc.ctx.configGetStatus = types.ConfigGetFail

	updateZedagentCloudConnectStatus(tc.ctx,
		types.ZedAgentStatus{ConfigGetStatus: types.ConfigGetSuccess})

	if !tc.ctx.configGetSuccess {
		t.Errorf("expected configGetSuccess=true")
	}
	if tc.ctx.lastControllerReachableTime != 100 {
		t.Errorf("expected lastControllerReachableTime=100, got %d",
			tc.ctx.lastControllerReachableTime)
	}
}

func TestZedagentCloudConnect_VaultTestStartReset(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.timeTickCount = 200
	tc.ctx.vaultmgrReported = true  // vaultmgr already reported
	tc.ctx.configGetSuccess = false // first ever success
	tc.ctx.configGetStatus = types.ConfigGetFail
	tc.ctx.vaultTestStartTime = 50

	updateZedagentCloudConnectStatus(tc.ctx,
		types.ZedAgentStatus{ConfigGetStatus: types.ConfigGetSuccess})

	if tc.ctx.vaultTestStartTime != 200 {
		t.Errorf("expected vaultTestStartTime reset to %d, got %d",
			tc.ctx.timeTickCount, tc.ctx.vaultTestStartTime)
	}
}

func TestZedagentCloudConnect_TemporaryFail(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.timeTickCount = 300
	tc.ctx.configGetStatus = types.ConfigGetFail
	tc.ctx.updateInprogress = true
	tc.ctx.testInprogress = true

	updateZedagentCloudConnectStatus(tc.ctx,
		types.ZedAgentStatus{ConfigGetStatus: types.ConfigGetTemporaryFail})

	if tc.ctx.lastControllerReachableTime != 300 {
		t.Errorf("temp-fail should still bump reachable time, got %d",
			tc.ctx.lastControllerReachableTime)
	}
	if !tc.ctx.testInprogress {
		t.Errorf("test should be re-armed")
	}
}

func TestZedagentCloudConnect_NoChangeIsFastPath(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.timeTickCount = 100
	tc.ctx.configGetStatus = types.ConfigGetSuccess
	tc.ctx.lastControllerReachableTime = 50

	updateZedagentCloudConnectStatus(tc.ctx,
		types.ZedAgentStatus{ConfigGetStatus: types.ConfigGetSuccess})

	if tc.ctx.lastControllerReachableTime != 50 {
		t.Errorf("no-change fast path should not refresh reachable time, got %d",
			tc.ctx.lastControllerReachableTime)
	}
}

// --- handleDeviceCmd / scheduleNodeOperation ------------------------

func TestHandleDeviceCmd_Reboot(t *testing.T) {
	tc := newTestCtx()
	handleDeviceCmd(tc.ctx, types.ZedAgentStatus{
		RebootCmd:             true,
		RequestedRebootReason: "user-initiated",
		RequestedBootReason:   types.BootReasonRebootCmd,
	}, types.DeviceOperationReboot)

	if !tc.ctx.rebootCmd {
		t.Errorf("expected rebootCmd=true")
	}
	if len(tc.scheduledOps) != 1 {
		t.Fatalf("expected 1 scheduled op, got %d", len(tc.scheduledOps))
	}
	if got := tc.scheduledOps[0]; got.bootRsn != types.BootReasonRebootCmd {
		t.Errorf("expected BootReasonRebootCmd, got %v", got.bootRsn)
	}
}

func TestHandleDeviceCmd_RebootIdempotent(t *testing.T) {
	tc := newTestCtx()
	for i := 0; i < 3; i++ {
		handleDeviceCmd(tc.ctx, types.ZedAgentStatus{
			RebootCmd:           true,
			RequestedBootReason: types.BootReasonRebootCmd,
		}, types.DeviceOperationReboot)
	}
	if len(tc.scheduledOps) != 1 {
		t.Errorf("repeated RebootCmd should schedule only once, got %d",
			len(tc.scheduledOps))
	}
}

func TestHandleDeviceCmd_Shutdown(t *testing.T) {
	tc := newTestCtx()
	handleDeviceCmd(tc.ctx, types.ZedAgentStatus{
		ShutdownCmd:         true,
		RequestedBootReason: types.BootReasonRebootCmd,
	}, types.DeviceOperationShutdown)

	if !tc.ctx.shutdownCmd {
		t.Errorf("expected shutdownCmd=true")
	}
	if got := tc.scheduledOps[0]; got.op != types.DeviceOperationShutdown {
		t.Errorf("expected shutdown op, got %v", got.op)
	}
}

func TestHandleDeviceCmd_Poweroff(t *testing.T) {
	tc := newTestCtx()
	handleDeviceCmd(tc.ctx, types.ZedAgentStatus{
		PoweroffCmd:         true,
		RequestedBootReason: types.BootReasonPoweroffCmd,
	}, types.DeviceOperationPoweroff)

	if !tc.ctx.poweroffCmd {
		t.Errorf("expected poweroffCmd=true")
	}
	if got := tc.scheduledOps[0]; got.op != types.DeviceOperationPoweroff {
		t.Errorf("expected poweroff op, got %v", got.op)
	}
}

func TestHandleDeviceCmd_FlagFalseIsNoop(t *testing.T) {
	tc := newTestCtx()
	handleDeviceCmd(tc.ctx, types.ZedAgentStatus{RebootCmd: false},
		types.DeviceOperationReboot)
	if len(tc.scheduledOps) != 0 || tc.ctx.rebootCmd {
		t.Errorf("RebootCmd=false should be no-op")
	}
}

// --- handleZedAgentStatusImpl ---------------------------------------

func TestHandleZedAgentStatus_RebootDispatch(t *testing.T) {
	tc := newTestCtx()
	handleZedAgentStatusImpl(tc.ctx, "global", types.ZedAgentStatus{
		RebootCmd:           true,
		RequestedBootReason: types.BootReasonRebootCmd,
	})
	if len(tc.scheduledOps) != 1 ||
		tc.scheduledOps[0].op != types.DeviceOperationReboot {
		t.Errorf("expected reboot dispatch, got %+v", tc.scheduledOps)
	}
}

func TestHandleZedAgentStatus_CertsRefused(t *testing.T) {
	tc := newTestCtx()
	handleZedAgentStatusImpl(tc.ctx, "global", types.ZedAgentStatus{
		EdgeNodeCertsRefused: true,
	})

	if !hasMaintReason(tc.ctx,
		types.MaintenanceModeReasonEdgeNodeCertsRefused) {
		t.Errorf("expected EdgeNodeCertsRefused reason added")
	}

	// Now clear it.
	handleZedAgentStatusImpl(tc.ctx, "global", types.ZedAgentStatus{
		EdgeNodeCertsRefused: false,
	})
	if hasMaintReason(tc.ctx,
		types.MaintenanceModeReasonEdgeNodeCertsRefused) {
		t.Errorf("expected EdgeNodeCertsRefused reason cleared")
	}
}

func hasMaintReason(ctx *nodeagentContext,
	want types.MaintenanceModeReason) bool {
	for _, r := range ctx.maintModeReasons {
		if r == want {
			return true
		}
	}
	return false
}
