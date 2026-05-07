// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestHandleNodeOperation_Reboot ensures a reboot op writes the reboot
// reason, marks all domains halted, and dispatches to zboot.Reset.
func TestHandleNodeOperation_Reboot(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.requestedRebootReason = "test-reboot"
	tc.ctx.requestedBootReason = types.BootReasonRebootCmd

	handleNodeOperation(tc.ctx, types.DeviceOperationReboot)

	if !tc.ctx.allDomainsHalted {
		t.Errorf("allDomainsHalted should be set to true")
	}
	if got := tc.zboot.resetCalled; got != 1 {
		t.Errorf("zboot.Reset call count: want 1, got %d", got)
	}
	if got := tc.zboot.poweroffCalled; got != 0 {
		t.Errorf("zboot.Poweroff call count: want 0, got %d", got)
	}
	if got := len(tc.rebootStore.written); got != 1 {
		t.Fatalf("WriteRebootReason call count: want 1, got %d", got)
	}
	w := tc.rebootStore.written[0]
	if w.reason != "test-reboot" || w.br != types.BootReasonRebootCmd ||
		w.agent != agentName || !w.last {
		t.Errorf("WriteRebootReason called with %+v", w)
	}
	pub, _ := tc.pubNodeAgentStatus.items["nodeagent"].(types.NodeAgentStatus)
	if !pub.AllDomainsHalted {
		t.Errorf("expected AllDomainsHalted=true in published status")
	}
}

func TestHandleNodeOperation_Poweroff(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.requestedRebootReason = "test-poweroff"
	tc.ctx.requestedBootReason = types.BootReasonPoweroffCmd

	handleNodeOperation(tc.ctx, types.DeviceOperationPoweroff)

	if got := tc.zboot.poweroffCalled; got != 1 {
		t.Errorf("zboot.Poweroff call count: want 1, got %d", got)
	}
	if got := tc.zboot.resetCalled; got != 0 {
		t.Errorf("zboot.Reset call count: want 0, got %d", got)
	}
	if got := len(tc.rebootStore.written); got != 1 {
		t.Errorf("WriteRebootReason call count: want 1, got %d", got)
	}
}

// TestHandleNodeOperation_Shutdown verifies that shutdown does NOT write
// the reboot reason and does NOT call zboot — it just halts domains and
// returns so the caller can leave the device powered.
func TestHandleNodeOperation_Shutdown(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.requestedRebootReason = "test-shutdown"

	handleNodeOperation(tc.ctx, types.DeviceOperationShutdown)

	if !tc.ctx.allDomainsHalted {
		t.Errorf("allDomainsHalted should be set to true")
	}
	if got := tc.zboot.resetCalled + tc.zboot.poweroffCalled; got != 0 {
		t.Errorf("zboot should not be called for shutdown, got %d calls", got)
	}
	if got := len(tc.rebootStore.written); got != 0 {
		t.Errorf("WriteRebootReason should not be called for shutdown, got %d", got)
	}
}

// TestWaitForAllDomainsHalted_ImmediateReturn ensures that when the
// subscription reports all domains deactivated, the wait loop returns
// without iterating.
func TestWaitForAllDomainsHalted_ImmediateReturn(t *testing.T) {
	tc := newTestCtx()
	tc.subDomainStatus.items["app1"] = types.DomainStatus{Activated: false}

	// If this hangs the test will time out — that's the point.
	waitForAllDomainsHalted(tc.ctx)
}

// TestWaitForAllDomainsHalted_BoundedWait ensures that even if domains
// stay activated, the loop terminates after maxDomainHaltTime ticks.
func TestWaitForAllDomainsHalted_BoundedWait(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.maxDomainHaltTime = 1
	tc.ctx.domainHaltWaitIncrement = 1
	tc.subDomainStatus.items["app1"] = types.DomainStatus{Activated: true}

	waitForAllDomainsHalted(tc.ctx)
	// no assertion: arrival at this line == bounded wait honoured
}
