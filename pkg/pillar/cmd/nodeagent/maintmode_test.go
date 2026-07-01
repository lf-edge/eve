// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func TestMaintenanceMode_AddAndRemove(t *testing.T) {
	initTestLog()
	ctx := &nodeagentContext{}

	addMaintenanceModeReason(ctx,
		types.MaintenanceModeReasonNoDiskSpace, "test")
	if !ctx.maintMode {
		t.Fatal("maintMode should be true after add")
	}
	if got := len(ctx.maintModeReasons); got != 1 {
		t.Fatalf("expected 1 reason, got %d", got)
	}

	// Adding the same reason a second time is a no-op.
	addMaintenanceModeReason(ctx,
		types.MaintenanceModeReasonNoDiskSpace, "test")
	if got := len(ctx.maintModeReasons); got != 1 {
		t.Fatalf("idempotent add expected 1 reason, got %d", got)
	}

	removeMaintenanceModeReason(ctx,
		types.MaintenanceModeReasonNoDiskSpace, "test")
	if ctx.maintMode {
		t.Fatal("maintMode should be cleared after last reason removed")
	}
	if got := len(ctx.maintModeReasons); got != 0 {
		t.Fatalf("expected 0 reasons, got %d", got)
	}
}

func TestMaintenanceMode_MultipleReasons(t *testing.T) {
	initTestLog()
	ctx := &nodeagentContext{}

	addMaintenanceModeReason(ctx,
		types.MaintenanceModeReasonNoDiskSpace, "test")
	addMaintenanceModeReason(ctx,
		types.MaintenanceModeReasonVaultLockedUp, "test")

	// Removing one keeps maintMode true while another remains.
	removeMaintenanceModeReason(ctx,
		types.MaintenanceModeReasonNoDiskSpace, "test")
	if !ctx.maintMode {
		t.Fatal("maintMode should remain true while another reason is set")
	}
	if got := len(ctx.maintModeReasons); got != 1 {
		t.Fatalf("expected 1 remaining reason, got %d", got)
	}
	if ctx.maintModeReasons[0] != types.MaintenanceModeReasonVaultLockedUp {
		t.Fatalf("expected VaultLockedUp to remain, got %v",
			ctx.maintModeReasons[0])
	}

	removeMaintenanceModeReason(ctx,
		types.MaintenanceModeReasonVaultLockedUp, "test")
	if ctx.maintMode {
		t.Fatal("maintMode should be cleared after last reason removed")
	}
}

func TestMaintenanceMode_RemoveFromEmpty(t *testing.T) {
	initTestLog()
	ctx := &nodeagentContext{}

	// No-op; in particular, must not flip maintMode true.
	removeMaintenanceModeReason(ctx,
		types.MaintenanceModeReasonNoDiskSpace, "test")
	if ctx.maintMode {
		t.Fatal("maintMode unexpectedly set after remove on empty ctx")
	}
}
