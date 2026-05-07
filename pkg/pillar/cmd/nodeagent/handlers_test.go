// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"testing"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// --- handleVolumeMgrStatusImpl --------------------------------------

func TestVolumeMgrStatus_NoSpaceAddsReason(t *testing.T) {
	tc := newTestCtx()
	handleVolumeMgrStatusImpl(tc.ctx, "global",
		types.VolumeMgrStatus{RemainingSpace: 0})

	if !tc.ctx.maintMode {
		t.Fatalf("expected MaintenanceMode set when RemainingSpace=0")
	}
	if !hasReason(tc.ctx.maintModeReasons,
		types.MaintenanceModeReasonNoDiskSpace) {
		t.Errorf("expected NoDiskSpace reason, got %v",
			tc.ctx.maintModeReasons)
	}
}

func TestVolumeMgrStatus_SpaceClearsReason(t *testing.T) {
	tc := newTestCtx()
	addMaintenanceModeReason(tc.ctx,
		types.MaintenanceModeReasonNoDiskSpace, "fixture")

	handleVolumeMgrStatusImpl(tc.ctx, "global",
		types.VolumeMgrStatus{RemainingSpace: 1 << 30})

	if tc.ctx.maintMode {
		t.Errorf("expected MaintenanceMode cleared once space returned")
	}
}

// --- handleTpmStatusImpl --------------------------------------------

func TestTpmStatus_EncFailureAddsReason(t *testing.T) {
	tc := newTestCtx()
	handleTpmStatusImpl(tc.ctx, "global", types.TpmSanityStatus{
		Status: types.MaintenanceModeReasonTpmEncFailure,
	})

	if !hasReason(tc.ctx.maintModeReasons,
		types.MaintenanceModeReasonTpmEncFailure) {
		t.Errorf("expected TpmEncFailure reason, got %v",
			tc.ctx.maintModeReasons)
	}
}

func TestTpmStatus_OkClearsReason(t *testing.T) {
	tc := newTestCtx()
	addMaintenanceModeReason(tc.ctx,
		types.MaintenanceModeReasonTpmEncFailure, "fixture")

	handleTpmStatusImpl(tc.ctx, "global", types.TpmSanityStatus{
		Status: types.MaintenanceModeReasonNone,
	})

	if hasReason(tc.ctx.maintModeReasons,
		types.MaintenanceModeReasonTpmEncFailure) {
		t.Errorf("TpmEncFailure should be cleared, got %v",
			tc.ctx.maintModeReasons)
	}
}

// --- handleVaultStatusImpl ------------------------------------------

func TestVaultStatus_OtherVaultIgnored(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.vaultOperational = types.TS_DISABLED

	handleVaultStatusImpl(tc.ctx, "global", types.VaultStatus{
		Name:               "some-other-vault",
		Status:             info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
		ConversionComplete: true,
	})

	// Untouched because Name != DefaultVaultName.
	if tc.ctx.vaultOperational != types.TS_DISABLED {
		t.Errorf("expected vaultOperational unchanged for irrelevant vault")
	}
}

func TestVaultStatus_DefaultVaultEnabled(t *testing.T) {
	tc := newTestCtx()
	addMaintenanceModeReason(tc.ctx,
		types.MaintenanceModeReasonVaultLockedUp, "fixture")
	tc.ctx.vaultOperational = types.TS_NONE

	handleVaultStatusImpl(tc.ctx, "global", types.VaultStatus{
		Name:               types.DefaultVaultName,
		Status:             info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
		ConversionComplete: true,
	})

	if tc.ctx.vaultOperational != types.TS_ENABLED {
		t.Errorf("expected TS_ENABLED, got %v", tc.ctx.vaultOperational)
	}
	if hasReason(tc.ctx.maintModeReasons,
		types.MaintenanceModeReasonVaultLockedUp) {
		t.Errorf("VaultLockedUp should be cleared once vault is enabled")
	}
}

func TestVaultStatus_DefaultVaultError(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.vaultOperational = types.TS_ENABLED

	handleVaultStatusImpl(tc.ctx, "global", types.VaultStatus{
		Name:   types.DefaultVaultName,
		Status: info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
	})

	if tc.ctx.vaultOperational != types.TS_DISABLED {
		t.Errorf("expected TS_DISABLED on error, got %v",
			tc.ctx.vaultOperational)
	}
}

func TestVaultStatus_RecordsTestStartOnFirstReport(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.timeTickCount = 42
	tc.ctx.vaultmgrReported = false
	tc.ctx.vaultTestStartTime = 0

	handleVaultStatusImpl(tc.ctx, "global", types.VaultStatus{
		Name:               "some-vault",
		Status:             info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
		ConversionComplete: true,
	})

	if !tc.ctx.vaultmgrReported {
		t.Errorf("expected vaultmgrReported=true after first report")
	}
	if tc.ctx.vaultTestStartTime != 42 {
		t.Errorf("expected vaultTestStartTime=42, got %d",
			tc.ctx.vaultTestStartTime)
	}
}

// --- handleNodeDrainStatusImpl --------------------------------------

func TestNodeDrain_NonDeviceOpIgnored(t *testing.T) {
	tc := newTestCtx()
	handleNodeDrainStatusImpl(tc.ctx, "global", kubeapi.NodeDrainStatus{
		Status:      kubeapi.REQUESTED,
		RequestedBy: kubeapi.UPDATE,
	}, nil)
	if tc.ctx.waitDrainInProgress {
		t.Errorf("non-DEVICEOP drain should be ignored")
	}
}

func TestNodeDrain_DeviceOpInProgress(t *testing.T) {
	tc := newTestCtx()
	handleNodeDrainStatusImpl(tc.ctx, "global", kubeapi.NodeDrainStatus{
		Status:      kubeapi.STARTING,
		RequestedBy: kubeapi.DEVICEOP,
	}, nil)
	if !tc.ctx.waitDrainInProgress {
		t.Errorf("expected waitDrainInProgress=true")
	}
}

func TestNodeDrain_DeviceOpComplete(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.waitDrainInProgress = true

	handleNodeDrainStatusImpl(tc.ctx, "global", kubeapi.NodeDrainStatus{
		Status:      kubeapi.COMPLETE,
		RequestedBy: kubeapi.DEVICEOP,
	}, nil)
	if tc.ctx.waitDrainInProgress {
		t.Errorf("expected waitDrainInProgress=false after COMPLETE")
	}
}

// --- allDomainsHalted -----------------------------------------------

func TestAllDomainsHalted_Empty(t *testing.T) {
	tc := newTestCtx()
	if !allDomainsHalted(tc.ctx) {
		t.Errorf("empty domain set should be considered halted")
	}
}

func TestAllDomainsHalted_OneActivated(t *testing.T) {
	tc := newTestCtx()
	tc.subDomainStatus.items["app1"] = types.DomainStatus{
		UUIDandVersion: types.UUIDandVersion{UUID: uuid.UUID{}},
		DisplayName:    "app1",
		Activated:      true,
	}
	if allDomainsHalted(tc.ctx) {
		t.Errorf("activated domain should prevent halt")
	}
}

func TestAllDomainsHalted_AllDeactivated(t *testing.T) {
	tc := newTestCtx()
	tc.subDomainStatus.items["app1"] = types.DomainStatus{
		DisplayName: "app1", Activated: false,
	}
	tc.subDomainStatus.items["app2"] = types.DomainStatus{
		DisplayName: "app2", Activated: false,
	}
	if !allDomainsHalted(tc.ctx) {
		t.Errorf("all-deactivated domain set should be considered halted")
	}
}

func hasReason(rs types.MaintenanceModeMultiReason,
	want types.MaintenanceModeReason) bool {
	for _, r := range rs {
		if r == want {
			return true
		}
	}
	return false
}
