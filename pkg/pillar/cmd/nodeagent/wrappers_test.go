// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"testing"

	"github.com/lf-edge/eve-api/go/info"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// The Create/Modify/Delete dispatch wrappers are trivial — they unpack
// the pubsub callback args, look up the relevant *Impl, and call it.
// These tests verify each wrapper dispatches without panicking.

// --- ZedAgentStatus -------------------------------------------------

func TestZedAgentStatus_CreateModifyDelete(t *testing.T) {
	tc := newTestCtx()
	st := types.ZedAgentStatus{
		ConfigGetStatus: types.ConfigGetSuccess,
	}
	handleZedAgentStatusCreate(tc.ctx, "global", st)
	handleZedAgentStatusModify(tc.ctx, "global", st, st)
	handleZedAgentStatusDelete(tc.ctx, "global", st)
}

// --- ZbootStatus ----------------------------------------------------

func TestZbootStatus_CreateModifyDelete(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.curPart = "IMGA"
	tc.subZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active", CurrentPartition: true,
	}
	st := tc.subZbootStatus.items["IMGA"].(types.ZbootStatus)
	handleZbootStatusCreate(tc.ctx, "IMGA", st)
	handleZbootStatusModify(tc.ctx, "IMGA", st, st)
	handleZbootStatusDelete(tc.ctx, "IMGA", st)
	// Delete on an unknown key takes a different branch.
	handleZbootStatusDelete(tc.ctx, "no-such-part", types.ZbootStatus{})
}

// --- VaultStatus ----------------------------------------------------

func TestVaultStatus_CreateModify(t *testing.T) {
	tc := newTestCtx()
	st := types.VaultStatus{
		Name:               types.DefaultVaultName,
		Status:             info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
		ConversionComplete: true,
	}
	handleVaultStatusCreate(tc.ctx, "global", st)
	handleVaultStatusModify(tc.ctx, "global", st, st)
	if tc.ctx.vaultOperational != types.TS_ENABLED {
		t.Errorf("Create+Modify should drive vault to ENABLED, got %v",
			tc.ctx.vaultOperational)
	}
}

// --- VolumeMgrStatus ------------------------------------------------

func TestVolumeMgrStatus_CreateModify(t *testing.T) {
	tc := newTestCtx()
	st := types.VolumeMgrStatus{RemainingSpace: 0}
	handleVolumeMgrStatusCreate(tc.ctx, "global", st)
	handleVolumeMgrStatusModify(tc.ctx, "global", st, st)
	if !tc.ctx.maintMode {
		t.Errorf("Create+Modify with no space should set maintMode")
	}
}

// --- TpmStatus ------------------------------------------------------

func TestTpmStatus_CreateModify(t *testing.T) {
	tc := newTestCtx()
	st := types.TpmSanityStatus{
		Status: types.MaintenanceModeReasonTpmEncFailure,
	}
	handleTpmStatusCreate(tc.ctx, "global", st)
	handleTpmStatusModify(tc.ctx, "global", st, st)
	if !tc.ctx.maintMode {
		t.Errorf("Create+Modify with TPM failure should set maintMode")
	}
}

// --- NodeDrainStatus ------------------------------------------------

func TestNodeDrainStatus_CreateModifyDelete(t *testing.T) {
	tc := newTestCtx()
	st := kubeapi.NodeDrainStatus{
		Status:      kubeapi.STARTING,
		RequestedBy: kubeapi.DEVICEOP,
	}
	handleNodeDrainStatusCreate(tc.ctx, "global", st)
	handleNodeDrainStatusModify(tc.ctx, "global", st, st)
	handleNodeDrainStatusDelete(tc.ctx, "global", st)
	if !tc.ctx.waitDrainInProgress {
		t.Errorf("Create+Modify with STARTING should set waitDrainInProgress")
	}
}

// --- GlobalConfig ---------------------------------------------------

func TestGlobalConfig_DeleteIgnoresNonGlobalKey(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.subGlobalConfig = newMockPubSub()

	// "non-global" key is a fast no-op path.
	handleGlobalConfigDelete(tc.ctx, "not-global", nil)
}
