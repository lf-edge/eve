// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package hypervisor

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/stretchr/testify/assert"
	v1 "kubevirt.io/api/core/v1"
)

func TestVirtualTPMSetupSucceedsForVMModes(t *testing.T) {
	var ctx kubevirtContext
	for _, mode := range []types.VmMode{types.PV, types.HVM, types.FML, types.LEGACY} {
		status := &types.DomainStatus{}
		status.VirtualizationMode = mode
		task := ctx.Task(status)
		assert.NoError(t, task.VirtualTPMSetup("dom", nil), "mode %v", mode)
	}
}

func TestVirtualTPMSetupRejectsNOHYPER(t *testing.T) {
	var ctx kubevirtContext
	status := &types.DomainStatus{}
	status.VirtualizationMode = types.NOHYPER
	task := ctx.Task(status)
	assert.Error(t, task.VirtualTPMSetup("dom", nil))
}

func TestVirtualTPMTerminateAndTeardownAreNoops(t *testing.T) {
	var ctx kubevirtContext
	status := &types.DomainStatus{}
	status.VirtualizationMode = types.HVM
	task := ctx.Task(status)
	assert.NoError(t, task.VirtualTPMTerminate("dom", nil))
	assert.NoError(t, task.VirtualTPMTeardown("dom", nil))
}

func TestAddTPMDeviceIsEphemeral(t *testing.T) {
	spec := &v1.VirtualMachineInstanceSpec{}
	addTPMDevice(spec)
	tpm := spec.Domain.Devices.TPM
	if assert.NotNil(t, tpm) {
		assert.Nil(t, tpm.Enabled, "TPM must be enabled by default")
		assert.Nil(t, tpm.Persistent, "TPM state must not be persistent")
	}
}
