// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const testUnmetCondition = "timed out waiting for the condition (last unmet " +
	"condition: longhorn not ready: daemonset:longhorn-manager not running on node)"

// A node whose cluster storage never came up must say so, and name the gate it
// was still waiting on. Reporting success here is indistinguishable, to
// everything outside volumemgr, from a node that is genuinely healthy.
func TestVolumeMgrStatusReportsUnmetCondition(t *testing.T) {
	ctx := volumemgrContext{statusTrigger: make(chan struct{}, 1)}
	ctx.setStorageReadiness(false, testUnmetCondition)
	status := ctx.volumeMgrStatus(1024)
	assert.False(t, status.Initialized)
	assert.Equal(t, testUnmetCondition, status.UnmetCondition)
	assert.Equal(t, uint64(1024), status.RemainingSpace)
}

func TestVolumeMgrStatusReportsStorageReady(t *testing.T) {
	ctx := volumemgrContext{statusTrigger: make(chan struct{}, 1)}
	ctx.setStorageReadiness(true, "")
	status := ctx.volumeMgrStatus(1024)
	assert.True(t, status.Initialized)
	assert.Empty(t, status.UnmetCondition)
}

// While the EVE-k cluster-storage wait is still running the status must already
// say what is outstanding: the wait can last tens of minutes, and a node that
// reports nothing is indistinguishable from one that never started.
func TestVolumeMgrStatusReportsPendingWait(t *testing.T) {
	ctx := volumemgrContext{statusTrigger: make(chan struct{}, 1)}
	ctx.setStorageReadiness(false, storageWaitPending)
	status := ctx.volumeMgrStatus(1024)
	assert.False(t, status.Initialized)
	assert.Equal(t, storageWaitPending, status.UnmetCondition)
}

// setStorageReadiness must not block when nothing is draining the trigger, so a
// verdict recorded before the status task runs cannot wedge startup.
func TestSetStorageReadinessNeverBlocks(t *testing.T) {
	ctx := volumemgrContext{statusTrigger: make(chan struct{}, 1)}
	ctx.setStorageReadiness(false, testUnmetCondition)
	ctx.setStorageReadiness(true, "")
	ready, unmet := ctx.storageReadiness()
	assert.True(t, ready)
	assert.Empty(t, unmet)
}
