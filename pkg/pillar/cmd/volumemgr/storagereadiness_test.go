// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"
	"time"

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

// A node that served volumes in single-node mode has storage cached as ready,
// and pillar survives the single->cluster transition. While kube-init still has
// to recycle the controllers, that cache must not let a volume create through,
// and it must be dropped so the next probe waits for the recycled controllers.
func TestClusterStorageReadyDropsCacheWhileRestartPending(t *testing.T) {
	savedCache, savedAt, savedPending := clusterStorageReadyCache,
		clusterStorageReadyCheckAt, controllerRestartPending
	t.Cleanup(func() {
		clusterStorageReadyCache, clusterStorageReadyCheckAt = savedCache, savedAt
		controllerRestartPending = savedPending
	})

	ctx := &volumemgrContext{hvTypeKube: true}
	clusterStorageReadyCache = true
	clusterStorageReadyCheckAt = time.Now()

	controllerRestartPending = func() bool { return true }
	assert.False(t, clusterStorageReady(ctx))
	assert.False(t, clusterStorageReadyCache, "cache kept while the recycle is pending")

	// Not EVE-k: never gated.
	assert.True(t, clusterStorageReady(&volumemgrContext{hvTypeKube: false}))
}

func TestClusterStorageReadyUsesCacheWhenNothingPending(t *testing.T) {
	savedCache, savedPending := clusterStorageReadyCache, controllerRestartPending
	t.Cleanup(func() {
		clusterStorageReadyCache = savedCache
		controllerRestartPending = savedPending
	})

	clusterStorageReadyCache = true
	controllerRestartPending = func() bool { return false }
	assert.True(t, clusterStorageReady(&volumemgrContext{hvTypeKube: true}))
}
