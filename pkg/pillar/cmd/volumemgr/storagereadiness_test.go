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
	ctx := volumemgrContext{
		storageReady: false,
		storageUnmet: testUnmetCondition,
	}
	status := ctx.volumeMgrStatus(1024)
	assert.False(t, status.Initialized)
	assert.Equal(t, testUnmetCondition, status.UnmetCondition)
	assert.Equal(t, uint64(1024), status.RemainingSpace)
}

func TestVolumeMgrStatusReportsStorageReady(t *testing.T) {
	ctx := volumemgrContext{storageReady: true}
	status := ctx.volumeMgrStatus(1024)
	assert.True(t, status.Initialized)
	assert.Empty(t, status.UnmetCondition)
}
