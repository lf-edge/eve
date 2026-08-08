// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package hypervisor

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

// TestTaskDerivesKubeName constructs a Task from a DomainStatus whose
// DisplayName/PurgeCounter match no vmiList entry, and asserts that the
// kubeName it derives is exactly what CreateReplicaVMIConfig/
// CreateReplicaPodConfig would have named the same generation.
func TestTaskDerivesKubeName(t *testing.T) {
	var ctx kubevirtContext // zero value: nil vmiList, no entries whatsoever

	appUUID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	status := &types.DomainStatus{
		UUIDandVersion: types.UUIDandVersion{UUID: appUUID},
		DisplayName:    "myapp",
		PurgeCounter:   3,
	}

	task := ctx.Task(status)
	kt, ok := task.(kubevirtTask)
	assert.True(t, ok, "Task() must return a kubevirtTask")

	// The derivation must not depend on any vmiList entry existing.
	_, found := kt.vmiList[kt.kubeName()]
	assert.False(t, found)

	want := base.GetAppKubeNameWithPurge("myapp", appUUID, 3)
	assert.Equal(t, want, kt.kubeName())
}

func TestTaskMetaType(t *testing.T) {
	var ctx kubevirtContext

	tests := []struct {
		name string
		mode types.VmMode
		want MetaDataType
	}{
		{name: "NOHYPER runs as a plain container ReplicaSet", mode: types.NOHYPER, want: IsMetaReplicaPod},
		{name: "HVM runs as a VMI ReplicaSet", mode: types.HVM, want: IsMetaReplicaVMI},
		{name: "PV (zero value) runs as a VMI ReplicaSet", mode: types.PV, want: IsMetaReplicaVMI},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := &types.DomainStatus{}
			status.VirtualizationMode = tc.mode
			kt := ctx.Task(status).(kubevirtTask)
			assert.Equal(t, tc.want, kt.metaType())
		})
	}
}
