// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package hypervisor

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

// newInfoTestTask builds a kubevirtTask ready to call Info/replicaSetUID
// against a mocked kubevirt client, with an arbitrary non-zero
// status.DomainId sentinel so tests can tell whether Info preserved it.
func newInfoTestTask(t *testing.T, lastKnownID int) (kubevirtTask, *types.DomainStatus) {
	t.Helper()
	appUUID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	status := &types.DomainStatus{
		UUIDandVersion: types.UUIDandVersion{UUID: appUUID},
		DisplayName:    "myapp",
		DomainName:     "myapp." + appUUID.String(),
		PurgeCounter:   1,
		DomainId:       lastKnownID,
	}
	status.VirtualizationMode = types.HVM // -> IsMetaReplicaVMI

	var ctx kubevirtContext
	ctx.nodeNameMap = map[string]string{"nodename": "node1"}

	// Leave ctx.kubeConfig nil, as domainmgr does, and stub only the
	// kubeconfig read. Info must then call getConfig itself. An earlier
	// version of this helper set kubeConfig here and hid a nil-pointer
	// panic in Info.
	swapGetKubeConfig(t)

	return ctx.Task(status).(kubevirtTask), status
}

// TestInfoContract pins the main invariant in Info's contract (see its doc
// comment in kubevirt.go): a zero DomainId means the VMIRS is confirmed
// absent, and nothing else. Every other outcome must return a non-zero id.
//
// It covers the two rows the existence check decides alone (NotFound, and
// unreachable) plus the stranded-VMIRS row. The remaining "found" rows need
// VMI and pod listing as well, so the evetest purge tests cover those.
func TestInfoContract(t *testing.T) {
	const lastKnownID = 918273645

	t.Run("NotFound is the only case that returns zero", func(t *testing.T) {
		task, _ := newInfoTestTask(t, lastKnownID)

		ctrl := gomock.NewController(t)
		mockClient := kubecli.NewMockKubevirtClient(ctrl)
		mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
		mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS).AnyTimes()
		mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			nil, apierrors.NewNotFound(
				schema.GroupResource{Group: "kubevirt.io", Resource: "virtualmachineinstancereplicasets"},
				task.kubeName()))
		swapKubevirtClient(t, mockClient)

		id, state, err := task.Info(task.status.DomainName)
		assert.NoError(t, err)
		assert.Equal(t, types.HALTED, state)
		assert.Zero(t, id)
	})

	t.Run("an unreachable API never returns zero and keeps the last known id", func(t *testing.T) {
		task, _ := newInfoTestTask(t, lastKnownID)

		ctrl := gomock.NewController(t)
		mockClient := kubecli.NewMockKubevirtClient(ctrl)
		mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
		mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS).AnyTimes()
		mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			nil, assert.AnError)
		swapKubevirtClient(t, mockClient)

		id, state, err := task.Info(task.status.DomainName)
		assert.Error(t, err)
		assert.Equal(t, types.UNKNOWN, state)
		assert.Equal(t, lastKnownID, id, "must preserve the caller's last known id, not fabricate a new one")
		assert.NotZero(t, id)
	})

	// The two rows above return before Info builds a client. This row is the
	// shortest path to that line, which panicked on a device. HALTED with a
	// non-zero id tells domainmgr to recreate the workload.
	t.Run("a stranded VMIRS is HALTED with a non-zero id", func(t *testing.T) {
		task, _ := newInfoTestTask(t, lastKnownID)
		domainName := task.status.DomainName
		task.vmiList = map[string]*vmiMetaData{
			domainName: {mtype: IsMetaReplicaVMI, name: task.kubeName()},
		}

		noReplicas := int32(0)
		stranded := &v1.VirtualMachineInstanceReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Name: task.kubeName(), UID: "stranded-uid"},
			Spec:       v1.VirtualMachineInstanceReplicaSetSpec{Replicas: &noReplicas},
		}

		ctrl := gomock.NewController(t)
		mockClient := kubecli.NewMockKubevirtClient(ctrl)
		mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
		mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS).AnyTimes()
		// Two Gets: the existence check in replicaSetUID, then getVmirs.
		mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(stranded, nil).AnyTimes()
		swapKubevirtClient(t, mockClient)

		id, state, err := task.Info(domainName)
		assert.Error(t, err, "a stranded VMIRS is logged as an error")
		assert.Equal(t, types.HALTED, state)
		assert.NotZero(t, id, "the object exists, so zero would falsely mean confirmed-absent")
	})
}

// TestInfoUnreachableKeepsLastID is a focused restatement of the second
// case in TestInfoContract: a range of different last-known ids must all
// survive an existence-check failure unchanged.
func TestInfoUnreachableKeepsLastID(t *testing.T) {
	for _, lastKnownID := range []int{1, 42, 918273645} {
		task, _ := newInfoTestTask(t, lastKnownID)

		ctrl := gomock.NewController(t)
		mockClient := kubecli.NewMockKubevirtClient(ctrl)
		mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
		mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS).AnyTimes()
		mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, assert.AnError)
		swapKubevirtClient(t, mockClient)

		id, state, err := task.Info(task.status.DomainName)
		assert.Error(t, err)
		assert.Equal(t, types.UNKNOWN, state)
		assert.Equal(t, lastKnownID, id)
	}
}

// TestCreateReturnsNonZero pins the pre-Start sequencing invariant: Create
// runs before the VMIRS exists, so vmiList has no entry for it yet, but
// Create must still return a non-zero id derived from config - never a nil
// dereference (the map access this replaced) and never zero.
func TestCreateReturnsNonZero(t *testing.T) {
	var ctx kubevirtContext // zero value: nil vmiList
	appUUID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	config := &types.DomainConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: appUUID},
		DisplayName:    "myapp",
		PurgeCounter:   1,
	}

	id, err := ctx.Create("some-domain-name", "", config)
	assert.NoError(t, err)
	assert.NotZero(t, id)
}
