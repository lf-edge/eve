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
	"k8s.io/client-go/rest"
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
		PurgeCounter:   1,
		DomainId:       lastKnownID,
	}
	status.VirtualizationMode = types.HVM // -> IsMetaReplicaVMI

	var ctx kubevirtContext
	ctx.nodeNameMap = map[string]string{"nodename": "node1"}
	ctx.kubeConfig = &rest.Config{} // non-nil so getConfig skips the real kubeconfig read

	return ctx.Task(status).(kubevirtTask), status
}

// TestInfoContract pins the single most important invariant in Info's
// contract (see its doc comment in kubevirt.go): a zero DomainId must
// appear in exactly one case - the VMIRS confirmed absent (Get -> NotFound).
// Every other outcome
// of the existence check, including any error that leaves existence
// genuinely unknown, must return a non-zero id and must never be reported
// as "gone".
//
// This covers the two rows reachable from the existence check alone
// (NotFound, and unreachable/other-error); the "found" rows (running here,
// not-yet-attributable, unmapped phase) additionally exercise
// replicaVmiScheduledOnMe's own VMI/pod listing and are covered by the
// evetest cluster-level purge tests rather than duplicated here with a
// second, deeper layer of client mocking.
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
}

// TestInfoVmirsDeletedMidCall covers a VMIRS that is present for Info's
// existence check and deleted before the Get that follows it. Absence
// observed at the second Get must produce the same answer as absence
// observed at the first - HALTED, zero id, no error - rather than the
// SCHEDULING-with-an-error that a NotFound would otherwise fall through to.
// That error matters beyond the state it carries: waitForDomainGone treats
// any error from Info as "the domain is gone" and stops waiting.
func TestInfoVmirsDeletedMidCall(t *testing.T) {
	const lastKnownID = 918273645
	task, status := newInfoTestTask(t, lastKnownID)
	status.DomainName = "11111111-1111-1111-1111-111111111111.1.1"
	task.vmiList = map[string]*vmiMetaData{
		status.DomainName: {mtype: IsMetaReplicaVMI, name: task.kubeName()},
	}

	ctrl := gomock.NewController(t)
	mockClient := kubecli.NewMockKubevirtClient(ctrl)
	mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
	mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS).AnyTimes()

	notFound := apierrors.NewNotFound(
		schema.GroupResource{Group: "kubevirt.io", Resource: "virtualmachineinstancereplicasets"},
		task.kubeName())
	gomock.InOrder(
		// The existence check finds it...
		mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			&v1.VirtualMachineInstanceReplicaSet{
				ObjectMeta: metav1.ObjectMeta{Name: task.kubeName(), UID: "some-uid"},
			}, nil),
		// ...and it is gone from here on. Left unbounded rather than pinned
		// to a single call so this asserts the answer Info returns, not how
		// many times it asks.
		mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, notFound).AnyTimes(),
	)
	swapKubevirtClient(t, mockClient)

	id, state, err := task.Info(status.DomainName)
	assert.NoError(t, err, "a confirmed-absent domain is not an error")
	assert.Equal(t, types.HALTED, state)
	assert.Zero(t, id)
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
