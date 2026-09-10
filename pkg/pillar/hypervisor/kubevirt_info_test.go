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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
// comment in kubevirt.go): a zero DomainId means the whole workload -
// VMIRS, VMI and pod - is confirmed absent, and nothing else. Every other
// outcome must return a non-zero id.
//
// It covers the two rows the existence check decides alone (NotFound, and
// unreachable) plus the stranded-VMIRS row. The remaining "found" rows need
// VMI and pod listing as well, so the evetest purge tests cover those.
func TestInfoContract(t *testing.T) {
	const lastKnownID = 918273645

	t.Run("a wholly absent workload is the only case that returns zero", func(t *testing.T) {
		task, _ := newInfoTestTask(t, lastKnownID)

		ctrl := gomock.NewController(t)
		mockClient := kubecli.NewMockKubevirtClient(ctrl)
		mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
		mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS).AnyTimes()
		mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, vmirsNotFound(task.kubeName()))
		// An absent VMIRS is necessary but not sufficient, so Info also
		// looks for a surviving VMI and pod. Both are absent here;
		// TestInfoStateFromWorkloadObjects covers the rest.
		mockVMI := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)
		mockClient.EXPECT().VirtualMachineInstance(gomock.Any()).
			Return(mockVMI).AnyTimes()
		mockVMI.EXPECT().List(gomock.Any(), gomock.Any()).
			Return(&v1.VirtualMachineInstanceList{}, nil).AnyTimes()
		swapKubevirtClient(t, mockClient)
		swapK8sClientWithObjects(t)

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

// runInfoAbsenceRace is the shared two-row truth table (no dependents left
// behind / a VMI outlived the VMIRS) behind TestInfoVmirsDeletedMidCall and
// TestInfoSchedulingLookupNotFoundIsAbsent. configureGets wires whatever
// sequence of ReplicaSet Gets the caller wants to race against Info(); it is
// the only thing that differs between the two.
func runInfoAbsenceRace(t *testing.T, configureGets func(mockRS *kubecli.MockReplicaSetInterface,
	notFound error, kubeName string)) {
	t.Helper()
	const lastKnownID = 918273645

	for _, tc := range []struct {
		name      string
		vmis      []v1.VirtualMachineInstance
		wantState types.SwState
		wantZero  bool
	}{{
		name:      "no dependents left behind",
		wantState: types.HALTED,
		wantZero:  true,
	}, {
		name:      "a VMI outlived the VMIRS",
		vmis:      []v1.VirtualMachineInstance{{ObjectMeta: metav1.ObjectMeta{Name: "vmi-0"}}},
		wantState: types.HALTING,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			task, status := newInfoTestTask(t, lastKnownID)
			status.DomainName = "11111111-1111-1111-1111-111111111111.1.1"
			task.vmiList = map[string]*vmiMetaData{
				status.DomainName: {mtype: IsMetaReplicaVMI, name: task.kubeName()},
			}

			vmis := tc.vmis
			for i := range vmis {
				vmis[i].Labels = map[string]string{eveLabelKey: status.DomainName}
			}

			ctrl := gomock.NewController(t)
			mockClient := kubecli.NewMockKubevirtClient(ctrl)
			mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
			mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS).AnyTimes()

			configureGets(mockRS, vmirsNotFound(task.kubeName()), task.kubeName())

			expectVMIList(t, ctrl, mockClient, vmis)
			swapKubevirtClient(t, mockClient)
			swapK8sClientNoPods(t)

			id, state, err := task.Info(status.DomainName)
			assert.NoError(t, err, "a confirmed answer, either way, is not an error")
			assert.Equal(t, tc.wantState, state)
			if tc.wantZero {
				assert.Zero(t, id)
			} else {
				assert.NotZero(t, id,
					"a zero id would falsely tell domainmgr the workload is gone")
			}
		})
	}
}

// TestInfoVmirsDeletedMidCall covers a VMIRS present at the existence check
// and gone by the next Get. Both rows race the same way; only the
// dependents differ, so a surviving VMI or pod must produce HALTING, not
// HALTED, the same as confirmedAbsent's other callers.
func TestInfoVmirsDeletedMidCall(t *testing.T) {
	runInfoAbsenceRace(t, func(mockRS *kubecli.MockReplicaSetInterface, notFound error, kubeName string) {
		gomock.InOrder(
			// The existence check finds it...
			mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(
				&v1.VirtualMachineInstanceReplicaSet{
					ObjectMeta: metav1.ObjectMeta{Name: kubeName, UID: "some-uid"},
				}, nil),
			// ...and it is gone from here on. Left unbounded rather than
			// pinned to a single call so this asserts the answer Info
			// returns, not how many times it asks.
			mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil, notFound).AnyTimes(),
		)
	})
}

// TestInfoSchedulingLookupNotFoundIsAbsent covers the scheduling-lookup
// backstop: the VMIRS is present at the existence check, the direct
// re-fetch hits a transient error, and scheduledOnMe's own Get is what
// finally observes NotFound. That NotFound must still go through
// confirmedAbsent's dependents check.
func TestInfoSchedulingLookupNotFoundIsAbsent(t *testing.T) {
	runInfoAbsenceRace(t, func(mockRS *kubecli.MockReplicaSetInterface, notFound error, kubeName string) {
		gomock.InOrder(
			// The existence check finds it...
			mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(
				&v1.VirtualMachineInstanceReplicaSet{
					ObjectMeta: metav1.ObjectMeta{Name: kubeName, UID: "some-uid"},
				}, nil),
			// The direct re-fetch hits some other, non-NotFound failure,
			// which falls through to scheduledOnMe's own Get instead of
			// answering here.
			mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil, assert.AnError),
			// ...and that Get is the one that observes it gone.
			mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil, notFound).AnyTimes(),
		)
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
