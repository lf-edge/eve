// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package hypervisor

import (
	"testing"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

// swapK8sClientNoPods overrides newK8sClient to return a fake clientset
// with no pods in it, i.e. every pod-list confirm-absence check reports
// "gone" immediately. Sufficient for sweep tests, which are exercising the
// VMIRS/ReplicaSet object side of confirm-absence, not pod teardown timing.
func swapK8sClientNoPods(t *testing.T) {
	t.Helper()
	orig := newK8sClient
	fakeClientset := fake.NewSimpleClientset()
	newK8sClient = func(*rest.Config) (kubernetes.Interface, error) {
		return fakeClientset, nil
	}
	t.Cleanup(func() { newK8sClient = orig })
}

// swapSweepConfirmInterval shrinks the confirm-absence retry interval for
// the duration of a test, so a deliberately-never-gone timeout test does
// not have to wait out the real ~50s budget.
func swapSweepConfirmInterval(t *testing.T, d time.Duration) {
	t.Helper()
	orig := sweepConfirmInterval
	sweepConfirmInterval = d
	t.Cleanup(func() { sweepConfirmInterval = orig })
}

// TestSweepDeletesOnlyOlderGenerations pins the sweep's core selection
// invariant: given a mix of older, current, and another app's generations,
// only the strictly-older generations of the target app are deleted - the
// current generation and the other app's generation must survive untouched.
func TestSweepDeletesOnlyOlderGenerations(t *testing.T) {
	appUUID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	otherUUID := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))
	domainName := appUUID.String() + ".1.0"
	const desiredName = "myapp-a1b2c-2"
	const desiredCounter = uint32(2)

	list := &v1.VirtualMachineInstanceReplicaSetList{
		Items: []v1.VirtualMachineInstanceReplicaSet{
			mkVMIRS("myapp-a1b2c-0", domainName),
			mkVMIRS("myapp-a1b2c-1", domainName),
			mkVMIRS(desiredName, domainName),
			mkVMIRS("otherapp-x9y8z-1", otherUUID.String()+".1.0"),
		},
	}
	notFoundErr := apierrors.NewNotFound(
		schema.GroupResource{Group: "kubevirt.io", Resource: "virtualmachineinstancereplicasets"}, "")

	ctrl := gomock.NewController(t)
	mockClient := kubecli.NewMockKubevirtClient(ctrl)
	mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
	mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS).AnyTimes()
	mockRS.EXPECT().List(gomock.Any(), gomock.Any()).Return(list, nil)

	deleted := map[string]bool{}
	mockRS.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ interface{}, name interface{}, _ interface{}) error {
			deleted[name.(string)] = true
			return nil
		}).Times(2)
	// Confirm-absence: object already gone by the time we check.
	mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, notFoundErr).Times(2)

	swapKubevirtClient(t, mockClient)
	swapK8sClientNoPods(t)

	var ctx kubevirtContext
	ctx.kubeConfig = &rest.Config{}

	err := ctx.sweepStaleGenerations(appUUID, desiredName, desiredCounter, IsMetaReplicaVMI)
	assert.NoError(t, err)
	assert.Equal(t, map[string]bool{"myapp-a1b2c-0": true, "myapp-a1b2c-1": true}, deleted)
}

// TestSweepConfirmAbsenceTimeoutFails: if a stale generation is deleted but
// never actually confirmed gone, the sweep must return an error (which
// Start propagates, refusing to create the new
// generation) rather than give up silently or hang indefinitely.
func TestSweepConfirmAbsenceTimeoutFails(t *testing.T) {
	appUUID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	domainName := appUUID.String() + ".1.0"

	list := &v1.VirtualMachineInstanceReplicaSetList{
		Items: []v1.VirtualMachineInstanceReplicaSet{
			mkVMIRS("myapp-a1b2c-1", domainName),
		},
	}

	ctrl := gomock.NewController(t)
	mockClient := kubecli.NewMockKubevirtClient(ctrl)
	mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
	mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS).AnyTimes()
	mockRS.EXPECT().List(gomock.Any(), gomock.Any()).Return(list, nil)
	mockRS.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	// The object is never confirmed gone: every Get keeps succeeding (still there).
	mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&v1.VirtualMachineInstanceReplicaSet{}, nil).
		Times(sweepConfirmRetries)

	swapKubevirtClient(t, mockClient)
	swapK8sClientNoPods(t)
	swapSweepConfirmInterval(t, time.Millisecond)

	var ctx kubevirtContext
	ctx.kubeConfig = &rest.Config{}

	err := ctx.sweepStaleGenerations(appUUID, "myapp-a1b2c-2", 2, IsMetaReplicaVMI)
	assert.Error(t, err)
}
