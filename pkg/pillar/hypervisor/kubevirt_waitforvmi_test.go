// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package hypervisor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

// swapGetKubeConfig overrides getKubeConfig (the wrapper around
// kubeapi.GetKubeConfig) to return a dummy, non-nil *rest.Config instead of
// reading the real kubeconfig file from disk, restoring the original when
// the test ends.
func swapGetKubeConfig(t *testing.T) {
	t.Helper()
	orig := getKubeConfig
	getKubeConfig = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	t.Cleanup(func() { getKubeConfig = orig })
}

// TestWaitForVMITargetsCorrectObject is the regression test for the
// terminating-replica confusion seen in the field: when a same-node
// replica restart briefly leaves both the outgoing and incoming VMI
// matching the same GenerateName and NodeName, getVMIStatus (the primitive
// waitForVMI polls) must report the live one's phase, not the terminating
// one's - previously the loop picked whichever the API happened to list
// first.
func TestWaitForVMITargetsCorrectObject(t *testing.T) {
	const nodeName = "node1"
	const repVmiName = "myapp-a1b2c-1"

	now := metav1.Now()
	terminating := v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "myapp-a1b2c-1bbbbb",
			GenerateName:      repVmiName,
			DeletionTimestamp: &now,
		},
		Status: v1.VirtualMachineInstanceStatus{
			NodeName: nodeName,
			Phase:    v1.Running,
		},
	}
	live := v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:         "myapp-a1b2c-1ccccc",
			GenerateName: repVmiName,
		},
		Status: v1.VirtualMachineInstanceStatus{
			NodeName: nodeName,
			Phase:    v1.Scheduling,
		},
	}

	ctrl := gomock.NewController(t)
	mockClient := kubecli.NewMockKubevirtClient(ctrl)
	mockVMI := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)
	mockClient.EXPECT().VirtualMachineInstance(gomock.Any()).Return(mockVMI).AnyTimes()
	// Deliberately list the terminating copy first, matching what the
	// field trace showed: picking by list order rather than skipping
	// terminating entries is exactly the bug this pins.
	mockVMI.EXPECT().List(gomock.Any(), gomock.Any()).Return(&v1.VirtualMachineInstanceList{
		Items: []v1.VirtualMachineInstance{terminating, live},
	}, nil)

	swapKubevirtClient(t, mockClient)
	swapGetKubeConfig(t)

	vmis := &vmiMetaData{name: repVmiName}
	state, err := getVMIStatus(vmis, nodeName)
	assert.NoError(t, err)
	assert.Equal(t, "Scheduling", state,
		"must report the live replica's phase, not the terminating one's")
}
