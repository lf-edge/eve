// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package hypervisor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"kubevirt.io/client-go/kubecli"
)

// swapKubevirtClient overrides newKubevirtClient to always return client,
// restoring the original constructor when the test ends. Tests using this
// must not run with t.Parallel, since the override is a shared
// package-level var.
func swapKubevirtClient(t *testing.T, client kubecli.KubevirtClient) {
	t.Helper()
	orig := newKubevirtClient
	newKubevirtClient = func(*rest.Config) (kubecli.KubevirtClient, error) {
		return client, nil
	}
	t.Cleanup(func() { newKubevirtClient = orig })
}

// TestStopReplicaVMIErrorHandling pins the fix to the inverted IsNotFound
// check in StopReplicaVMI: success and NotFound must both return nil, and
// only a real API error should be returned (and logged as an error).
func TestStopReplicaVMIErrorHandling(t *testing.T) {
	tests := []struct {
		name    string
		delErr  error
		wantErr bool
	}{
		{
			name:    "success",
			delErr:  nil,
			wantErr: false,
		},
		{
			name: "not found is not an error",
			delErr: apierrors.NewNotFound(
				schema.GroupResource{Group: "kubevirt.io", Resource: "virtualmachineinstancereplicasets"},
				"myapp-a1b2c-1"),
			wantErr: false,
		},
		{
			name:    "a real API error is returned",
			delErr:  apierrors.NewInternalError(assert.AnError),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockClient := kubecli.NewMockKubevirtClient(ctrl)
			mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
			mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS).AnyTimes()
			mockRS.EXPECT().
				Delete(gomock.Any(), "myapp-a1b2c-1", gomock.Any()).
				Return(tc.delErr)

			swapKubevirtClient(t, mockClient)

			err := StopReplicaVMI(&rest.Config{}, "myapp-a1b2c-1")
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
