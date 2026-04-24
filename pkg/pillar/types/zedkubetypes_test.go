// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/stretchr/testify/assert"
)

// NodeAdmission.ZNodeAdmission

func TestZNodeAdmission(t *testing.T) {
	cases := []struct {
		in   NodeAdmission
		want info.NodeAdmission
	}{
		{NodeAdmissionNotClustered, info.NodeAdmission_NODE_ADMISSION_NOT_CLUSTERED},
		{NodeAdmissionLeaving, info.NodeAdmission_NODE_ADMISSION_LEAVING},
		{NodeAdmissionJoining, info.NodeAdmission_NODE_ADMISSION_JOINING},
		{NodeAdmissionJoined, info.NodeAdmission_NODE_ADMISSION_JOINED},
		{NodeAdmission(99), info.NodeAdmission_NODE_ADMISSION_UNSPECIFIED},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.in.ZNodeAdmission())
	}
}

// KubePodStatus.ZKubePodStatus

func TestZKubePodStatus(t *testing.T) {
	cases := []struct {
		in   KubePodStatus
		want info.KubePodStatus
	}{
		{KubePodStatusUnknown, info.KubePodStatus_KUBE_POD_STATUS_UNSPECIFIED},
		{KubePodStatusPending, info.KubePodStatus_KUBE_POD_STATUS_PENDING},
		{KubePodStatusRunning, info.KubePodStatus_KUBE_POD_STATUS_RUNNING},
		{KubePodStatusSucceeded, info.KubePodStatus_KUBE_POD_STATUS_SUCCEEDED},
		{KubePodStatusFailed, info.KubePodStatus_KUBE_POD_STATUS_FAILED},
		{KubePodStatus(99), info.KubePodStatus_KUBE_POD_STATUS_UNSPECIFIED},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.in.ZKubePodStatus())
	}
}

// StorageVolumeState.ZStorageVolumeState

func TestZStorageVolumeState(t *testing.T) {
	cases := []struct {
		in   StorageVolumeState
		want info.StorageVolumeState
	}{
		{StorageVolumeStateUnknown, info.StorageVolumeState_STORAGE_VOLUME_STATE_UNSPECIFIED},
		{StorageVolumeStateCreating, info.StorageVolumeState_STORAGE_VOLUME_STATE_CREATING},
		{StorageVolumeStateAttached, info.StorageVolumeState_STORAGE_VOLUME_STATE_ATTACHED},
		{StorageVolumeStateDetached, info.StorageVolumeState_STORAGE_VOLUME_STATE_DETACHED},
		{StorageVolumeStateAttaching, info.StorageVolumeState_STORAGE_VOLUME_STATE_ATTACHING},
		{StorageVolumeStateDetaching, info.StorageVolumeState_STORAGE_VOLUME_STATE_DETACHING},
		{StorageVolumeStateDeleting, info.StorageVolumeState_STORAGE_VOLUME_STATE_DELETING},
		{StorageVolumeState(99), info.StorageVolumeState_STORAGE_VOLUME_STATE_UNSPECIFIED},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.in.ZStorageVolumeState())
	}
}

// StorageVolumeReplicaStatus.ZStorageVolumeReplicaStatus

func TestZStorageVolumeReplicaStatus(t *testing.T) {
	cases := []struct {
		in   StorageVolumeReplicaStatus
		want info.StorageVolumeReplicaStatus
	}{
		{StorageVolumeReplicaStatusUnknown, info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_UNSPECIFIED},
		{StorageVolumeReplicaStatusRebuilding, info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_REBUILDING},
		{StorageVolumeReplicaStatusOnline, info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_ONLINE},
		{StorageVolumeReplicaStatusFailed, info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_FAILED},
		{StorageVolumeReplicaStatusOffline, info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_OFFLINE},
		{StorageVolumeReplicaStatusStarting, info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_STARTING},
		{StorageVolumeReplicaStatusStopping, info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_STOPPING},
		{StorageVolumeReplicaStatus(99), info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_UNSPECIFIED},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.in.ZStorageVolumeReplicaStatus())
	}
}

// KubeUserServices.Equal

func TestKubeUserServicesEqual(t *testing.T) {
	svc := KubeServiceInfo{
		Namespace: "default",
		Name:      "my-svc",
		Port:      8080,
	}
	s1 := KubeUserServices{
		UserService: []KubeServiceInfo{svc},
	}
	s2 := s1
	assert.True(t, s1.Equal(s2))

	s2.UserService = []KubeServiceInfo{{Namespace: "other"}}
	assert.False(t, s1.Equal(s2))

	// Both empty → equal
	assert.True(t, KubeUserServices{}.Equal(KubeUserServices{}))
}
