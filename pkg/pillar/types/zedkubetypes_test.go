// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// KubeVMIStatus.ZKubeVMIStatus

func TestZKubeVMIStatus(t *testing.T) {
	cases := []struct {
		in   KubeVMIStatus
		want info.KubeVMIStatus
	}{
		{KubeVMIStatusUnset, info.KubeVMIStatus_KUBE_VMI_STATUS_UNSPECIFIED},
		{KubeVMIStatusPending, info.KubeVMIStatus_KUBE_VMI_STATUS_PENDING},
		{KubeVMIStatusScheduling, info.KubeVMIStatus_KUBE_VMI_STATUS_SCHEDULING},
		{KubeVMIStatusScheduled, info.KubeVMIStatus_KUBE_VMI_STATUS_SCHEDULED},
		{KubeVMIStatusRunning, info.KubeVMIStatus_KUBE_VMI_STATUS_RUNNING},
		{KubeVMIStatusSucceeded, info.KubeVMIStatus_KUBE_VMI_STATUS_SUCCEEDED},
		{KubeVMIStatusFailed, info.KubeVMIStatus_KUBE_VMI_STATUS_FAILED},
		{KubeVMIStatusUnknown, info.KubeVMIStatus_KUBE_VMI_STATUS_UNKNOWN},
		{KubeVMIStatus(99), info.KubeVMIStatus_KUBE_VMI_STATUS_UNKNOWN},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.in.ZKubeVMIStatus())
	}
}

// KubeVMIInfo.ZKubeVMIInfo

func TestZKubeVMIInfo(t *testing.T) {
	kvi := KubeVMIInfo{
		Name:     "myapp-vmi",
		Status:   KubeVMIStatusRunning,
		IsReady:  true,
		NodeName: "node1",
	}
	result := kvi.ZKubeVMIInfo()
	assert.NotNil(t, result)
	assert.Equal(t, "myapp-vmi", result.Name)
	assert.Equal(t, info.KubeVMIStatus_KUBE_VMI_STATUS_RUNNING, result.Status)
	assert.True(t, result.IsReady)
	assert.Equal(t, "node1", result.NodeName)
}

// KubePodInfo.ZKubeEVEAppPodInfo

func TestZKubeEVEAppPodInfo(t *testing.T) {
	kpi := KubePodInfo{
		Name:     "myapp-pod",
		Status:   KubePodStatusRunning,
		PodIP:    "10.244.0.1",
		NodeName: "node1",
	}
	result := kpi.ZKubeEVEAppPodInfo()
	assert.NotNil(t, result)
	assert.Equal(t, "myapp-pod", result.Name)
	assert.Equal(t, info.KubePodStatus_KUBE_POD_STATUS_RUNNING, result.Status)
	assert.Equal(t, "10.244.0.1", result.IpAddress)
	assert.Equal(t, "node1", result.NodeName)
}

// KubeVolumeReplicaInfo.ZKubeVolumeReplicaInfo

func TestZKubeVolumeReplicaInfo(t *testing.T) {
	kvri := KubeVolumeReplicaInfo{
		Name:                      "vol-replica-0",
		OwnerNode:                 "node1",
		RebuildProgressPercentage: 50,
		Status:                    StorageVolumeReplicaStatusOnline,
	}
	result := kvri.ZKubeVolumeReplicaInfo()
	assert.NotNil(t, result)
	assert.Equal(t, "vol-replica-0", result.Name)
	assert.Equal(t, "node1", result.OwnerNode)
	assert.Equal(t, uint32(50), result.RebuildProgressPercentage)
	assert.Equal(t, info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_ONLINE, result.Status)
}

// ServiceStatus.ZServiceStatus

func TestZServiceStatus(t *testing.T) {
	cases := []struct {
		in   ServiceStatus
		want info.ServiceStatus
	}{
		{ServiceStatusUnset, info.ServiceStatus_SERVICE_STATUS_UNSPECIFIED},
		{ServiceStatusFailed, info.ServiceStatus_SERVICE_STATUS_FAILED},
		{ServiceStatusDegraded, info.ServiceStatus_SERVICE_STATUS_DEGRADED},
		{ServiceStatusHealthy, info.ServiceStatus_SERVICE_STATUS_HEALTHY},
		{ServiceStatus(99), info.ServiceStatus_SERVICE_STATUS_UNSPECIFIED},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.in.ZServiceStatus())
	}
}

// KubeVolumeInfo.ZKubeVolumeInfo

func TestZKubeVolumeInfo(t *testing.T) {
	kvi := KubeVolumeInfo{
		Name:             "longhorn-vol",
		State:            StorageVolumeStateAttached,
		ProvisionedBytes: 10 * 1024 * 1024 * 1024,
		VolumeID:         "vol-123",
		Replicas: []KubeVolumeReplicaInfo{
			{Name: "rep1", OwnerNode: "node1", Status: StorageVolumeReplicaStatusOnline},
		},
	}
	result := kvi.ZKubeVolumeInfo()
	assert.NotNil(t, result)
	assert.Equal(t, "longhorn-vol", result.Name)
	assert.Equal(t, info.StorageVolumeState_STORAGE_VOLUME_STATE_ATTACHED, result.State)
	assert.Equal(t, uint64(10*1024*1024*1024), result.ProvisionedBytes)
	assert.Equal(t, "vol-123", result.VolumeId)
	require.Len(t, result.Replica, 1)
	assert.Equal(t, "rep1", result.Replica[0].Name)
}

// KubeStorageInfo.ZKubeStorageInfo

func TestZKubeStorageInfo(t *testing.T) {
	ksi := KubeStorageInfo{
		Health: ServiceStatusHealthy,
		Volumes: []KubeVolumeInfo{
			{Name: "vol1", State: StorageVolumeStateAttached},
		},
	}
	result := ksi.ZKubeStorageInfo()
	assert.NotNil(t, result)
	assert.Equal(t, info.ServiceStatus_SERVICE_STATUS_HEALTHY, result.Health)
	assert.Len(t, result.Volumes, 1)
	assert.Equal(t, "vol1", result.Volumes[0].Name)
}

// KubeNodeInfo.ZKubeNodeInfo

func TestZKubeNodeInfo(t *testing.T) {
	kni := KubeNodeInfo{
		Name:        "node-1",
		Status:      KubeNodeStatusReady,
		IsMaster:    true,
		InternalIP:  "10.0.0.1",
		Schedulable: true,
		Admission:   NodeAdmissionJoined,
		NodeID:      "abc-123",
	}
	result := kni.ZKubeNodeInfo()
	assert.NotNil(t, result)
	assert.Equal(t, "node-1", result.Name)
	assert.Equal(t, "10.0.0.1", result.InternalIp)
	assert.True(t, result.Schedulable)
	assert.Equal(t, info.NodeAdmission_NODE_ADMISSION_JOINED, result.AdmissionStatus)
	assert.Equal(t, "abc-123", result.NodeId)
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

// KubeUserServices.Equal — ingress and LBPoolStatus branches

func TestKubeUserServicesEqualIngress(t *testing.T) {
	ing := KubeIngressInfo{
		Namespace: "default",
		Name:      "my-ing",
		Hostname:  "example.com",
		Path:      "/api",
	}
	s1 := KubeUserServices{UserIngress: []KubeIngressInfo{ing}}
	s2 := KubeUserServices{UserIngress: []KubeIngressInfo{ing}}
	assert.True(t, s1.Equal(s2))

	s2.UserIngress = []KubeIngressInfo{{Namespace: "other"}}
	assert.False(t, s1.Equal(s2))
}

func TestKubeUserServicesEqualLBPool(t *testing.T) {
	lb := KubeLBPoolStatus{Interface: "eth0", IPPrefix: "192.168.1.0/28", AllocatedIPs: []string{"192.168.1.1"}}

	// Both nil
	s1 := KubeUserServices{}
	s2 := KubeUserServices{}
	assert.True(t, s1.Equal(s2))

	// One nil, one not
	s2.LBPoolStatus = &lb
	assert.False(t, s1.Equal(s2))

	// Both set, equal
	s1.LBPoolStatus = &lb
	assert.True(t, s1.Equal(s2))

	// Both set, different
	lb2 := lb
	lb2.Interface = "eth1"
	s2.LBPoolStatus = &lb2
	assert.False(t, s1.Equal(s2))
}
