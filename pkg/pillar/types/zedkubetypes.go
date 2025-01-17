// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// KubeNodeStatus - Enum for the status of a Kubernetes node
type KubeNodeStatus int8

const (
	KubeNodeStatusUnknown      KubeNodeStatus = iota // KubeNodeStatusUnknown - Node status is unknown
	KubeNodeStatusReady                              // KubeNodeStatusReady - Node is in ready status
	KubeNodeStatusNotReady                           // KubeNodeStatusNotReady - Node is in not ready status
	KubeNodeStatusNotReachable                       // KubeNodeStatusNotReachable - Node is not reachable
)

type NodeAdmission uint8

const (
	NodeAdmissionUnknown NodeAdmission = iota
	NodeAdmissionNotClustered
	NodeAdmissionLeaving
	NodeAdmissionJoining
	NodeAdmissionJoined
)

func (status NodeAdmission) ZNodeAdmission() info.NodeAdmission {
	switch status {
	case NodeAdmissionNotClustered:
		return info.NodeAdmission_NODE_ADMISSION_NOT_CLUSTERED
	case NodeAdmissionLeaving:
		return info.NodeAdmission_NODE_ADMISSION_LEAVING
	case NodeAdmissionJoining:
		return info.NodeAdmission_NODE_ADMISSION_JOINING
	case NodeAdmissionJoined:
		return info.NodeAdmission_NODE_ADMISSION_JOINED
	default:
		return info.NodeAdmission_NODE_ADMISSION_UNSPECIFIED
	}
}

// KubeNodeInfo - Information about a Kubernetes node
type KubeNodeInfo struct {
	Name               string
	Status             KubeNodeStatus
	IsMaster           bool
	UsesEtcd           bool
	CreationTime       time.Time
	LastTransitionTime time.Time // Of Ready Condition
	KubeletVersion     string
	InternalIP         string
	ExternalIP         string
	Schedulable        bool
	Admission          NodeAdmission
	NodeId             string
}

func (kni KubeNodeInfo) ZKubeNodeInfo() *info.KubeNodeInfo {
	iKni := new(info.KubeNodeInfo)
	iKni.Name = kni.Name
	rdyCondition := info.KubeNodeCondition{
		Type:               info.KubeNodeConditionType_KUBE_NODE_CONDITION_TYPE_READY,
		Set:                kni.Status == KubeNodeStatusReady,
		LastTransitionTime: timestamppb.New(kni.LastTransitionTime),
	}
	iKni.Conditions = append(iKni.Conditions, &rdyCondition)
	iKni.RoleServer = true
	iKni.CreationTimestamp = timestamppb.New(kni.CreationTime)
	iKni.ApiServerSersion = kni.KubeletVersion
	iKni.InternalIp = kni.InternalIP
	iKni.Schedulable = kni.Schedulable
	iKni.AdmissionStatus = kni.Admission.ZNodeAdmission()
	iKni.NodeId = kni.NodeId
	return iKni
}

// KubePodStatus - Enum for the status of a Kubernetes pod
type KubePodStatus int8

const (
	KubePodStatusUnknown   KubePodStatus = iota // KubePodStatusUnknown - Pod status is unknown
	KubePodStatusPending                        // KubePodStatusPending - Pod is in pending status
	KubePodStatusRunning                        // KubePodStatusRunning - Pod is in running status
	KubePodStatusSucceeded                      // KubePodStatusSucceeded - Pod is in succeeded status
	KubePodStatusFailed                         // KubePodStatusFailed - Pod is in failed status
)

func (status KubePodStatus) ZKubePodStatus() info.KubePodStatus {
	switch status {
	case KubePodStatusUnknown:
		return info.KubePodStatus_KUBE_POD_STATUS_UNSPECIFIED
	case KubePodStatusPending:
		return info.KubePodStatus_KUBE_POD_STATUS_PENDING
	case KubePodStatusRunning:
		return info.KubePodStatus_KUBE_POD_STATUS_RUNNING
	case KubePodStatusSucceeded:
		return info.KubePodStatus_KUBE_POD_STATUS_SUCCEEDED
	case KubePodStatusFailed:
		return info.KubePodStatus_KUBE_POD_STATUS_FAILED
	default:
		return info.KubePodStatus_KUBE_POD_STATUS_UNSPECIFIED
	}
}

// KubePodInfo - Information about a Kubernetes pod
type KubePodInfo struct {
	Name              string
	Status            KubePodStatus
	RestartCount      int32
	RestartTimestamp  time.Time
	CreationTimestamp time.Time
	PodIP             string
	NodeName          string
}

func (kpi KubePodInfo) ZKubeEVEAppPodInfo() *info.KubeEVEAppPodInfo {
	iKeapi := new(info.KubeEVEAppPodInfo)
	iKeapi.Name = kpi.Name
	iKeapi.Status = kpi.Status.ZKubePodStatus()
	iKeapi.RestartCount = uint32(kpi.RestartCount)
	iKeapi.RestartTimestamp = timestamppb.New(kpi.RestartTimestamp)
	iKeapi.CreationTimestamp = timestamppb.New(kpi.CreationTimestamp)
	iKeapi.IpAddress = kpi.PodIP
	iKeapi.NodeName = kpi.NodeName
	return iKeapi
}

type KubePodNameSpaceInfo struct {
	// Name of the namespace
	Name string
	// Number of pods in the namespace
	PodCount uint32
	// Number of pods in the namespace that are running
	PodRunningCount uint32
	// Number of pods in the namespace that are pending
	PodPendingCount uint32
	// Number of pods in the namespace that are failed
	PodFailedCount uint32
	// Number of pods in the namespace that are succeeded
	PodSucceededCount uint32
}

// KubeVMIStatus - Enum for the status of a VirtualMachineInstance
type KubeVMIStatus int8

const (
	KubeVMIStatusUnset      KubeVMIStatus = iota // KubeVMIStatusUnset - UnSet VMI status
	KubeVMIStatusPending                         // KubeVMIStatusPending - VMI in pending status
	KubeVMIStatusScheduling                      // KubeVMIStatusScheduling - VMI in Scheduling status
	KubeVMIStatusScheduled                       // KubeVMIStatusScheduled - VMI in Scheduled status
	KubeVMIStatusRunning                         // KubeVMIStatusRunning - VMI in Running status
	KubeVMIStatusSucceeded                       // KubeVMIStatusSucceeded - VMI in Succeeded status
	KubeVMIStatusFailed                          // KubeVMIStatusFailed - VMI in Failed status
	KubeVMIStatusUnknown                         // KubeVMIStatusUnknown - VMI in Unknown status
)

func (status KubeVMIStatus) ZKubeVMIStatus() info.KubeVMIStatus {
	switch status {
	case KubeVMIStatusUnset:
		return info.KubeVMIStatus_KUBE_VMI_STATUS_UNSPECIFIED
	case KubeVMIStatusPending:
		return info.KubeVMIStatus_KUBE_VMI_STATUS_PENDING
	case KubeVMIStatusScheduling:
		return info.KubeVMIStatus_KUBE_VMI_STATUS_SCHEDULING
	case KubeVMIStatusScheduled:
		return info.KubeVMIStatus_KUBE_VMI_STATUS_SCHEDULED
	case KubeVMIStatusRunning:
		return info.KubeVMIStatus_KUBE_VMI_STATUS_RUNNING
	case KubeVMIStatusSucceeded:
		return info.KubeVMIStatus_KUBE_VMI_STATUS_SUCCEEDED
	case KubeVMIStatusFailed:
		return info.KubeVMIStatus_KUBE_VMI_STATUS_FAILED
	case KubeVMIStatusUnknown:
		return info.KubeVMIStatus_KUBE_VMI_STATUS_UNKNOWN
	default:
		return info.KubeVMIStatus_KUBE_VMI_STATUS_UNKNOWN
	}
}

// KubeVMIInfo - Information about a VirtualMachineInstance
type KubeVMIInfo struct {
	Name               string
	Status             KubeVMIStatus
	CreationTime       time.Time
	LastTransitionTime time.Time
	IsReady            bool
	NodeName           string
}

func (kvi KubeVMIInfo) ZKubeVMIInfo() *info.KubeVMIInfo {
	iKvi := new(info.KubeVMIInfo)
	iKvi.Name = kvi.Name
	iKvi.Status = kvi.Status.ZKubeVMIStatus()
	iKvi.CreationTime = timestamppb.New(kvi.CreationTime)
	iKvi.LastTransitionTime = timestamppb.New(kvi.LastTransitionTime)
	iKvi.IsReady = kvi.IsReady
	iKvi.NodeName = kvi.NodeName
	return iKvi
}

// KubeClusterInfo - Information about a Kubernetes cluster
type KubeClusterInfo struct {
	Nodes     []KubeNodeInfo         // List of nodes in the cluster
	AppPods   []KubePodInfo          // List of EVE application pods
	AppVMIs   []KubeVMIInfo          // List of VirtualMachineInstance
	Storage   KubeStorageInfo        // Distributed storage info
	PodNsInfo []KubePodNameSpaceInfo // General namespace pod running/failed count
}

type StorageHealthStatus uint8

const (
	StorageHealthStatusUnknown StorageHealthStatus = iota
	StorageHealthStatusHealthy
	StorageHealthStatusDegraded2ReplicaAvailableReplicating //replicating to third replica
	StorageHealthStatusDegraded2ReplicaAvailableNotReplicating
	StorageHealthStatusDegraded1ReplicaAvailableReplicating //replicating to one or two replicas
	StorageHealthStatusDegraded1ReplicaAvailableNotReplicating
	StorageHealthStatusFailed
)

type StorageVolumeState uint8

const (
	StorageVolumeState_Unknown StorageVolumeState = iota
	StorageVolumeState_Creating
	StorageVolumeState_Attached
	StorageVolumeState_Detached
	StorageVolumeState_Attaching
	StorageVolumeState_Detaching
	StorageVolumeState_Deleting
)

func (svs StorageVolumeState) ZStorageVolumeState() info.StorageVolumeState {
	switch svs {
	case StorageVolumeState_Unknown:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_UNSPECIFIED
	case StorageVolumeState_Creating:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_CREATING
	case StorageVolumeState_Attached:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_ATTACHED
	case StorageVolumeState_Detached:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_DETACHED
	case StorageVolumeState_Attaching:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_ATTACHING
	case StorageVolumeState_Detaching:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_DETACHING
	case StorageVolumeState_Deleting:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_DELETING
	default:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_UNSPECIFIED
	}
}

type StorageVolumeRobustness uint8

const (
	StorageVolumeRobustness_Unknown StorageVolumeRobustness = iota
	StorageVolumeRobustness_Healthy
	StorageVolumeRobustness_Degraded
	StorageVolumeRobustness_Faulted
)

type StorageVolumePvcStatus uint8

const (
	StorageVolumePvcStatus_Unknown StorageVolumePvcStatus = iota
	StorageVolumePvcStatus_Bound
	StorageVolumePvcStatus_Pending
	StorageVolumePvcStatus_Available
	StorageVolumePvcStatus_Released
	StorageVolumePvcStatus_Faulted
)

type StorageVolumeReplicaStatus uint8

const (
	StorageVolumeReplicaStatus_Unknown StorageVolumeReplicaStatus = iota
	StorageVolumeReplicaStatus_Rebuilding
	StorageVolumeReplicaStatus_Online
	StorageVolumeReplicaStatus_Failed
	StorageVolumeReplicaStatus_Offline
	StorageVolumeReplicaStatus_Starting
	StorageVolumeReplicaStatus_Stopping
)

func (svrs StorageVolumeReplicaStatus) ZStorageVolumeReplicaStatus() info.StorageVolumeReplicaStatus {
	switch svrs {
	case StorageVolumeReplicaStatus_Unknown:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_UNSPECIFIED
	case StorageVolumeReplicaStatus_Rebuilding:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_REBUILDING
	case StorageVolumeReplicaStatus_Online:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_ONLINE
	case StorageVolumeReplicaStatus_Failed:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_FAILED
	case StorageVolumeReplicaStatus_Offline:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_OFFLINE
	case StorageVolumeReplicaStatus_Starting:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_STARTING
	case StorageVolumeReplicaStatus_Stopping:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_STOPPING
	default:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_UNSPECIFIED
	}
}

type KubeVolumeReplicaInfo struct {
	Name                      string
	OwnerNode                 string
	RebuildProgressPercentage uint8
	Status                    StorageVolumeReplicaStatus
}

func (kvri KubeVolumeReplicaInfo) ZKubeVolumeReplicaInfo() *info.KubeVolumeReplicaInfo {
	iKvri := new(info.KubeVolumeReplicaInfo)
	iKvri.Name = kvri.Name
	iKvri.OwnerNode = kvri.OwnerNode
	iKvri.RebuildProgressPercentage = uint32(kvri.RebuildProgressPercentage)
	iKvri.Status = kvri.Status.ZStorageVolumeReplicaStatus()
	return iKvri
}

type KubeVolumeInfo struct {
	Name               string
	State              StorageVolumeState
	Robustness         StorageVolumeRobustness
	CreatedAt          time.Time
	ProvisionedBytes   uint64
	AllocatedBytes     uint64
	PvcStatus          StorageVolumePvcStatus
	Replicas           []KubeVolumeReplicaInfo
	RobustnessSubstate StorageHealthStatus
	VolumeId           string
}

func (kvi KubeVolumeInfo) ZKubeVolumeInfo() *info.KubeVolumeInfo {
	iKvi := new(info.KubeVolumeInfo)
	iKvi.Name = kvi.Name
	iKvi.State = kvi.State.ZStorageVolumeState()
	iKvi.Robustness = info.StorageVolumeRobustness(kvi.Robustness)
	iKvi.CreationTimestamp = timestamppb.New(kvi.CreatedAt)
	iKvi.ProvisionedBytes = kvi.ProvisionedBytes
	iKvi.AllocatedBytes = kvi.AllocatedBytes
	iKvi.PvcStatus = info.StorageVolumePVCStatus(kvi.PvcStatus)
	for _, rep := range kvi.Replicas {
		iKvi.Replica = append(iKvi.Replica, rep.ZKubeVolumeReplicaInfo())
	}
	iKvi.RobustnessSubstate = info.StorageHealthStatus(kvi.RobustnessSubstate)
	iKvi.VolumeId = kvi.VolumeId
	return iKvi
}

type ServiceStatus int8

const (
	ServiceStatusUnset ServiceStatus = iota
	ServiceStatusFailed
	ServiceStatusDegraded
	ServiceStatusHealthy
)

func (state ServiceStatus) ZServiceStatus() info.ServiceStatus {
	switch state {
	case ServiceStatusUnset:
		return info.ServiceStatus_SERVICE_STATUS_UNSPECIFIED
	case ServiceStatusFailed:
		return info.ServiceStatus_SERVICE_STATUS_FAILED
	case ServiceStatusDegraded:
		return info.ServiceStatus_SERVICE_STATUS_DEGRADED
	case ServiceStatusHealthy:
		return info.ServiceStatus_SERVICE_STATUS_HEALTHY
	default:
		return info.ServiceStatus_SERVICE_STATUS_UNSPECIFIED
	}
}

type KubeStorageInfo struct {
	Health         ServiceStatus
	TransitionTime time.Time
	Volumes        []KubeVolumeInfo
}

func (ksi KubeStorageInfo) ZKubeStorageInfo() *info.KubeStorageInfo {
	iKsi := new(info.KubeStorageInfo)
	iKsi.TransitionTime = timestamppb.New(ksi.TransitionTime)
	iKsi.Health = ksi.Health.ZServiceStatus()
	for _, vol := range ksi.Volumes {
		iKsi.Volumes = append(iKsi.Volumes, vol.ZKubeVolumeInfo())
	}
	return iKsi
}
