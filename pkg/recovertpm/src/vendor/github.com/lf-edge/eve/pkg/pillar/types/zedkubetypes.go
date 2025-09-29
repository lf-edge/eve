// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
)

const (
	// DefaultDrainSkipK8sAPINotReachableTimeoutSeconds is the time duration which the drain request handler
	// will continue retrying the k8s api before declaring the node is unavailable and continuing
	// device operations (reboot/shutdown/upgrade)
	// This covers the following k8s.io/apimachinery/pkg/api/errors
	// IsInternalError
	// IsServerTimeout
	// IsServiceUnavailable
	// IsTimeout
	// IsTooManyRequests
	DefaultDrainSkipK8sAPINotReachableTimeoutSeconds = 300
	// DefaultDrainTimeoutHours is time allowed for a node drain before a failure is returned
	DefaultDrainTimeoutHours = 24
)

// KubeNodeStatus - Enum for the status of a Kubernetes node
type KubeNodeStatus int8

const (
	KubeNodeStatusUnknown      KubeNodeStatus = iota // KubeNodeStatusUnknown - Node status is unknown
	KubeNodeStatusReady                              // KubeNodeStatusReady - Node is in ready status
	KubeNodeStatusNotReady                           // KubeNodeStatusNotReady - Node is in not ready status
	KubeNodeStatusNotReachable                       // KubeNodeStatusNotReachable - Node is not reachable
)

// NodeAdmission - Enum for the admission status of a node in a cluster
type NodeAdmission uint8

const (
	NodeAdmissionUnknown      NodeAdmission = iota // NodeAdmissionUnknown - Node admission status is unknown
	NodeAdmissionNotClustered                      // NodeAdmissionNotClustered - Node is not part of the cluster
	NodeAdmissionLeaving                           // NodeAdmissionLeaving - Node is leaving the cluster
	NodeAdmissionJoining                           // NodeAdmissionJoining - Node is joining the cluster
	NodeAdmissionJoined                            // NodeAdmissionJoined - Node has joined the cluster
)

// ZNodeAdmission - Converts pubsub NodeAdmission to eve-api info.NodeAdmission
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
	NodeID             string
}

// ZKubeNodeInfo - Converts pubsub KubeNodeInfo to eve-api info.KubeNodeInfo
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
	iKni.NodeId = kni.NodeID
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

// ZKubePodStatus - Converts pubsub KubePodStatus to eve-api info.KubePodStatus
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

// ZKubeEVEAppPodInfo Converts pubsub KubePodInfo to eve-api info.KubeEVEAppPodInfo
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

// KubePodNameSpaceInfo - pod counts by state in a namespace of a Kubernetes cluster
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

// ZKubeVMIStatus - Converts pubsub KubeVMIStatus to eve-api info.KubeVMIStatus
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

// ZKubeVMIInfo - Converts KubeVMIInfo to info.KubeVMIInfo
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

// StorageHealthStatus - Enum for the redundancy level and replication status of a storage volume
type StorageHealthStatus uint8

const (
	StorageHealthStatusUnknown                                 StorageHealthStatus = iota // StorageHealthStatusUnknown - Storage health status is unknown
	StorageHealthStatusHealthy                                                            // StorageHealthStatusHealthy - All replicas healthy
	StorageHealthStatusDegraded2ReplicaAvailableReplicating                               // StorageHealthStatusDegraded2ReplicaAvailableReplicating - replicating to third replica
	StorageHealthStatusDegraded2ReplicaAvailableNotReplicating                            // StorageHealthStatusDegraded2ReplicaAvailableNotReplicating - not replicating to third replica
	StorageHealthStatusDegraded1ReplicaAvailableReplicating                               // StorageHealthStatusDegraded1ReplicaAvailableReplicating - replicating to one or two replicas
	StorageHealthStatusDegraded1ReplicaAvailableNotReplicating                            // StorageHealthStatusDegraded1ReplicaAvailableNotReplicating - no redundancy, not replicating
	StorageHealthStatusFailed                                                             // StorageHealthStatusFailed - no healthy replicas
)

// StorageVolumeState - Enum for the attachment state of a storage volume
type StorageVolumeState uint8

const (
	StorageVolumeStateUnknown   StorageVolumeState = iota // StorageVolumeStateUnknown - Volume state is unknown
	StorageVolumeStateCreating                            // StorageVolumeStateCreating - Volume is being created
	StorageVolumeStateAttached                            // StorageVolumeStateAttached - Volume is attached
	StorageVolumeStateDetached                            // StorageVolumeStateDetached - Volume is detached
	StorageVolumeStateAttaching                           // StorageVolumeStateAttaching - Volume is being attached
	StorageVolumeStateDetaching                           // StorageVolumeStateDetaching - Volume is being detached
	StorageVolumeStateDeleting                            // StorageVolumeStateDeleting - Volume is being deleted
)

// ZStorageVolumeState - Converts pubsub StorageVolumeState to eve-api info.StorageVolumeState
func (svs StorageVolumeState) ZStorageVolumeState() info.StorageVolumeState {
	switch svs {
	case StorageVolumeStateUnknown:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_UNSPECIFIED
	case StorageVolumeStateCreating:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_CREATING
	case StorageVolumeStateAttached:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_ATTACHED
	case StorageVolumeStateDetached:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_DETACHED
	case StorageVolumeStateAttaching:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_ATTACHING
	case StorageVolumeStateDetaching:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_DETACHING
	case StorageVolumeStateDeleting:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_DELETING
	default:
		return info.StorageVolumeState_STORAGE_VOLUME_STATE_UNSPECIFIED
	}
}

// StorageVolumeRobustness - Enum for the replica robustness of a storage volume
type StorageVolumeRobustness uint8

const (
	StorageVolumeRobustnessUnknown  StorageVolumeRobustness = iota // StorageVolumeRobustnessUnknown - Volume robustness is unknown
	StorageVolumeRobustnessHealthy                                 // StorageVolumeRobustnessHealthy - All Volume replicas healthy
	StorageVolumeRobustnessDegraded                                // StorageVolumeRobustnessDegraded - One or more Volume replicas degraded
	StorageVolumeRobustnessFaulted                                 // StorageVolumeRobustnessFaulted - no healthy replicas
)

// StorageVolumePvcStatus - Enum for the status of a PVC associated with a volume instance
type StorageVolumePvcStatus uint8

const (
	StorageVolumePvcStatusUnknown   StorageVolumePvcStatus = iota // StorageVolumePvcStatusUnknown - PVC status is unknown
	StorageVolumePvcStatusBound                                   // StorageVolumePvcStatusBound - PVC is bound
	StorageVolumePvcStatusPending                                 // StorageVolumePvcStatusPending - PVC is pending
	StorageVolumePvcStatusAvailable                               // StorageVolumePvcStatusAvailable - PVC is available
	StorageVolumePvcStatusReleased                                // StorageVolumePvcStatusReleased - PVC is released
	StorageVolumePvcStatusFaulted                                 // StorageVolumePvcStatusFaulted - PVC is faulted
)

// StorageVolumeReplicaStatus - Enum for the status of a replica of a storage volume
type StorageVolumeReplicaStatus uint8

const (
	StorageVolumeReplicaStatusUnknown    StorageVolumeReplicaStatus = iota // StorageVolumeReplicaStatusUnknown - Replica status is unknown
	StorageVolumeReplicaStatusRebuilding                                   // StorageVolumeReplicaStatusRebuilding - Replica is rebuilding
	StorageVolumeReplicaStatusOnline                                       // StorageVolumeReplicaStatusOnline - Replica is online
	StorageVolumeReplicaStatusFailed                                       // StorageVolumeReplicaStatusFailed - Replica has failed
	StorageVolumeReplicaStatusOffline                                      // StorageVolumeReplicaStatusOffline - Replica is offline
	StorageVolumeReplicaStatusStarting                                     // StorageVolumeReplicaStatusStarting - Replica is starting
	StorageVolumeReplicaStatusStopping                                     // StorageVolumeReplicaStatusStopping - Replica is stopping
)

// ZStorageVolumeReplicaStatus - Converts pubsub StorageVolumeReplicaStatus to eve-api info.StorageVolumeReplicaStatus
func (svrs StorageVolumeReplicaStatus) ZStorageVolumeReplicaStatus() info.StorageVolumeReplicaStatus {
	switch svrs {
	case StorageVolumeReplicaStatusUnknown:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_UNSPECIFIED
	case StorageVolumeReplicaStatusRebuilding:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_REBUILDING
	case StorageVolumeReplicaStatusOnline:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_ONLINE
	case StorageVolumeReplicaStatusFailed:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_FAILED
	case StorageVolumeReplicaStatusOffline:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_OFFLINE
	case StorageVolumeReplicaStatusStarting:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_STARTING
	case StorageVolumeReplicaStatusStopping:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_STOPPING
	default:
		return info.StorageVolumeReplicaStatus_STORAGE_VOLUME_REPLICA_STATUS_UNSPECIFIED
	}
}

// KubeVolumeReplicaInfo - Information about a replica of a clustered volume in a kubernetes cluster
type KubeVolumeReplicaInfo struct {
	Name                      string
	OwnerNode                 string
	RebuildProgressPercentage uint8
	Status                    StorageVolumeReplicaStatus
}

// ZKubeVolumeReplicaInfo - Converts pubsub KubeVolumeReplicaInfo to eve-api info.KubeVolumeReplicaInfo
func (kvri KubeVolumeReplicaInfo) ZKubeVolumeReplicaInfo() *info.KubeVolumeReplicaInfo {
	iKvri := new(info.KubeVolumeReplicaInfo)
	iKvri.Name = kvri.Name
	iKvri.OwnerNode = kvri.OwnerNode
	iKvri.RebuildProgressPercentage = uint32(kvri.RebuildProgressPercentage)
	iKvri.Status = kvri.Status.ZStorageVolumeReplicaStatus()
	return iKvri
}

// KubeVolumeInfo - Information about a clustered volume in a kubernetes cluster
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
	VolumeID           string
}

// ZKubeVolumeInfo - Converts pubsub KubeVolumeInfo to eve-api info.KubeVolumeInfo
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
	iKvi.VolumeId = kvi.VolumeID
	return iKvi
}

// ServiceStatus - Enum for the status of a service
type ServiceStatus int8

const (
	ServiceStatusUnset    ServiceStatus = iota // ServiceStatusUnset - Service status is unset
	ServiceStatusFailed                        // ServiceStatusFailed - Service status is failed
	ServiceStatusDegraded                      // ServiceStatusDegraded - Service status is degraded
	ServiceStatusHealthy                       // ServiceStatusHealthy - Service status is healthy
)

// ZServiceStatus - Converts pubsub ServiceStatus to eve-api info.ServiceStatus
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

// KubeStorageInfo - Information about the storage services health in a Kubernetes cluster
// This also includes all clustered volumes
type KubeStorageInfo struct {
	Health         ServiceStatus
	TransitionTime time.Time
	Volumes        []KubeVolumeInfo
}

// ZKubeStorageInfo - Converts pubsub KubeStorageInfo to eve-api info.KubeStorageInfo
func (ksi KubeStorageInfo) ZKubeStorageInfo() *info.KubeStorageInfo {
	iKsi := new(info.KubeStorageInfo)
	iKsi.TransitionTime = timestamppb.New(ksi.TransitionTime)
	iKsi.Health = ksi.Health.ZServiceStatus()
	for _, vol := range ksi.Volumes {
		iKsi.Volumes = append(iKsi.Volumes, vol.ZKubeVolumeInfo())
	}
	return iKsi
}

// KubeServiceInfo represents information about a Kubernetes Service
type KubeServiceInfo struct {
	Name           string             // Name of the service
	Namespace      string             // Namespace of the service
	Protocol       corev1.Protocol    // Protocol used by the service (TCP, UDP, etc.)
	Port           int32              // Port number for the service
	NodePort       int32              // NodePort number for NodePort services
	Type           corev1.ServiceType // Type of the service (ClusterIP, NodePort, LoadBalancer, etc.)
	LoadBalancerIP string             // IP address assigned to LoadBalancer service
	ACEenabled     bool               // Authorized Cluster Endpoint access is enabled
}

// Define the K8s service CIDR that we want to exclude from external IP handling
const (
	KubeServicePrefix = "10.43.0.0/16" // Standard K3s service CIDR
)

// KubeIngressInfo represents information about a Kubernetes Ingress
type KubeIngressInfo struct {
	Name        string             // Name of the Ingress resource
	Namespace   string             // Namespace of the Ingress resource
	Hostname    string             // e.g. "example.com"
	Path        string             // e.g. "/api/v1"
	PathType    string             // "Prefix" or "Exact"
	Protocol    string             // "http" or "https"
	Service     string             // Target service name
	ServicePort int32              // Target service port
	ServiceType corev1.ServiceType // Type of the target service (LoadBalancer, NodePort, etc.)
	IngressIP   []string           // LoadBalancer IPs if available
}

// KubeUserServices - Collected User services from kubernetes
type KubeUserServices struct {
	UserService []KubeServiceInfo
	UserIngress []KubeIngressInfo
}

// Equal checks if two KubeUserServices instances are equal
func (s KubeUserServices) Equal(s2 KubeUserServices) bool {
	// Use generics.EqualSetsFn to compare service arrays
	servicesEqual := generics.EqualSetsFn(s.UserService, s2.UserService,
		func(svc1, svc2 KubeServiceInfo) bool {
			return svc1.Namespace == svc2.Namespace &&
				svc1.Name == svc2.Name &&
				svc1.Protocol == svc2.Protocol &&
				svc1.Port == svc2.Port &&
				svc1.NodePort == svc2.NodePort &&
				svc1.LoadBalancerIP == svc2.LoadBalancerIP &&
				svc1.Type == svc2.Type &&
				svc1.ACEenabled == svc2.ACEenabled
		})

	if !servicesEqual {
		return false
	}

	// Use generics.EqualSetsFn to compare ingress arrays
	return generics.EqualSetsFn(s.UserIngress, s2.UserIngress,
		func(ing1, ing2 KubeIngressInfo) bool {
			if ing1.Namespace != ing2.Namespace ||
				ing1.Name != ing2.Name ||
				ing1.Hostname != ing2.Hostname ||
				ing1.Path != ing2.Path ||
				ing1.PathType != ing2.PathType ||
				ing1.ServiceType != ing2.ServiceType ||
				ing1.Protocol != ing2.Protocol {
				return false
			}

			// Compare the ingress IPs
			return generics.EqualSets(ing1.IngressIP, ing2.IngressIP)
		})
}
