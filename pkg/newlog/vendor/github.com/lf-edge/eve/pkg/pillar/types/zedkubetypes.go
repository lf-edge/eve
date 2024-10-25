// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// KubeNodeStatus - Enum for the status of a Kubernetes node
type KubeNodeStatus int8

const (
	KubeNodeStatusUnknown      KubeNodeStatus = iota // KubeNodeStatusUnknown - Node status is unknown
	KubeNodeStatusReady                              // KubeNodeStatusReady - Node is in ready status
	KubeNodeStatusNotReady                           // KubeNodeStatusNotReady - Node is in not ready status
	KubeNodeStatusNotReachable                       // KubeNodeStatusNotReachable - Node is not reachable
)

// KubeNodeInfo - Information about a Kubernetes node
type KubeNodeInfo struct {
	Name               string
	Status             KubeNodeStatus
	IsMaster           bool
	UsesEtcd           bool
	CreationTime       time.Time
	LastTransitionTime time.Time
	KubeletVersion     string
	InternalIP         string
	ExternalIP         string
	Schedulable        bool
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

// KubeVMIInfo - Information about a VirtualMachineInstance
type KubeVMIInfo struct {
	Name               string
	Status             KubeVMIStatus
	CreationTime       time.Time
	LastTransitionTime time.Time
	IsReady            bool
	NodeName           string
}

// KubeClusterInfo - Information about a Kubernetes cluster
type KubeClusterInfo struct {
	Nodes   []KubeNodeInfo // List of nodes in the cluster
	AppPods []KubePodInfo  // List of EVE application pods
	AppVMIs []KubeVMIInfo  // List of VirtualMachineInstance
}
