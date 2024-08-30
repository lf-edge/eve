// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

type KubeNodeStatus int8

const (
	KubeNodeStatusUnknown KubeNodeStatus = iota
	KubeNodeStatusReady
	KubeNodeStatusNotReady
	KubeNodeStatusNotReachable
)

type KubeNodeInfo struct {
	Name               string
	Status             KubeNodeStatus
	IsMaster           bool
	IsEtcd             bool
	CreationTime       time.Time
	LastTransitionTime time.Time
	KubeletVersion     string
	InternalIP         string
	ExternalIP         string
	Schedulable        bool
}

type KubePodStatus int8

const (
	KubePodStatusUnknown KubePodStatus = iota
	KubePodStatusPending
	KubePodStatusRunning
	KubePodStatusSucceeded
	KubePodStatusFailed
)

type KubePodInfo struct {
	Name              string
	Status            KubePodStatus
	RestartCount      int32
	RestartTimestamp  time.Time
	CreationTimestamp time.Time
	PodIP             string
	NodeName          string
}

type KubeClusterInfo struct {
	Nodes   []KubeNodeInfo // List of nodes in the cluster
	AppPods []KubePodInfo  // List of EVE application pods
}
