// Copyright (c) 2024-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
	"time"

	uuid "github.com/satori/go.uuid"
)

const (
	// ClusterStatusPort - Port for k3s server for cluster status advertise
	// See more detail description in pkg/pillar/docs/zedkube.md
	ClusterStatusPort = "12346"
)

// ClusterType represents a cluster configuration type including various preinstalled components
type ClusterType uint8

const (
	// ClusterTypeNone - default value
	ClusterTypeNone ClusterType = iota
	// ClusterTypeK3sBase - k3s,registration yaml
	ClusterTypeK3sBase
	// ClusterTypeReplicatedStorage - k3s,cdi,kubevirt,longhorn
	ClusterTypeReplicatedStorage
	// ClusterTypeHA - future use
	ClusterTypeHA
)

// EdgeNodeClusterConfig - Configuration for cluster multi-node from controller
type EdgeNodeClusterConfig struct {
	ClusterName string
	ClusterID   UUIDandVersion
	// ClusterInterface - Interface to be used for kubernetes cluster for the node.
	// This can be a Management interface or an App-Shared interface. This is a logical
	// label of the port.
	ClusterInterface string
	// ClusterIPPrefix - IP Prefix for the kubernetes cluster Node IP. This IP prefix is
	// applied to the ClusterInterface. It can be the only IP prefix on the interface, or
	// it can be the 2nd IP prefix on the interface.
	ClusterIPPrefix *net.IPNet
	// IsWorkerNode - Is this node a worker node in the cluster, vs a kubernetes server node
	IsWorkerNode bool
	// JoinServerIP - The kubernetes server IP address to join for this node as part of the
	// multi-node cluster
	JoinServerIP net.IP
	// BootstrapNode - Is this node the bootstrap node for the cluster. In bringing up the
	// kubernetes cluster, one node is designated as the bootstrap node in HA server mode.
	// This node needs to be up first before other nodes can join the cluster. This BootstrapNode
	// will own the 'JoinServerIP' on it's cluster interface.
	BootstrapNode bool

	// CipherBlockStatus, for encrypted cluster token data
	CipherToken CipherBlockStatus

	// CipherGzipRegistrationManifestYaml, for compressed bytes of a registration yaml file
	// Shares the same CipherBlock as CipherToken
	CipherGzipRegistrationManifestYaml CipherBlockStatus

	// ClusterType notes the base, replicated storage, ha attributes of the cluster
	ClusterType ClusterType

	// TieBreakerNodeID - uuid of a node which will be unscheduled for all workloads
	TieBreakerNodeID UUIDandVersion
}

// ENClusterAppStatus - Status of an App Instance in the multi-node cluster
type ENClusterAppStatus struct {
	AppUUID             uuid.UUID // UUID of the appinstance
	IsDNidNode          bool      // DesignatedNodeID is set on the App for this node
	ScheduledOnThisNode bool      // App is running on this device
	StatusRunning       bool      // Status of the app in "Running" state
	AppIsVMI            bool      // Is this a VMI app, vs a Pod app
	AppKubeName         string    // Kube name of the app, either VMI or Pod
}

// Equal returns true if all ENClusterAppStatus fields are equal
func (enc ENClusterAppStatus) Equal(newEnc ENClusterAppStatus) bool {
	return newEnc == enc
}

// Key - returns the key for the config of EdgeNodeClusterConfig
func (config EdgeNodeClusterConfig) Key() string {
	return config.ClusterID.UUID.String()
}

// EdgeNodeClusterStatus - Status of the multi-node cluster published by zedkube
type EdgeNodeClusterStatus struct {
	ClusterName string
	ClusterID   UUIDandVersion
	// ClusterInterface - Interface to be used for kubernetes cluster for the node.
	// This can be a Management interface or an App-Shared interface. This is a logical
	// label of the port.
	ClusterInterface string
	// ClusterIPPrefix - IP Prefix for the kubernetes cluster Node IP. This IP prefix is
	// applied to the ClusterInterface. It can be the only IP prefix on the interface, or
	// it can be the 2nd IP prefix on the interface.
	ClusterIPPrefix *net.IPNet
	// ClusterIPIsReady - Is the cluster IP address ready on the cluster interface
	ClusterIPIsReady bool
	// IsWorkerNode - Is this node a worker node in the cluster, vs a kubernetes server node
	IsWorkerNode bool
	// JoinServerIP - The kubernetes server IP address to join for this node as part of the
	// multi-node cluster
	JoinServerIP net.IP
	// BootstrapNode - Is this node the bootstrap node for the cluster. In bringing up the
	// kubernetes cluster, one node is designated as the bootstrap node in HA server mode.
	// This node needs to be up first before other nodes can join the cluster. This BootstrapNode
	// will own the 'JoinServerIP' on it's cluster interface.
	BootstrapNode bool
	// EncryptedClusterToken - for kubernetes cluster server token
	// This token string is the decrypted from the CipherBlock in the EdgeNodeClusterConfig
	// by zedkube using the Controller and Edge-node certificates. See decryptClusterToken()
	EncryptedClusterToken string

	Error ErrorDescription
}

// KubeLeaderElectInfo - Information about the status reporter leader election
type KubeLeaderElectInfo struct {
	InLeaderElection bool
	IsStatsLeader    bool
	ElectionRunning  bool
	LeaderIdentity   string
	LatestChange     time.Time
}
