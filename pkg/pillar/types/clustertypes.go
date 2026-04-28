// Copyright (c) 2024-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
)

const (
	// ClusterStatusPort - Port for k3s server for cluster status advertise
	// See more detail description in pkg/pillar/docs/zedkube.md
	ClusterStatusPort = "12346"
	// VmiVNCDir is the directory for VNC parameter files.
	// VmiVNCDir specifies the directory for VNC parameter files used by both remote-console and edgeview VNC.
	VmiVNCDir = "/run/edgeview/VncParams"
	// VmiVNCFileName is the unified path for both remote-console and edgeview VNC configuration file.
	VmiVNCFileName = VmiVNCDir + "/vmiVNC.run"
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

// LBInterfaceConfig pairs a network interface name with the IP CIDR pool that
// kube-vip uses to allocate load balancer IPs on that interface.
// Used in both EdgeNodeClusterConfig and EdgeNodeClusterStatus.
type LBInterfaceConfig struct {
	// Interface is the logical label of the network interface.
	Interface string
	// IPPrefix is the IP CIDR pool for load balancer IP allocation, in CIDR
	// notation (e.g. "192.168.1.24/29"). The host bits are preserved so that
	// jq consumers in cluster-init.sh see the original address, not the
	// network address.
	IPPrefix string
}

// EdgeNodeClusterConfig - Configuration for cluster multi-node from controller
type EdgeNodeClusterConfig struct {
	Initialized bool // To tell a subscriber that publisher is done
	Valid       bool // To tell a subscriber there is a cluster
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

	// LBInterfaces - load balancer interface configurations from the controller.
	// Populated only for ClusterTypeK3sBase clusters. Mirrors the LoadBalancerService
	// interfaces array from the protobuf; each entry holds one interface name and its
	// first CIDR from address_cidrs.
	LBInterfaces []LBInterfaceConfig
}

// AppKubeStatus represents this node's last view of an app's lifecycle in the
// kubernetes cluster. Each value comes from a distinct branch in zedkube's
// periodic poll. Consumers should treat any value other than
// AppKubeStatusRunning as "no authoritative evidence the app is running on a
// peer" and fail open accordingly.
type AppKubeStatus uint8

const (
	// AppKubeStatusUnknown - never polled (cold start; zero value).
	AppKubeStatusUnknown AppKubeStatus = iota
	// AppKubeStatusAPIUnreachable - kube API not reachable past the grace window.
	AppKubeStatusAPIUnreachable
	// AppKubeStatusNotInCluster - API ok, no pod found for this app.
	AppKubeStatusNotInCluster
	// AppKubeStatusNotRunningState - pod found, kubernetes phase != PodRunning.
	AppKubeStatusNotRunningState
	// AppKubeStatusRunningState - pod found, kubernetes phase == PodRunning.
	AppKubeStatusRunningState
)

// String returns a human-readable name for the AppKubeStatus.
func (s AppKubeStatus) String() string {
	switch s {
	case AppKubeStatusUnknown:
		return "Unknown"
	case AppKubeStatusAPIUnreachable:
		return "APIUnreachable"
	case AppKubeStatusNotInCluster:
		return "NotInCluster"
	case AppKubeStatusNotRunningState:
		return "NotRunningState"
	case AppKubeStatusRunningState:
		return "RunningState"
	default:
		return "Invalid"
	}
}

// ENClusterAppStatus - Status of an App Instance in the multi-node cluster
type ENClusterAppStatus struct {
	AppUUID             uuid.UUID     // UUID of the appinstance
	IsDNidNode          bool          // DesignatedNodeID is set on the App for this node
	ScheduledOnThisNode bool          // Pod for this app is scheduled on this node
	AppKubeStatus       AppKubeStatus // This node's view of the app's kube lifecycle
	AppIsVMI            bool          // Is this a VMI app, vs a Pod app
	VMIName             string        // Kube name of the VMI
	VNCPort             uint32        // VNC port for the VMI (e.g., 5901)
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
	// This can be a Management interface or an App-Shared interface. This is the
	// resolved Linux interface name of the port.
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

	// LBInterfaces - load balancer interface configurations.
	// Only populated on the bootstrap node when LoadBalancerService is configured.
	// IPPrefix strings are in CIDR notation consumed by cluster-init.sh via jq.
	LBInterfaces []LBInterfaceConfig

	// LBIPPrefixes - LB CIDR pool strings populated on every cluster node
	// (bootstrap and non-bootstrap) whenever LoadBalancerService is configured.
	// Used by dpcmanager to filter kube-vip VIPs (/32 host-route addresses) out
	// of AddrInfoList on all nodes, not just the bootstrap node.
	LBIPPrefixes []string

	// LBConfigError is set on any cluster node (bootstrap or not) when the
	// controller-supplied LB CIDR overlaps with a local IP on any L3 port of
	// that node. On the bootstrap node the offending LBInterface entry is also
	// omitted from LBInterfaces so kube-vip is not applied; non-bootstrap nodes
	// only report here since they do not control kube-vip deployment.
	LBConfigError ErrorDescription

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

// VmiVNCConfig is the JSON structure for vmiVNC.run file.
// VmiVNCConfig defines the unified format used by both remote-console and edgeview VNC.
type VmiVNCConfig struct {
	VMIName   string `json:"VMIName"`
	VNCPort   uint32 `json:"VNCPort"`
	AppUUID   string `json:"AppUUID,omitempty"`   // UUID of the app owning this session
	CallerPID int    `json:"CallerPID,omitempty"` // Set by edgeview; absent for remote-console
}

// procPath is the root of the proc filesystem. Overridden in tests.
var procPath = "/proc"

// OwnerAlive reports whether CallerPID refers to a live edge-view process.
// Returns false when CallerPID is unset (remote-console file), when the PID
// is dead, or when the PID has been reused by a different program.
func (c VmiVNCConfig) OwnerAlive() bool {
	if c.CallerPID <= 0 {
		return false
	}
	comm, err := os.ReadFile(fmt.Sprintf("%s/%d/comm", procPath, c.CallerPID))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(comm)) == "edge-view"
}
