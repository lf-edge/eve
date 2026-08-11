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

	// EnableNativeK8SOrchestration, when true on a ClusterTypeReplicatedStorage
	// cluster, enables native Kubernetes orchestration of user workloads
	// (registration manifest + kube-vip load balancer) in addition to the
	// EVE-API-managed scheduling. Unlike ClusterTypeK3sBase it does NOT remove
	// longhorn/kubevirt; the full replicated-storage stack keeps running.
	// Sourced from EdgeNodeCluster.enable_native_k8s_orchestration.
	EnableNativeK8SOrchestration bool

	// LBInterfaces - load balancer interface configurations from the controller.
	// Populated when native k8s orchestration is enabled (see
	// NativeK8sOrchestrationEnabled). Mirrors the LoadBalancerService interfaces
	// array from the protobuf; each entry holds one interface name and its first
	// CIDR from address_cidrs.
	LBInterfaces []LBInterfaceConfig

	// MasterNodeIDs - UUIDs of all designated control-plane nodes in the cluster
	// as known to the controller. Sourced from EdgeNodeCluster.master_node_uuids.
	// Used by zedkube on the elected stats-leader to prune k8s Node objects
	// (and thereby k3s embedded etcd members) for masters the controller has
	// removed via a "replace node" operation. Workers are not included.
	MasterNodeIDs []uuid.UUID

	// WitnessIP - virtual IP that the witness (a lightweight etcd-only 3rd
	// voting member for a 2-physical-node cluster) binds its etcd to on
	// ClusterInterface. Nil means no witness runs. Sourced from
	// EdgeNodeCluster.witness.witness_ip. The witness always co-locates with
	// whichever node currently owns JoinServerIP, so there is no separate
	// placement field.
	WitnessIP net.IP

	// WitnessConfigError describes why a witness configured by the controller
	// was rejected, leaving WitnessIP nil. Empty when the witness config is
	// valid or absent. Carried here so zedkube can report it to the controller
	// without zedagent having to invalidate the whole cluster config over it.
	WitnessConfigError string

	// QuorumRecoveryGeneration - controller-declared quorum-loss recovery
	// trigger. Incrementing it tells the node named by JoinServerIP to
	// promote itself to sole bootstrap via a forced etcd quorum reset.
	// That node tracks the last generation it converged to and does
	// nothing while this value is unchanged. Initial cluster formation is
	// generation 0.
	//
	// A rejected increase (see QuorumRecoveryError) leaves this at the
	// last accepted value rather than the controller's new one.
	QuorumRecoveryGeneration uint32

	// QuorumRecoveryError describes why an increase to
	// QuorumRecoveryGeneration was rejected, leaving it unchanged. Empty
	// when the value was accepted or never changed. A rejected increase
	// is one that does not name a survivor: an increase that leaves this
	// device's own bootstrap status unchanged either forces a healthy
	// seed into an unrequested destructive reset, or asks a peer that
	// isn't being promoted to do something this design has no action
	// for, either way stranding whichever device actually needed to
	// rejoin. Carried here so zedkube can report it to the controller
	// without zedagent having to invalidate the whole cluster config
	// over it.
	QuorumRecoveryError string
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

// NativeK8sOrchestrationEnabled reports whether native Kubernetes orchestration
// of user workloads is active for this cluster: always for the legacy
// ClusterTypeK3sBase, and for ClusterTypeReplicatedStorage when the controller
// opts in via EnableNativeK8SOrchestration. It gates the registration manifest
// and the kube-vip load balancer. The replicated-storage opt-in, unlike
// K3sBase, keeps longhorn/kubevirt installed.
func (config EdgeNodeClusterConfig) NativeK8sOrchestrationEnabled() bool {
	if config.ClusterType == ClusterTypeK3sBase {
		return true
	}
	return config.ClusterType == ClusterTypeReplicatedStorage &&
		config.EnableNativeK8SOrchestration
}

// IsTieBreakerNode reports whether nodeUUID is the tie-breaker node the
// controller designated for this cluster. A tie-breaker node exists only to
// hold a quorum vote: it is kept cordoned, runs no workloads and carries no
// Longhorn replicas, so node-local storage configuration does not apply to it.
//
// This is the authoritative test. Do not infer tie-breaker-ness from a node
// being unschedulable: Longhorn drives its node Schedulable condition off the
// Kubernetes cordon, which every node passes through at boot and during
// drains, so that signal would misclassify ordinary storage nodes.
//
// Returns false when the controller designated no tie-breaker (zero UUID) or
// nodeUUID does not parse, so a node is only treated as the tie-breaker on
// positive evidence from the EVE API config.
func (config EdgeNodeClusterConfig) IsTieBreakerNode(nodeUUID string) bool {
	if config.TieBreakerNodeID.UUID == uuid.Nil {
		return false
	}
	parsed, err := uuid.FromString(nodeUUID)
	if err != nil {
		return false
	}
	return parsed == config.TieBreakerNodeID.UUID
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

	// WitnessIP mirrors EdgeNodeClusterConfig.WitnessIP. Consumed by NIM, which
	// bridges the cluster port and plugs a veth carrying this address into the
	// witness container's network namespace, and by the witness itself.
	WitnessIP net.IP

	// WitnessConfigError mirrors EdgeNodeClusterConfig.WitnessConfigError so a
	// witness the controller configured but the device rejected is visible
	// remotely rather than only in the device log.
	WitnessConfigError ErrorDescription

	// QuorumRecoveryGeneration mirrors
	// EdgeNodeClusterConfig.QuorumRecoveryGeneration.
	QuorumRecoveryGeneration uint32

	// QuorumRecoveryError mirrors EdgeNodeClusterConfig.QuorumRecoveryError
	// so a rejected generation increase is visible remotely rather than
	// only in the device log.
	QuorumRecoveryError ErrorDescription

	Error ErrorDescription
}

// Node annotations through which kube-init reports state that only the
// node itself knows, for the elected cluster-info reporter to read back
// and forward to the controller. The same route node-uuid already
// takes: a node has no other way to tell the reporter something the
// kube API does not already hold.
//
// Unprefixed, matching the keys EVE already sets on its nodes
// (node-uuid, tie-breaker-node). Keys carrying another project's state,
// such as Longhorn's, keep that project's prefix.
const (
	// NodeRecoveryAnnotation carries a KubeQuorumRecoveryStatus as JSON.
	NodeRecoveryAnnotation = "quorum-recovery"
	// NodeWitnessAnnotation carries a WitnessStatus as JSON, stamped
	// only by the device hosting the witness.
	NodeWitnessAnnotation = "witness-status"
)

// KubeQuorumRecoveryStatus is a device's progress against
// EdgeNodeCluster.quorum_recovery_generation. Reported by the device
// promoted to sole bootstrap via a forced etcd quorum reset; every other
// current/former member converges to nothing, since its cluster config
// is withdrawn outright instead.
type KubeQuorumRecoveryStatus struct {
	// AppliedGeneration is the last generation this device fully
	// converged to.
	AppliedGeneration uint32
	// Converging is true while it is still working towards a newer one.
	Converging bool
	// Error is set when the most recent attempt failed;
	// AppliedGeneration stays at the last one that succeeded.
	Error ErrorDescription
	// LastTransitionAt is when the state above last changed.
	LastTransitionAt time.Time
}

// WitnessEtcdState is the witness's view of its own etcd membership.
type WitnessEtcdState uint8

const (
	// WitnessEtcdStateUnspecified - never reported.
	WitnessEtcdStateUnspecified WitnessEtcdState = iota
	// WitnessEtcdStateIdle - running no etcd at all: no witness is
	// configured for this cluster, or the witness has not yet started
	// joining.
	WitnessEtcdStateIdle
	// WitnessEtcdStateJoining - k3s is up but this member is not yet a
	// started, voting member. Includes the learner phase, during which
	// etcd replicates to it but it casts no vote.
	WitnessEtcdStateJoining
	// WitnessEtcdStateJoined - an active voter; the healthy steady state.
	WitnessEtcdStateJoined
	// WitnessEtcdStateError - the witness failed to reach or hold
	// membership.
	WitnessEtcdStateError
)

// String returns a human-readable name for the WitnessEtcdState.
func (s WitnessEtcdState) String() string {
	switch s {
	case WitnessEtcdStateIdle:
		return "Idle"
	case WitnessEtcdStateJoining:
		return "Joining"
	case WitnessEtcdStateJoined:
		return "Joined"
	case WitnessEtcdStateError:
		return "Error"
	default:
		return "Unspecified"
	}
}

// WitnessStatus - status of the 2-node-HA witness, published by the
// kube-init daemon running in the witness container and consumed by
// zedkube on the same device, which forwards it to the controller.
//
// Published only by the device hosting the witness. Every other device
// has no witness container contributing to this topic.
type WitnessStatus struct {
	// WitnessIP is the address this witness binds its etcd to, echoing
	// the controller's configuration.
	WitnessIP string
	// State is the witness's own view of its etcd membership.
	State WitnessEtcdState
	// Error describes why the witness is not where it should be, e.g. a
	// wrong token, an unreachable seed or a stale cluster ID - detail
	// WitnessEtcdStateError alone does not carry.
	Error ErrorDescription
}

// Key - returns the key for the WitnessStatus publication.
func (status WitnessStatus) Key() string {
	return "global"
}

// KubeLeaderElectInfo - Information about the leader elections this node runs.
// InLeaderElection, IsStatsLeader, ElectionRunning, and LeaderIdentity
// describe the status-reporter election only.
type KubeLeaderElectInfo struct {
	InLeaderElection bool
	IsStatsLeader    bool
	ElectionRunning  bool
	LeaderIdentity   string
	// IsAppOpLeader reports whether this node holds the eve-app-op lease,
	// which is what decides the one node allowed to act on an app whose
	// designated node is down. AppOpLeaderIdentity is the holder this node
	// last observed, whether or not that is this node.
	IsAppOpLeader       bool
	AppOpLeaderIdentity string
	LatestChange        time.Time
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
