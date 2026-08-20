// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Per-NI NetworkAttachmentDefinition provisioning.
//
// Controller-managed (ENC) apps resolve their Network Instance implicitly: zedrouter
// pre-allocates a MAC and the CNI request is matched to the NI by that MAC. Directly
// deployed Kubernetes workloads (raw yaml / helm charts) carry no AppNetworkConfig, so
// the NI identity must be carried explicitly. We do that by creating one NAD per NI
// whose CNI config embeds the NI UUID in the "networkInstance" field that eve-bridge
// reads and forwards to zedrouter over RPC.
//
// All NADs live in the single eve-kube-app namespace (CreateOrUpdateNAD hardcodes it).
// Workloads in any namespace reference the NAD cross-namespace as
// "eve-kube-app/<nad-name>", so their own (arbitrary, unknown) namespace does not matter.
//
// Ownership: the NAD is a single cluster-wide object, while NetworkInstanceStatus is
// per-node (each node receives its own copy of a cluster NI). To avoid one node acting on
// its local view and disturbing a NAD other nodes rely on, all NAD writes (create, update,
// delete) are performed only by the elected stats-leader. Event handlers cover steady
// state; reconcileAllNINADs() runs once when this node becomes leader to cover NIs whose
// status was already processed before the lease was won.

// niNADName returns the NAD name for a Network Instance. The NI display name (sanitized
// to a DNS-1123 fragment) is used for human-friendly references in workload yaml, falling
// back to the UUID when the display name has no usable characters. Display names are
// expected to be unique within the cluster; two NIs whose names sanitize to the same
// string would collide on a single NAD (last writer wins) - logged by reconcileNINAD.
func niNADName(status types.NetworkInstanceStatus) string {
	name := base.SanitizeKubeName(status.DisplayName)
	if name == "" {
		name = status.UUIDandVersion.UUID.String()
	}
	const maxLen = 253 - len("ni-")
	if len(name) > maxLen {
		name = name[:maxLen]
	}
	return "ni-" + name
}

// niNADConfig builds the CNI config JSON embedded in the per-NI NAD. eve-bridge reads
// the "networkInstance" field to learn which NI a workload interface attaches to.
func niNADConfig(niUUID string) string {
	return fmt.Sprintf(`{"cniVersion":"0.3.1","type":"eve-bridge","networkInstance":%q}`, niUUID)
}

// niNADApplicable reports whether a NI needs a per-NI NAD. Only cluster-wide
// Local/Switch NIs qualify: cluster-wide because the NAD is a single
// cluster-scoped k8s object shared by every node (see the ownership note
// above), and Local/Switch because those are the types served by the
// eve-bridge CNI - direct-attach and others use a different CNI (host-device)
// and are out of scope here.
func niNADApplicable(status types.NetworkInstanceStatus) bool {
	if !status.ClusterWide {
		return false
	}
	switch status.Type {
	case types.NetworkInstanceTypeLocal, types.NetworkInstanceTypeSwitch:
		return true
	default:
		return false
	}
}

// reconcileNINAD creates or updates the per-NI NAD for a local/switch Network Instance.
// Leader-only: see the ownership note above.
func (z *zedkube) reconcileNINAD(status types.NetworkInstanceStatus) {
	z.reconcileNINADWithWriter(status, func(name, spec string) error {
		return kubeapi.CreateOrUpdateNAD(log, name, spec)
	})
}

func (z *zedkube) reconcileNINADWithWriter(status types.NetworkInstanceStatus,
	write func(name, spec string) error) {
	if !z.clusterConfig.NativeK8sOrchestrationEnabled() {
		return
	}
	if !niNADApplicable(status) {
		return
	}
	if !z.isStatsLeader() {
		return
	}
	niUUID := status.UUIDandVersion.UUID.String()
	name := niNADName(status)
	if err := write(name, niNADConfig(niUUID)); err != nil {
		log.Errorf("reconcileNINAD: CreateOrUpdateNAD %s failed: %v", name, err)
		return
	}
	log.Noticef("reconcileNINAD: NAD %s ready for NI %s (%s)",
		name, status.DisplayName, niUUID)
}

// removeNINAD deletes the per-NI NAD on an explicit NI delete (or rename). Leader-only,
// and driven only by a real delete/rename event - never by mere absence of status - so a
// node losing its local NI copy (reboot, transient propagation) cannot tear down a NAD
// that workloads on other nodes still depend on.
func (z *zedkube) removeNINAD(status types.NetworkInstanceStatus) {
	z.removeNINADWithWriter(status, func(name string) error {
		return kubeapi.DeleteNAD(log, name)
	})
}

func (z *zedkube) removeNINADWithWriter(status types.NetworkInstanceStatus,
	remove func(name string) error) {
	if !z.clusterConfig.NativeK8sOrchestrationEnabled() {
		return
	}
	if !niNADApplicable(status) {
		return
	}
	if !z.isStatsLeader() {
		return
	}
	name := niNADName(status)
	if err := remove(name); err != nil {
		log.Warnf("removeNINAD: DeleteNAD %s failed: %v", name, err)
		return
	}
	log.Noticef("removeNINAD: NAD %s deleted for NI %s", name, status.DisplayName)
}

// reconcileAllNINADs ensures a NAD exists for every NI currently known to this node.
// Called once on the leader->true transition to cover NIs whose status was processed
// before this node won the stats lease (which would otherwise emit no fresh event).
// Runs in the main event-loop goroutine so it does not race the subscription cache.
func (z *zedkube) reconcileAllNINADs() {
	if !z.clusterConfig.NativeK8sOrchestrationEnabled() {
		return
	}
	if !z.isStatsLeader() {
		return
	}
	items := z.subNetworkInstanceStatus.GetAll()
	for _, item := range items {
		status := item.(types.NetworkInstanceStatus)
		z.reconcileNINAD(status)
	}
	log.Noticef("reconcileAllNINADs: reconciled %d network instances", len(items))
}

func handleNetworkInstanceStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	z := ctxArg.(*zedkube)
	status := statusArg.(types.NetworkInstanceStatus)
	z.reconcileNINAD(status)
}

func handleNetworkInstanceStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	z := ctxArg.(*zedkube)
	status := statusArg.(types.NetworkInstanceStatus)
	oldStatus := oldStatusArg.(types.NetworkInstanceStatus)
	// A display-name change moves the NAD to a new name; drop the stale one first.
	if oldStatus.DisplayName != status.DisplayName {
		z.removeNINAD(oldStatus)
	}
	z.reconcileNINAD(status)
}

func handleNetworkInstanceStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	z := ctxArg.(*zedkube)
	status := statusArg.(types.NetworkInstanceStatus)
	z.removeNINAD(status)
}
