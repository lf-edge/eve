// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// controlPlaneRoleLabel is the k3s/k8s node label identifying a control-plane
// (master) node. The master/ label was removed upstream; control-plane is the
// canonical replacement.
const controlPlaneRoleLabel = "node-role.kubernetes.io/control-plane"

// nodeUUIDLabel pairs a k8s Node to an EVE device UUID. Set by zedkube on
// every node and used elsewhere (e.g. getLocalNode in drain.go) to map between
// the two identities.
const nodeUUIDLabel = "node-uuid"

// pruneStaleMasterNodes is invoked from applyClusterConfig on every ENCC
// create/modify with a valid config. The elected stats-leader deletes any k8s
// control-plane Node whose node-uuid label is absent from
// config.MasterNodeIDs; followers no-op. A sweep that could not run, on a
// follower or while the kube API is down, is left pending and retried by the
// periodic re-evaluation (see pruneStaleMasterDue). This is the EVE-side
// response to a
// controller "replace node" operation: removing the stale Node object lets
// k3s's embedded-etcd controller drop the corresponding etcd member, which is
// the precondition for a replacement master to join the cluster.
//
// Ready/NotReady is intentionally not part of the predicate: the controller
// may decide to replace a still-healthy master. Worker nodes are out of scope
// because they are never present in MasterNodeIDs.
//
// MasterNodeIDs being empty is treated as "controller has not yet sent the
// list" (e.g. older zedcloud that pre-dates the field, or a transient parse
// error) — we skip the sweep entirely so no Node is touched.
//
// Self-deletion is never performed: if this node's own UUID is absent from
// MasterNodeIDs (i.e. the controller is replacing *this* node), we skip it.
// The controller stops shipping config to the removed node directly; letting
// the node delete itself while still running would disrupt etcd membership
// and Longhorn replicas before a graceful exit.
func (z *zedkube) pruneStaleMasterNodes(config *types.EdgeNodeClusterConfig) {
	swept := z.sweepStaleMasterNodes(config)
	z.pruneStaleMasterPending = !swept
	if swept {
		z.pruneStaleMasterLast = time.Now()
	}
}

// pruneStaleMasterDue reports whether the periodic re-evaluation should sweep
// now: on every tick while a sweep is pending, as one that could not run
// must run as soon as it can, and otherwise once pruneStaleMasterInterval
// has passed since the last completed sweep.
//
// A sweep is pending when the last one did not complete: this node was not
// the stats leader, or the kube API did not answer. That is the case right
// after a quorum recovery, when the cluster config that drops the lost member
// arrives while the API is still down, so the stale member is removed as soon
// as the API is back rather than up to pruneStaleMasterInterval later.
func pruneStaleMasterDue(pending bool, last, now time.Time) bool {
	return pending || now.Sub(last) >= pruneStaleMasterInterval*time.Second
}

// sweepStaleMasterNodes deletes the stale master nodes when this node is the
// stats leader, and returns whether there is nothing left to do: either it
// swept them all, or the controller has not sent master_node_uuids.
func (z *zedkube) sweepStaleMasterNodes(config *types.EdgeNodeClusterConfig) bool {
	if config == nil || len(config.MasterNodeIDs) == 0 {
		return true
	}
	if !z.isStatsLeader() {
		return false
	}
	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("pruneStaleMasterNodes: clientset: %v", err)
		return false
	}
	keep := make(map[string]struct{}, len(config.MasterNodeIDs))
	for _, u := range config.MasterNodeIDs {
		keep[u.String()] = struct{}{}
	}
	return deleteStaleMasterNodes(clientset, keep, z.nodeuuid)
}

// deleteStaleMasterNodes deletes every control-plane Node whose node-uuid
// label is not in keep, except this node's own (selfUUID). Returns whether it
// listed the nodes and deleted every stale one.
func deleteStaleMasterNodes(clientset kubernetes.Interface, keep map[string]struct{},
	selfUUID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer cancel()
	nodes, err := clientset.CoreV1().Nodes().List(ctx,
		metav1.ListOptions{LabelSelector: controlPlaneRoleLabel})
	if err != nil {
		log.Errorf("pruneStaleMasterNodes: list nodes: %v", err)
		return false
	}

	swept := true
	for i := range nodes.Items {
		n := &nodes.Items[i]
		uuidLabel := n.Labels[nodeUUIDLabel]
		if uuidLabel == "" {
			log.Warnf("pruneStaleMasterNodes: control-plane node %s has no %s label, skipping",
				n.Name, nodeUUIDLabel)
			continue
		}
		if _, ok := keep[uuidLabel]; ok {
			continue
		}
		if uuidLabel == selfUUID {
			// Never delete our own Node object. The controller stops
			// shipping config to us when we are being replaced; self-
			// deletion while still running would disrupt etcd and
			// Longhorn replicas before we exit gracefully.
			log.Noticef("pruneStaleMasterNodes: skipping self (uuid=%s) not in ENCC master_node_uuids",
				uuidLabel)
			continue
		}
		deleteCtx, deleteCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
		log.Noticef("pruneStaleMasterNodes: deleting stale master node %s (uuid=%s) not in ENCC master_node_uuids",
			n.Name, uuidLabel)
		if err := clientset.CoreV1().Nodes().Delete(deleteCtx,
			n.Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
			log.Errorf("pruneStaleMasterNodes: delete %s: %v", n.Name, err)
			swept = false
		}
		deleteCancel()
	}
	return swept
}
