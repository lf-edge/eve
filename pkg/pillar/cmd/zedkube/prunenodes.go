// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"

	"github.com/lf-edge/eve/pkg/pillar/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
// config.MasterNodeIDs; followers no-op. This is the EVE-side response to a
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
	if config == nil || len(config.MasterNodeIDs) == 0 {
		return
	}
	if !z.isKubeStatsLeader.Load() {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer cancel()

	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("pruneStaleMasterNodes: clientset: %v", err)
		return
	}

	keep := make(map[string]struct{}, len(config.MasterNodeIDs))
	for _, u := range config.MasterNodeIDs {
		keep[u.String()] = struct{}{}
	}

	nodes, err := clientset.CoreV1().Nodes().List(ctx,
		metav1.ListOptions{LabelSelector: controlPlaneRoleLabel})
	if err != nil {
		log.Errorf("pruneStaleMasterNodes: list nodes: %v", err)
		return
	}

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
		if uuidLabel == z.nodeuuid {
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
			n.Name, metav1.DeleteOptions{}); err != nil {
			log.Errorf("pruneStaleMasterNodes: delete %s: %v", n.Name, err)
		}
		deleteCancel()
	}
}
