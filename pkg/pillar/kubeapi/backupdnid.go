// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// nodeUUIDLabel pairs a Kubernetes Node with an EVE device UUID. It is written
// by pkg/kube/kube-init when the node joins and re-stamped by its monitor, so
// the mapping is maintained rather than written once.
const nodeUUIDLabel = "node-uuid"

// backupDNIDAPITimeout bounds the node-health read. Deliberately much shorter
// than kubeAPITimeout: this read happens on an agent's main loop, where a
// 30-second stall would eat the watchdog's warning budget and a few in a row
// would pass its error time. Failing fast is not a compromise here, because a
// read that cannot complete resolves to "cannot confirm", which already means
// "not currently backup".
const backupDNIDAPITimeout = 3 * time.Second

// GetNodeByUUID returns the Kubernetes Node carrying the given EVE device UUID.
func GetNodeByUUID(nodeUUID string) (*corev1.Node, error) {
	client, err := getNodeClient()
	if err != nil {
		return nil, err
	}
	return getNodeByUUIDWithClient(client, nodeUUID)
}

// GetNodeNameFromUUID resolves an EVE device UUID to its current Kubernetes
// node name, via the same node-uuid label match GetNodeByUUID uses. Not
// cached: a caller doing repeated lookups should add its own caching layer
// suited to its own staleness tolerance.
func GetNodeNameFromUUID(nodeUUID string) (string, error) {
	node, err := GetNodeByUUID(nodeUUID)
	if err != nil {
		return "", err
	}
	return node.Name, nil
}

// getNodeByUUIDWithClient is GetNodeByUUID against a supplied client, so the
// lookup can be tested without a cluster.
func getNodeByUUIDWithClient(client kubernetes.Interface,
	nodeUUID string) (*corev1.Node, error) {
	ctx, cancel := context.WithTimeout(context.Background(), backupDNIDAPITimeout)
	defer cancel()

	selector := metav1.LabelSelector{
		MatchLabels: map[string]string{nodeUUIDLabel: nodeUUID},
	}
	options := metav1.ListOptions{
		LabelSelector: metav1.FormatLabelSelector(&selector),
	}
	nodes, err := client.CoreV1().Nodes().List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("list nodes for uuid %s: %w", nodeUUID, err)
	}
	if len(nodes.Items) == 0 {
		return nil, fmt.Errorf("no node carries %s=%s", nodeUUIDLabel, nodeUUID)
	}
	return &nodes.Items[0], nil
}

// getNodeClient builds a clientset for the node reads above. Thin wrapper
// over GetClientSet so its return type matches the kubernetes.Interface the
// tested call sites take, rather than the concrete *kubernetes.Clientset.
func getNodeClient() (kubernetes.Interface, error) {
	return GetClientSet()
}

// NodeHealthLookup answers whether the node carrying the given EVE device
// UUID is currently known to be Ready, and since when that status has held.
// found is false when the node is not yet known to the cache behind the
// lookup at all.
//
// This is deliberately a plain cache read, never a live API call: it is
// called from an agent's main loop (once per app, or once per volume or
// content tree), where a per-call Nodes().Get() would multiply into one
// live round trip per relevant object per pass. The lookup's implementation
// -- typically a small wrapper around a pubsub subscription of
// types.KubeNodeInfo -- is the caller's to keep current; kubeapi has no
// main loop of its own to do that with.
type NodeHealthLookup func(nodeUUID string) (ready bool, since time.Time, found bool)

// IsCurrentlyBackupDNID reports whether this node may act on an app in
// place of its designated node: this node holds the eve-app-op lease, and
// the designated node has been unhealthy for longer than threshold.
//
// Required-affinity apps are excluded. Kubernetes would refuse to schedule
// one anywhere but its designated node, so acting on it here would create
// real resources on a node that can never run it -- a hazard that does not
// apply to a caller that places nothing, such as deleting a volume.
func IsCurrentlyBackupDNID(log *base.LogObject, lookup NodeHealthLookup,
	designatedNodeID string, isAppOpLeader bool, affinity types.Affinity,
	threshold time.Duration) bool {
	if affinity == types.RequiredDuringScheduling {
		return false
	}
	return backupDNIDEligible(log, lookup, designatedNodeID, isAppOpLeader, threshold)
}

// backupDNIDEligible answers the lease-and-health question, without the
// Required-affinity exclusion IsCurrentlyBackupDNID applies on top. Every
// cheap check runs before the lookup, so a non-leader and an app with no
// designated node cost nothing.
func backupDNIDEligible(log *base.LogObject, lookup NodeHealthLookup,
	designatedNodeID string, isAppOpLeader bool, threshold time.Duration) bool {
	if !isAppOpLeader || designatedNodeID == "" {
		return false
	}
	eligible, err := isCurrentlyBackupDNIDFromHealth(log, lookup, designatedNodeID,
		threshold)
	if err != nil {
		log.Warnf("backupDNID: cannot confirm node %s health: %v",
			designatedNodeID, err)
		return false
	}
	return eligible
}

// isCurrentlyBackupDNIDFromHealth decides against a supplied lookup, so the
// decision can be tested without a cluster or a cache of its own.
func isCurrentlyBackupDNIDFromHealth(log *base.LogObject, lookup NodeHealthLookup,
	designatedNodeID string, threshold time.Duration) (bool, error) {
	ready, since, found := lookup(designatedNodeID)
	if !found {
		// Never reported into the cache. Treat it as unconfirmed rather
		// than unhealthy -- see the zero-time note below, which is the
		// same hazard.
		return false, fmt.Errorf("node %s health not yet known", designatedNodeID)
	}
	if ready {
		return false, nil
	}
	if since.IsZero() || since.After(time.Now()) {
		// time.Since of the zero time is centuries, which would clear any
		// threshold instantly and hand a peer an app whose owner's health
		// was never established.
		return false, fmt.Errorf("node %s has an unusable Ready timestamp %v",
			designatedNodeID, since)
	}

	outage := time.Since(since)
	if outage < threshold {
		log.Functionf("backupDNID: node %s unhealthy for %v, under threshold %v",
			designatedNodeID, outage, threshold)
		return false, nil
	}
	log.Noticef("backupDNID: node %s unhealthy for %v, past threshold %v",
		designatedNodeID, outage, threshold)
	return true, nil
}

func getNodeWithClient(client kubernetes.Interface,
	name string) (*corev1.Node, error) {
	ctx, cancel := context.WithTimeout(context.Background(), backupDNIDAPITimeout)
	defer cancel()
	return client.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
}

// nodeReadyCondition reports whether the node's Ready condition is True, when
// it last changed, and whether the condition is present at all.
//
// Healthy means ConditionTrue and nothing else. A hard power-off leaves Ready
// at ConditionUnknown, not ConditionFalse -- Kubernetes cannot know the node
// failed, only that it stopped reporting -- so a check written as "unhealthy
// when ConditionFalse" would never fire for the case this exists for.
func nodeReadyCondition(node *corev1.Node) (ready bool, since time.Time, found bool) {
	for _, cond := range node.Status.Conditions {
		if cond.Type != corev1.NodeReady {
			continue
		}
		return cond.Status == corev1.ConditionTrue, cond.LastTransitionTime.Time, true
	}
	return false, time.Time{}, false
}

// IsNodeReady reports whether the named Kubernetes node's Ready condition is
// currently true. Any lookup failure (API unreachable, node not found) is
// treated as "cannot confirm" -- false, the safe direction for a caller
// deciding whether a resource still assigned to that node is actually owned
// by a live node or just hasn't been reaped yet.
func IsNodeReady(nodeName string) bool {
	client, err := GetClientSet()
	if err != nil {
		return false
	}
	node, err := getNodeWithClient(client, nodeName)
	if err != nil {
		return false
	}
	ready, _, found := nodeReadyCondition(node)
	return found && ready
}
