// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

// nodeNameByUUID caches the device-UUID to node-name mapping. The mapping is
// stable for the life of a node and re-stamped by kube-init's monitor, so the
// label-selector List stays off the hot path; only the health read is live.
// A name that stops resolving is dropped and looked up again.
var nodeNameByUUID sync.Map

// GetNodeByUUID returns the Kubernetes Node carrying the given EVE device UUID.
func GetNodeByUUID(nodeUUID string) (*corev1.Node, error) {
	client, err := getNodeClient()
	if err != nil {
		return nil, err
	}
	return getNodeByUUIDWithClient(client, nodeUUID)
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

// IsCurrentlyBackupDNID reports whether this node may act on an app in
// place of its designated node: this node holds the eve-app-op lease, and
// the designated node has been unhealthy for longer than threshold.
//
// Required-affinity apps are excluded. Kubernetes would refuse to schedule
// one anywhere but its designated node, so acting on it here would create
// real resources on a node that can never run it -- a hazard that does not
// apply to a caller that places nothing, such as deleting a volume.
func IsCurrentlyBackupDNID(log *base.LogObject, designatedNodeID string,
	isAppOpLeader bool, affinity types.Affinity, threshold time.Duration) bool {
	if affinity == types.RequiredDuringScheduling {
		return false
	}
	return backupDNIDEligible(log, designatedNodeID, isAppOpLeader, threshold)
}

// backupDNIDEligible answers the lease-and-health question, without the
// Required-affinity exclusion IsCurrentlyBackupDNID applies on top. Every
// cheap check runs before the API is touched, so a non-leader and an app with
// no designated node cost nothing.
func backupDNIDEligible(log *base.LogObject, designatedNodeID string,
	isAppOpLeader bool, threshold time.Duration) bool {
	if !isAppOpLeader || designatedNodeID == "" {
		return false
	}
	client, err := getNodeClient()
	if err != nil {
		log.Warnf("backupDNID: no client, cannot confirm: %v", err)
		return false
	}
	eligible, err := isCurrentlyBackupDNIDWithClient(log, client, designatedNodeID,
		threshold)
	if err != nil {
		log.Warnf("backupDNID: cannot confirm node %s health: %v",
			designatedNodeID, err)
		return false
	}
	return eligible
}

// isCurrentlyBackupDNIDWithClient decides against a supplied client, so the
// decision can be tested without a cluster.
func isCurrentlyBackupDNIDWithClient(log *base.LogObject, client kubernetes.Interface,
	designatedNodeID string, threshold time.Duration) (bool, error) {
	name, err := nodeNameForHealth(log, client, designatedNodeID)
	if err != nil {
		return false, err
	}

	node, err := getNodeWithClient(client, name)
	if apierrors.IsNotFound(err) {
		// A cached name that no longer resolves: drop it and try once more,
		// in case the node re-registered under a different name.
		nodeNameByUUID.Delete(designatedNodeID)
		name, err = nodeNameForHealth(log, client, designatedNodeID)
		if err != nil {
			return false, err
		}
		node, err = getNodeWithClient(client, name)
	}
	if err != nil {
		return false, err
	}

	ready, since, found := nodeReadyCondition(node)
	if !found {
		// No Ready condition at all: the node has never reported. Treat it
		// as unconfirmed rather than unhealthy -- see the zero-time note
		// below, which is the same hazard.
		return false, fmt.Errorf("node %s has no Ready condition", name)
	}
	if ready {
		return false, nil
	}
	if since.IsZero() || since.After(time.Now()) {
		// time.Since of the zero time is centuries, which would clear any
		// threshold instantly and hand a peer an app whose owner's health
		// was never established.
		return false, fmt.Errorf("node %s has an unusable Ready timestamp %v",
			name, since)
	}

	outage := time.Since(since)
	if outage < threshold {
		log.Functionf("backupDNID: node %s unhealthy for %v, under threshold %v",
			name, outage, threshold)
		return false, nil
	}
	log.Noticef("backupDNID: node %s unhealthy for %v, past threshold %v",
		name, outage, threshold)
	return true, nil
}

// nodeNameForHealth resolves the UUID to a node name, using the cache and the
// supplied client.
func nodeNameForHealth(log *base.LogObject, client kubernetes.Interface,
	nodeUUID string) (string, error) {
	if name, ok := nodeNameByUUID.Load(nodeUUID); ok {
		return name.(string), nil
	}
	node, err := getNodeByUUIDWithClient(client, nodeUUID)
	if err != nil {
		return "", err
	}
	nodeNameByUUID.Store(nodeUUID, node.Name)
	log.Functionf("backupDNID: %s is node %s", nodeUUID, node.Name)
	return node.Name, nil
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
