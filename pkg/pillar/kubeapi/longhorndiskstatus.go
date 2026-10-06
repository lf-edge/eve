// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"fmt"

	lhv1beta2 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	"github.com/longhorn/longhorn-manager/k8s/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// diskStatusGetter is the subset of the generated Longhorn client this file
// needs, kept narrow so the state logic below can be exercised without a
// live API server.
type diskStatusGetter interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*lhv1beta2.Node, error)
}

// nodeDiskStatusReady reports whether nodeName's Longhorn Node object has
// finished recording status for its disks: every disk Spec.Disks declares
// must have a Status.DiskStatus entry with a disk UUID, and at least one
// must have a True Ready condition. The disk monitor that fills in that
// status needs a running instance-manager, so a node whose instance-manager
// only just started can pass instanceManagerReady before the monitor has
// completed even once.
//
// Only recording is required of every disk; Ready is required of one. A
// recorded but degraded disk must not strand the node, since the callers of
// checkLonghornReady mostly need it able to host a replica, which is the
// any-disk semantics checkLonghornSchedulable uses.
func nodeDiskStatusReady(ctx context.Context, getter diskStatusGetter, nodeName string) (bool, error) {
	node, err := getter.Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	if len(node.Spec.Disks) == 0 {
		return false, nil
	}
	anyReady := false
	for diskName := range node.Spec.Disks {
		status := node.Status.DiskStatus[diskName]
		if status == nil || status.DiskUUID == "" {
			return false, nil
		}
		for _, cond := range status.Conditions {
			if cond.Type == lhv1beta2.DiskConditionTypeReady &&
				cond.Status == lhv1beta2.ConditionStatusTrue {
				anyReady = true
				break
			}
		}
	}
	return anyReady, nil
}

// diskStatusReady is the gate checkLonghornReady applies after the
// instance-manager gate. A variable so tests can stub it, like
// instanceManagerReady. The ctx it receives is bounded by checkLonghornReady.
var diskStatusReady = checkLonghornDiskStatusReady

// checkLonghornDiskStatusReady fails while nodeName's Longhorn Node
// object has not finished recording its disks (see nodeDiskStatusReady).
func checkLonghornDiskStatusReady(ctx context.Context, nodeName string) error {
	config, err := GetKubeConfig()
	if err != nil {
		return fmt.Errorf("longhorn disk status: kubeconfig: %v", err)
	}
	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("longhorn disk status: versioned client: %v", err)
	}
	ready, err := nodeDiskStatusReady(ctx,
		lhClient.LonghornV1beta2().Nodes(longhornNamespace), nodeName)
	if err != nil {
		return fmt.Errorf("longhorn disk status: get node %s: %v", nodeName, err)
	}
	if !ready {
		return fmt.Errorf("longhorn disk status not yet recorded on node")
	}
	return nil
}
