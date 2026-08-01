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

// instanceManagerLister is the subset of the generated Longhorn client this
// file needs, kept narrow so the state logic below can be exercised without a
// live API server.
type instanceManagerLister interface {
	List(ctx context.Context, opts metav1.ListOptions) (*lhv1beta2.InstanceManagerList, error)
}

// instanceManagerRunningOnNode reports whether nodeName has an InstanceManager
// in the running state.
//
// Longhorn runs a volume's engine and replica processes inside the
// instance-manager pod, so the node cannot serve any volume until one is
// running. The pod is owned by an InstanceManager CR rather than a DaemonSet,
// which is why the daemonset sweep in checkLonghornReady cannot observe it.
//
// InstanceManager.Spec.NodeID carries the Kubernetes node name, the same value
// checkLonghornReady uses to select per-node DaemonSet pods.
func instanceManagerRunningOnNode(ctx context.Context, lister instanceManagerLister,
	nodeName string) (bool, error) {
	ims, err := lister.List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	for _, im := range ims.Items {
		if im.Spec.NodeID != nodeName {
			continue
		}
		if im.Status.CurrentState == lhv1beta2.InstanceManagerStateRunning {
			return true, nil
		}
	}
	return false, nil
}

// instanceManagerReady is the gate checkLonghornReady applies once the Longhorn
// DaemonSets look healthy. It is a variable so that tests driving
// checkLonghornReady with a fake clientset can substitute it: the real
// implementation builds a Longhorn client from the on-device kubeconfig, which
// a fake clientset cannot supply.
var instanceManagerReady = checkLonghornInstanceManagerReady

// checkLonghornInstanceManagerReady fails while nodeName has no running
// InstanceManager.
//
// Longhorn creates the CR during node setup rather than on first volume
// request, so waiting on it cannot deadlock against a volume whose own creation
// is gated on storage readiness.
func checkLonghornInstanceManagerReady(ctx context.Context, nodeName string) error {
	config, err := GetKubeConfig()
	if err != nil {
		return fmt.Errorf("longhorn instance-manager: kubeconfig: %v", err)
	}
	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("longhorn instance-manager: versioned client: %v", err)
	}
	running, err := instanceManagerRunningOnNode(ctx,
		lhClient.LonghornV1beta2().InstanceManagers(longhornNamespace), nodeName)
	if err != nil {
		return fmt.Errorf("longhorn instance-manager: list: %v", err)
	}
	if !running {
		return fmt.Errorf("longhorn instance-manager not running on node")
	}
	return nil
}
