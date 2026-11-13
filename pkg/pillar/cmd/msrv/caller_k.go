// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package msrv

import (
	"context"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/wait"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// addKubePodIdentity fills in the running pod of the workload ownerName on
// this node. zedkube rejects NI attachments of multi-replica ReplicaSets, so
// a workload has at most one pod per node.
func (msrv *Msrv) addKubePodIdentity(ctx context.Context, id *CallerIdentity,
	ownerName string) error {
	enInfoObj, err := msrv.subEdgeNodeInfo.Get("global")
	if err != nil {
		return fmt.Errorf("node name unknown: %w", err)
	}
	nodeName := wait.NodeNameFromDeviceName(enInfoObj.(types.EdgeNodeInfo).DeviceName)
	cs, err := kubeapi.GetClientSet()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pods, err := cs.CoreV1().Pods(id.Namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return err
	}
	var match *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase != corev1.PodRunning ||
			!base.KubePodMatchesOwner(pod.Name, ownerName) {
			continue
		}
		if match != nil {
			return fmt.Errorf("more than one running pod (%s, %s)", match.Name, pod.Name)
		}
		match = pod
	}
	if match == nil {
		return fmt.Errorf("no running pod on node %s", nodeName)
	}
	id.PodName = match.Name
	id.PodUID = string(match.UID)
	id.ServiceAccount = match.Spec.ServiceAccountName
	id.NodeName = nodeName
	for _, cs := range match.Status.ContainerStatuses {
		id.Containers = append(id.Containers, ContainerIdentity{
			Name: cs.Name, Image: cs.Image, ImageID: cs.ImageID})
	}
	return nil
}
