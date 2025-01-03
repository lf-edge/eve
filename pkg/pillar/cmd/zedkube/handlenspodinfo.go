// Copyright (c) 2024-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"context"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func getAllNs() ([]string, error) {
	var nsNameList []string
	clientset, err := kubeapi.GetClientSet()
	if err != nil {
		return nsNameList, err
	}
	nsList, err := clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nsNameList, err
	}
	for _, ns := range nsList.Items {
		nsNameList = append(nsNameList, ns.ObjectMeta.Name)
	}
	return nsNameList, nil
}

func getPodNsInfo(ns string) (types.KubePodNameSpaceInfo, error) {
	kpnsi := types.KubePodNameSpaceInfo{Name: ns}

	clientset, err := kubeapi.GetClientSet()
	if err != nil {
		return kpnsi, err
	}
	podList, err := clientset.CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return kpnsi, err
	}
	kpnsi.PodCount = uint32(len(podList.Items))
	for _, pod := range podList.Items {
		switch pod.Status.Phase {
		case corev1.PodRunning:
			kpnsi.PodRunningCount++
		case corev1.PodPending:
			kpnsi.PodPendingCount++
		case corev1.PodFailed:
			kpnsi.PodFailedCount++
		case corev1.PodSucceeded:
			kpnsi.PodSucceededCount++
		}
	}
	return kpnsi, nil
}
