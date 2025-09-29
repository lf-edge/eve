// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"time"

	corev1 "k8s.io/api/core/v1"
)

func getPodTerminatingTime(pod corev1.Pod) time.Duration {
	if pod.ObjectMeta.DeletionTimestamp == nil {
		return 0
	}
	return time.Since(pod.ObjectMeta.DeletionTimestamp.Time)
}

// If DeletionTimestamp is not null, the pod is terminating.
func isPodTerminating(pod corev1.Pod) bool {
	return pod.ObjectMeta.DeletionTimestamp != nil
}
