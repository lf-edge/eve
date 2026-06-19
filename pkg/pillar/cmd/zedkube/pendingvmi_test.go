// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	virtv1 "kubevirt.io/api/core/v1"
)

func TestVMIPhaseIsPreRunning(t *testing.T) {
	tests := []struct {
		phase virtv1.VirtualMachineInstancePhase
		want  bool
	}{
		{virtv1.Pending, true},
		{virtv1.Scheduling, true},
		{virtv1.Scheduled, false},
		{virtv1.Running, false},
		{virtv1.Succeeded, false},
		{virtv1.Failed, false},
		{virtv1.Unknown, false},
	}
	for _, tc := range tests {
		t.Run(string(tc.phase), func(t *testing.T) {
			assert.Equal(t, tc.want, vmiPhaseIsPreRunning(tc.phase))
		})
	}
}

func TestVirtLauncherPodIsActiveOnNode(t *testing.T) {
	const node = "andrew-cherry"
	const appKubeName = "enc-a2-84c66"

	mkPod := func(name, specNode string, phase corev1.PodPhase) corev1.Pod {
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       corev1.PodSpec{NodeName: specNode},
			Status:     corev1.PodStatus{Phase: phase},
		}
	}
	launcherName := "virt-launcher-" + appKubeName + "-x"

	tests := []struct {
		name string
		pods []corev1.Pod
		want bool
	}{
		{
			name: "Pending phase with NodeName set (Init:0/1 on this node)",
			pods: []corev1.Pod{mkPod(launcherName, node, corev1.PodPending)},
			want: true,
		},
		{
			name: "Pending phase with NodeName empty (unscheduled)",
			pods: []corev1.Pod{mkPod(launcherName, "", corev1.PodPending)},
			want: false,
		},
		{
			name: "Running phase on this node",
			pods: []corev1.Pod{mkPod(launcherName, node, corev1.PodRunning)},
			want: true,
		},
		{
			name: "Failed phase on this node",
			pods: []corev1.Pod{mkPod(launcherName, node, corev1.PodFailed)},
			want: true,
		},
		{
			name: "Running phase on a different node",
			pods: []corev1.Pod{mkPod(launcherName, "other-node", corev1.PodRunning)},
			want: false,
		},
		{
			name: "Terminating pod on this node",
			pods: []corev1.Pod{func() corev1.Pod {
				p := mkPod(launcherName, node, corev1.PodRunning)
				now := metav1.Now()
				p.DeletionTimestamp = &now
				return p
			}()},
			want: false,
		},
		{
			name: "Pod name does not match app prefix",
			pods: []corev1.Pod{mkPod("virt-launcher-other-app-x", node, corev1.PodRunning)},
			want: false,
		},
		{
			name: "No pods",
			pods: nil,
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, virtLauncherPodIsActiveOnNode(tc.pods, appKubeName, node))
		})
	}
}
