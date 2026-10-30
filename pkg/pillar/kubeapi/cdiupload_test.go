// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestPVCUploadState checks the annotation combinations a PVC goes through
// from creation by CreatePVC or virtctl to a finished CDI upload.
func TestPVCUploadState(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        PVCUploadState
	}{
		{"blank PVC", nil, PVCNoUpload},
		{"created by virtctl, upload pod not started",
			map[string]string{cdiUploadTargetAnnotation: ""}, PVCUploadIncomplete},
		{"upload pod failed", map[string]string{
			cdiUploadTargetAnnotation: "",
			cdiPodPhaseAnnotation:     "Failed",
		}, PVCUploadIncomplete},
		{"upload pod running", map[string]string{
			cdiUploadTargetAnnotation:                           "",
			cdiPodPhaseAnnotation:                               "Running",
			"cdi.kubevirt.io/storage.condition.running.message": "",
		}, PVCUploadIncomplete},
		{"upload complete", map[string]string{
			cdiUploadTargetAnnotation:                           "",
			cdiPodPhaseAnnotation:                               "Succeeded",
			"cdi.kubevirt.io/storage.condition.running.message": "Upload Complete",
		}, PVCUploadComplete},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
				Name:        "pvc",
				Annotations: tc.annotations,
			}}
			if got := pvcUploadState(testLog(), pvc); got != tc.want {
				t.Errorf("pvcUploadState = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestPVCUsers checks that only live, non-CDI pods mounting the PVC count as
// its users.
func TestPVCUsers(t *testing.T) {
	pod := func(name string, phase corev1.PodPhase, labels map[string]string, claims ...string) corev1.Pod {
		p := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
			Status:     corev1.PodStatus{Phase: phase},
		}
		for _, c := range claims {
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: c},
				},
			})
		}
		return p
	}
	pods := []corev1.Pod{
		pod("virt-launcher-app", corev1.PodRunning, nil, "other", "pvc"),
		pod("cdi-upload-pvc", corev1.PodRunning, map[string]string{"app": cdiAppLabelValue}, "pvc"),
		pod("old-launcher", corev1.PodFailed, nil, "pvc"),
		pod("done-launcher", corev1.PodSucceeded, nil, "pvc"),
		pod("pending-launcher", corev1.PodPending, nil, "pvc"),
		pod("unrelated", corev1.PodRunning, nil, "other"),
		pod("no-volumes", corev1.PodRunning, nil),
	}
	got := pvcUsers(pods, "pvc")
	want := []string{"virt-launcher-app", "pending-launcher"}
	if !slices.Equal(got, want) {
		t.Errorf("pvcUsers = %v, want %v", got, want)
	}
}
