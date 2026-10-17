// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
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
