// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"context"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// waitForPVCUploadComplete: Loop until PVC upload annotations show upload complete
// At this time the only caller of this is kubeapi.RolloutDiskToPVC() which runs in the
// volumecreate worker context.  This does currently wait up to 5 minutes
// but does not need to bump a watchdog as the worker does not have one.
func waitForPVCUploadComplete(ctx context.Context, pvcName string, log *base.LogObject) error {
	clientset, err := GetClientSet()
	if err != nil {
		log.Errorf("waitForPVCUploadComplete failed to get clientset err %v", err)
		return err
	}

	i := 100
	for i > 0 {
		i--

		select {
		case <-ctx.Done():
			return fmt.Errorf("waitForPVCUploadComplete: context done")
		default:
			time.Sleep(5 * time.Second)
		}

		pvc, err := clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).
			Get(context.Background(), pvcName, metav1.GetOptions{})
		if err != nil {
			log.Errorf("waitForPVCUploadComplete failed to get pvc info err %v", err)
			continue
		}
		if cdiUploadIsComplete(log, pvc) {
			return nil
		}
	}

	return fmt.Errorf("waitForPVCUploadComplete: time expired")
}

func cdiUploadIsComplete(log *base.LogObject, pvc *corev1.PersistentVolumeClaim) bool {
	annotationKey := "cdi.kubevirt.io/storage.pod.phase"
	annotationExpectedVal := "Succeeded"
	foundVal, ok := pvc.Annotations[annotationKey]
	if !ok {
		log.Errorf("pvc %s annotation %s is missing", pvc.Name, annotationKey)
		return false
	}
	if foundVal != annotationExpectedVal {
		log.Warnf("pvc %s annotation %s is %s, waiting for %s", pvc.Name, annotationKey, foundVal, annotationExpectedVal)
		return false
	}

	annotationKey = "cdi.kubevirt.io/storage.condition.running.message"
	annotationExpectedVal = "Upload Complete"
	foundVal, ok = pvc.Annotations[annotationKey]
	if !ok {
		log.Errorf("pvc %s annotation %s is missing", pvc.Name, annotationKey)
		return false
	}
	if foundVal != annotationExpectedVal {
		log.Warnf("pvc %s annotation %s is %s, waiting for %s", pvc.Name, annotationKey, foundVal, annotationExpectedVal)
		return false
	}
	return true
}
