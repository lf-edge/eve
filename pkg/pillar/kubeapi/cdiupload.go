// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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

// IsPVCUploadComplete reports whether the CDI image upload into the named PVC has
// finished. A non-nil error means the PVC could not be queried; callers should
// treat that as "not known complete". Used after a reboot that left a PVC behind
// to decide whether the upload still needs to be re-driven against it.
func IsPVCUploadComplete(pvcName string, log *base.LogObject) (bool, error) {
	clientset, err := GetClientSet()
	if err != nil {
		return false, fmt.Errorf("failed to get clientset: %v", err)
	}
	pvc, err := clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).
		Get(context.Background(), pvcName, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to get PVC %s: %v", pvcName, err)
	}
	return cdiUploadIsComplete(log, pvc), nil
}

// PVCAdoptionState is the outcome of checking whether an existing PVC can be
// adopted in place of downloading/creating a volume's content from scratch.
// Callers must not treat every non-ready state alike: only PVCStateAbsent is
// evidence that no PVC will ever answer this check, and it is the only
// verdict safe to act on as if the volume needs a real download.
type PVCAdoptionState int

const (
	// PVCStateUnknown means the check did not complete: the API server was
	// unreachable, or some other transient error occurred. This is not
	// evidence the PVC is gone -- callers should keep waiting and probe
	// again later.
	PVCStateUnknown PVCAdoptionState = iota
	// PVCStateReady means the PVC exists, is Bound, and its CDI image
	// upload has completed. Safe to adopt.
	PVCStateReady
	// PVCStateNotReady means the PVC exists but is not yet Bound, or its
	// upload has not finished. Keep waiting; this is still in progress,
	// not gone.
	PVCStateNotReady
	// PVCStateAbsent means Kubernetes confirmed no PVC by this name
	// exists (a real NotFound, not a transient error). This is the only
	// state that means the volume actually needs a download.
	PVCStateAbsent
)

// ProbePVCAdoption reports the current adoption state of a PVC with this
// exact name -- i.e. whether it is safe to adopt in place of waiting on (or
// re-driving) a source ContentTree download. See PVCAdoptionState for what
// each outcome means and how callers should react to it.
//
// This is the cluster-failover fast path: VolumeStatus.GetPVCName() embeds the
// volume's generation counter in the PVC name itself, so a match here can only
// be the PVC for this exact generation -- a stale or newer generation simply
// will not be found under this name, and this function does not need (and does
// not do) any separate generation comparison.
func ProbePVCAdoption(pvcName string, log *base.LogObject) PVCAdoptionState {
	clientset, err := GetClientSet()
	if err != nil {
		log.Functionf("ProbePVCAdoption: get clientset: %v", err)
		return PVCStateUnknown
	}
	ctx, cancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer cancel()
	pvc, err := clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).
		Get(ctx, pvcName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return PVCStateAbsent
		}
		log.Functionf("ProbePVCAdoption: get PVC %s: %v", pvcName, err)
		return PVCStateUnknown
	}
	if pvc.Status.Phase != corev1.ClaimBound {
		log.Functionf("ProbePVCAdoption: pvc %s phase is %s, not Bound", pvcName, pvc.Status.Phase)
		return PVCStateNotReady
	}
	if cdiUploadIsComplete(log, pvc) {
		return PVCStateReady
	}
	return PVCStateNotReady
}
