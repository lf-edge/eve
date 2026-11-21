// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"fmt"

	lhv1beta2 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	"github.com/longhorn/longhorn-manager/k8s/pkg/client/clientset/versioned"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
)

// eveRecurringJobName is the cluster-scoped name of the Longhorn RecurringJob EVE manages.
// This name appears in kubectl diagnostics: kubectl -n longhorn-system get recurringjob default-eve-kube-app-snapshot
const eveRecurringJobName = "default-eve-kube-app-snapshot"

// SetLonghornRecurringSnapshot creates or updates the EVE recurring snapshot RecurringJob
// using the provided cron expression. An empty cron string deletes the job if it exists.
// Returns (true, nil) when the desired state has been successfully applied.
// Returns (false, nil) when Longhorn is not yet available; callers should retry.
func SetLonghornRecurringSnapshot(cron string) (bool, error) {
	apiExists, err := longhornAPIExists()
	if !apiExists && err == nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	config, err := GetKubeConfig()
	if err != nil {
		return false, fmt.Errorf("SetLonghornRecurringSnapshot: kubeconfig: %v", err)
	}
	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return false, fmt.Errorf("SetLonghornRecurringSnapshot: versioned client: %v", err)
	}

	lhCtx, lhCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer lhCancel()

	jobs := lhClient.LonghornV1beta2().RecurringJobs(longhornNamespace)
	existing, err := jobs.Get(lhCtx, eveRecurringJobName, metav1.GetOptions{})
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return false, fmt.Errorf("SetLonghornRecurringSnapshot: get: %v", err)
	}

	if cron == "" {
		if notFound {
			return true, nil
		}
		if err := jobs.Delete(lhCtx, eveRecurringJobName, metav1.DeleteOptions{}); err != nil {
			return false, fmt.Errorf("SetLonghornRecurringSnapshot: delete: %v", err)
		}
		return true, nil
	}

	if notFound {
		job := &lhv1beta2.RecurringJob{
			ObjectMeta: metav1.ObjectMeta{
				Name:      eveRecurringJobName,
				Namespace: longhornNamespace,
			},
			Spec: lhv1beta2.RecurringJobSpec{
				Task:        lhv1beta2.RecurringJobTypeSnapshot,
				Groups:      []string{"default"},
				Cron:        cron,
				Retain:      3,
				Concurrency: 1,
			},
		}
		if _, err := jobs.Create(lhCtx, job, metav1.CreateOptions{}); err != nil {
			return false, fmt.Errorf("SetLonghornRecurringSnapshot: create: %v", err)
		}
		return true, nil
	}

	if existing.Spec.Cron == cron {
		return true, nil
	}
	// Only Cron is patched; every other field is left as-is. The cron schedule
	// is the only operator-controlled variable, and a patch keeps any manual
	// tuning applied directly to the job, including fields newer than pillar's
	// Longhorn types.
	patch, err := lhSpecMergePatch(map[string]interface{}{"cron": cron})
	if err != nil {
		return false, fmt.Errorf("SetLonghornRecurringSnapshot: build patch: %v", err)
	}
	if _, err := jobs.Patch(lhCtx, eveRecurringJobName, ktypes.MergePatchType,
		patch, metav1.PatchOptions{}); err != nil {
		return false, fmt.Errorf("SetLonghornRecurringSnapshot: patch: %v", err)
	}
	return true, nil
}
