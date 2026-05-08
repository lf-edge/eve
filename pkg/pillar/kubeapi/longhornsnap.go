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
	// Only Cron is patched; Retain, Concurrency, Groups, and Task are left as-is.
	// EVE does not re-assert those fields on update: the cron schedule is the only
	// operator-controlled variable, and preserving other fields avoids overwriting
	// any manual tuning an operator may have applied directly to the job.
	existing.Spec.Cron = cron
	if _, err := jobs.Update(lhCtx, existing, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("SetLonghornRecurringSnapshot: update: %v", err)
	}
	return true, nil
}
