// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"fmt"

	"github.com/longhorn/longhorn-manager/k8s/pkg/client/clientset/versioned"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// longhornNodeDrainPolicySettingName is the name of the Longhorn Setting object for node drain policy.
const longhornNodeDrainPolicySettingName = "node-drain-policy"

// SetLonghornNodeDrainPolicy sets the Longhorn cluster-wide node-drain-policy setting.
// Returns (true, nil) when successfully applied; (false, nil) when Longhorn is not yet available.
func SetLonghornNodeDrainPolicy(policy string) (bool, error) {
	apiExists, err := longhornAPIExists()
	if !apiExists && err == nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	config, err := GetKubeConfig()
	if err != nil {
		return false, fmt.Errorf("SetLonghornNodeDrainPolicy: kubeconfig: %v", err)
	}
	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return false, fmt.Errorf("SetLonghornNodeDrainPolicy: versioned client: %v", err)
	}
	lhCtx, lhCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer lhCancel()
	settings := lhClient.LonghornV1beta2().Settings(longhornNamespace)
	existing, err := settings.Get(lhCtx, longhornNodeDrainPolicySettingName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("SetLonghornNodeDrainPolicy: get: %v", err)
	}
	if existing.Value == policy {
		return true, nil
	}
	existing.Value = policy
	if _, err := settings.Update(lhCtx, existing, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("SetLonghornNodeDrainPolicy: update: %v", err)
	}
	return true, nil
}
