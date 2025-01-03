// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"context"
	"fmt"
	"time"

	"github.com/longhorn/longhorn-manager/k8s/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LonghornVolumeSizeDetails returns the provisionedBytes and allocatedBytes size values for a longhorn volume
func LonghornVolumeSizeDetails(longhornVolumeName string) (provisionedBytes uint64, allocatedBytes uint64, err error) {
	config, err := GetKubeConfig()
	if err != nil {
		return 0, 0, fmt.Errorf("LonghornVolumeSizeDetails can't get kubeconfig %v", err)
	}

	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return 0, 0, fmt.Errorf("LonghornVolumeSizeDetails can't get versioned config: %v", err)
	}

	// Don't allow a k8s api timeout keep us waiting forever, set this one explicitly as its used in metrics path
	shortContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lhVol, err := lhClient.LonghornV1beta2().Volumes("longhorn-system").Get(shortContext, longhornVolumeName, metav1.GetOptions{})
	if err != nil || lhVol == nil {
		return 0, 0, fmt.Errorf("LonghornVolumeSizeDetails can't get lh vol err:%v", err)
	}

	return uint64(lhVol.Spec.Size), uint64(lhVol.Status.ActualSize), nil
}
