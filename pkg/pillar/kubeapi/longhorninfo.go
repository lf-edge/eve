// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"context"
	"fmt"
	"strings"

	lhv1beta2 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	"github.com/longhorn/longhorn-manager/k8s/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func LonghornReplicaList(ownerNodeName string, longhornVolName string) (*lhv1beta2.ReplicaList, error) {
	config, err := GetKubeConfig()
	if err != nil {
		return nil, err
	}

	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("LonghornReplicaList can't get versioned config: %v", err)
	}

	labelSelectors := []string{}
	if ownerNodeName != "" {
		labelSelectors = append(labelSelectors, "longhornnode="+ownerNodeName)
	}
	if longhornVolName != "" {
		labelSelectors = append(labelSelectors, "longhornvolume="+longhornVolName)
	}
	replicas, err := lhClient.LonghornV1beta2().Replicas("longhorn-system").List(context.Background(), metav1.ListOptions{
		LabelSelector: strings.Join(labelSelectors, ","),
	})
	if err != nil {
		return nil, fmt.Errorf("LonghornReplicaList labelSelector:%s can't get replicas: %v", strings.Join(labelSelectors, ","), err)
	}

	return replicas, nil
}
