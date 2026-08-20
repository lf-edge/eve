// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func controllerRef(apiVersion, kind, name string) metav1.OwnerReference {
	controller := true
	return metav1.OwnerReference{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		Controller: &controller,
	}
}

func TestKubeAppNamesUseDeploymentForDisplayOnly(t *testing.T) {
	replicaSetName := "switch-ni-test-7f6c4d84f5"
	replicaSets := []appsv1.ReplicaSet{{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "default",
			Name:            replicaSetName,
			OwnerReferences: []metav1.OwnerReference{controllerRef("apps/v1", "Deployment", "switch-ni-test")},
		},
	}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace:       "default",
		Name:            replicaSetName + "-abcde",
		OwnerReferences: []metav1.OwnerReference{controllerRef("apps/v1", "ReplicaSet", replicaSetName)},
	}}

	ownerName, displayName := kubeAppNames(pod, deploymentNamesByReplicaSet(replicaSets))
	if ownerName != replicaSetName {
		t.Fatalf("owner name changed to %q, want ReplicaSet %q", ownerName, replicaSetName)
	}
	if displayName != "switch-ni-test" {
		t.Fatalf("display name is %q, want Deployment name", displayName)
	}
}

func TestKubeAppNamesKeepDirectReplicaSetName(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace:       "default",
		Name:            "direct-rs-abcde",
		OwnerReferences: []metav1.OwnerReference{controllerRef("apps/v1", "ReplicaSet", "direct-rs")},
	}}

	ownerName, displayName := kubeAppNames(pod, nil)
	if ownerName != "direct-rs" || displayName != "direct-rs" {
		t.Fatalf("got owner/display %q/%q, want direct-rs/direct-rs", ownerName, displayName)
	}
}

func TestKubeAppNamesKeepBarePodName(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "bare-local-ni-test",
	}}

	ownerName, displayName := kubeAppNames(pod, nil)
	if ownerName != pod.Name || displayName != pod.Name {
		t.Fatalf("got owner/display %q/%q, want Pod name %q", ownerName, displayName, pod.Name)
	}
}

func TestNIUUIDForNADStatusesRequiresApplicableClusterWideNI(t *testing.T) {
	clusterLocalID := uuid.Must(uuid.NewV4())
	clusterSwitchID := uuid.Must(uuid.NewV4())
	deviceLocalID := uuid.Must(uuid.NewV4())
	clusterCloudID := uuid.Must(uuid.NewV4())
	statuses := []types.NetworkInstanceStatus{
		{NetworkInstanceConfig: types.NetworkInstanceConfig{
			UUIDandVersion: types.UUIDandVersion{UUID: clusterLocalID},
			DisplayName:    "cluster-local", Type: types.NetworkInstanceTypeLocal,
			ClusterWide: true,
		}},
		{NetworkInstanceConfig: types.NetworkInstanceConfig{
			UUIDandVersion: types.UUIDandVersion{UUID: clusterSwitchID},
			DisplayName:    "cluster-switch", Type: types.NetworkInstanceTypeSwitch,
			ClusterWide: true,
		}},
		{NetworkInstanceConfig: types.NetworkInstanceConfig{
			UUIDandVersion: types.UUIDandVersion{UUID: deviceLocalID},
			DisplayName:    "device-local", Type: types.NetworkInstanceTypeLocal,
			ClusterWide: false,
		}},
		{NetworkInstanceConfig: types.NetworkInstanceConfig{
			UUIDandVersion: types.UUIDandVersion{UUID: clusterCloudID},
			DisplayName:    "cluster-cloud", Type: types.NetworkInstanceTypeCloud,
			ClusterWide: true,
		}},
	}

	tests := []struct {
		name      string
		namespace string
		nadName   string
		wantUUID  uuid.UUID
		wantOK    bool
	}{
		{"cluster-wide local", kubeapi.EVEKubeNameSpace, "ni-cluster-local", clusterLocalID, true},
		{"cluster-wide Switch", kubeapi.EVEKubeNameSpace, "ni-cluster-switch", clusterSwitchID, true},
		{"device-local rejected", kubeapi.EVEKubeNameSpace, "ni-device-local", uuid.UUID{}, false},
		{"unsupported type rejected", kubeapi.EVEKubeNameSpace, "ni-cluster-cloud", uuid.UUID{}, false},
		{"wrong namespace rejected", "default", "ni-cluster-local", uuid.UUID{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := niUUIDForNADStatuses(tc.namespace, tc.nadName, statuses)
			if ok != tc.wantOK || got != tc.wantUUID {
				t.Fatalf("got UUID/ok %s/%v, want %s/%v", got, ok, tc.wantUUID, tc.wantOK)
			}
		})
	}
}
