// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"k8s.io/client-go/kubernetes"
)

func disabledNativeOrchestrationConfig() types.EdgeNodeClusterConfig {
	return types.EdgeNodeClusterConfig{
		ClusterType: types.ClusterTypeReplicatedStorage,
	}
}

func enabledNativeOrchestrationConfig() types.EdgeNodeClusterConfig {
	return types.EdgeNodeClusterConfig{
		ClusterType:                  types.ClusterTypeReplicatedStorage,
		EnableNativeK8SOrchestration: true,
	}
}

// statsLeaderZedkube returns a zedkube that reports isStatsLeader() == true,
// without going through real leader election.
func statsLeaderZedkube(clusterConfig types.EdgeNodeClusterConfig) *zedkube {
	z := &zedkube{statsElection: &leaderElection{}, clusterConfig: clusterConfig}
	z.statsElection.isLeader.Store(true)
	return z
}

func TestReconcileKubeAppNetworksNoNodeNameDoesNotAcquireClient(t *testing.T) {
	z := &zedkube{}
	clientRequested := false
	z.reconcileKubeAppNetworksWithClient(func() (*kubernetes.Clientset, error) {
		clientRequested = true
		return nil, nil
	})
	if clientRequested {
		t.Fatal("missing node identity acquired a Kubernetes client")
	}
}

func TestReconcileNINADDisabledDoesNotWrite(t *testing.T) {
	z := statsLeaderZedkube(disabledNativeOrchestrationConfig())
	writeCalled := false
	z.reconcileNINADWithWriter(types.NetworkInstanceStatus{
		NetworkInstanceConfig: types.NetworkInstanceConfig{
			Type:        types.NetworkInstanceTypeLocal,
			ClusterWide: true,
		},
	}, func(_, _ string) error {
		writeCalled = true
		return nil
	})
	if writeCalled {
		t.Fatal("disabled native orchestration wrote a per-NI NAD")
	}
}

func TestRemoveNINADDisabledDoesNotDelete(t *testing.T) {
	z := statsLeaderZedkube(disabledNativeOrchestrationConfig())
	deleteCalled := false
	z.removeNINADWithWriter(types.NetworkInstanceStatus{
		NetworkInstanceConfig: types.NetworkInstanceConfig{
			Type:        types.NetworkInstanceTypeSwitch,
			ClusterWide: true,
		},
	}, func(_ string) error {
		deleteCalled = true
		return nil
	})
	if deleteCalled {
		t.Fatal("disabled native orchestration deleted a per-NI NAD")
	}
}

func TestReconcileNINADNotClusterWideDoesNotWrite(t *testing.T) {
	z := statsLeaderZedkube(enabledNativeOrchestrationConfig())
	writeCalled := false
	z.reconcileNINADWithWriter(types.NetworkInstanceStatus{
		NetworkInstanceConfig: types.NetworkInstanceConfig{
			Type:        types.NetworkInstanceTypeLocal,
			ClusterWide: false,
		},
	}, func(_, _ string) error {
		writeCalled = true
		return nil
	})
	if writeCalled {
		t.Fatal("device-local (non cluster-wide) NI wrote a per-NI NAD")
	}
}

func TestReconcileNINADClusterWideWrites(t *testing.T) {
	z := statsLeaderZedkube(enabledNativeOrchestrationConfig())
	writeCalled := false
	z.reconcileNINADWithWriter(types.NetworkInstanceStatus{
		NetworkInstanceConfig: types.NetworkInstanceConfig{
			Type:        types.NetworkInstanceTypeLocal,
			ClusterWide: true,
		},
	}, func(_, _ string) error {
		writeCalled = true
		return nil
	})
	if !writeCalled {
		t.Fatal("cluster-wide NI did not write a per-NI NAD")
	}
}
