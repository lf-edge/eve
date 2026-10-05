// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package clustermode

import (
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
)

// TestExpectedMasters pins how many control-plane nodes count as a whole
// cluster, which is what tells a partial view from a complete one.
//
// A witness holds an etcd vote but runs no kubelet, so it has no Node
// object and never appears in the control-plane list. Expecting three
// there would mean the rank is never recorded and the two real nodes
// race their etcd joins on every simultaneous power-up.
func TestExpectedMasters(t *testing.T) {
	cases := []struct {
		name   string
		status *k3s.ClusterStatus
		want   int
	}{
		{"no status", nil, replicatedStorageMinMasters},
		{"no witness configured", &k3s.ClusterStatus{}, replicatedStorageMinMasters},
		{"witness configured", &k3s.ClusterStatus{WitnessIP: "10.244.244.5"},
			witnessClusterMinMasters},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := expectedMasters(c.status); got != c.want {
				t.Errorf("expectedMasters() = %d, want %d", got, c.want)
			}
		})
	}
}

// TestWitnessClusterIsSmaller guards the relationship rather than the
// numbers: a witness cluster must expect fewer masters than a
// three-master one, or the guard never passes.
func TestWitnessClusterIsSmaller(t *testing.T) {
	if witnessClusterMinMasters >= replicatedStorageMinMasters {
		t.Errorf("witness cluster expects %d masters, not fewer than %d",
			witnessClusterMinMasters, replicatedStorageMinMasters)
	}
}
