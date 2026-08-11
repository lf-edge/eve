// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcreconciler

import (
	"net"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func TestClusterStatusChanged(t *testing.T) {
	prefix := &net.IPNet{
		IP:   net.ParseIP("10.244.244.2"),
		Mask: net.CIDRMask(24, 32),
	}
	base := types.EdgeNodeClusterStatus{
		ClusterInterface: "eth0",
		ClusterIPPrefix:  prefix,
		BootstrapNode:    true,
	}
	tests := []struct {
		name    string
		mod     func(*types.EdgeNodeClusterStatus)
		changed bool
	}{
		{"unchanged", func(*types.EdgeNodeClusterStatus) {}, false},
		{"readiness is not networking", func(s *types.EdgeNodeClusterStatus) {
			s.ClusterIPIsReady = true
		}, false},
		{"cluster interface", func(s *types.EdgeNodeClusterStatus) {
			s.ClusterInterface = "eth1"
		}, true},
		{"witness added", func(s *types.EdgeNodeClusterStatus) {
			s.WitnessIP = net.ParseIP("10.244.244.5")
		}, true},
		{"seed moved away", func(s *types.EdgeNodeClusterStatus) {
			s.BootstrapNode = false
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &LinuxDpcReconciler{}
			r.lastArgs.ClusterStatus = base
			newStatus := base
			tc.mod(&newStatus)
			if got := r.clusterStatusChanged(newStatus); got != tc.changed {
				t.Fatalf("clusterStatusChanged = %v, want %v", got, tc.changed)
			}
		})
	}
	t.Run("witness moved", func(t *testing.T) {
		r := &LinuxDpcReconciler{}
		r.lastArgs.ClusterStatus = base
		r.lastArgs.ClusterStatus.WitnessIP = net.ParseIP("10.244.244.5")
		newStatus := r.lastArgs.ClusterStatus
		newStatus.WitnessIP = net.ParseIP("10.244.244.6")
		if !r.clusterStatusChanged(newStatus) {
			t.Fatal("moving the witness IP must trigger a reconcile")
		}
	})
}
