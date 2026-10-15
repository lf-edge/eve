// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import "testing"

// TestIsDecisionNodeFollowsAppOpLease covers EV-2923: the failover decision
// must follow the eve-app-op lease, not the stats lease, which can stay with
// a dead node for its whole 300s lease duration.
func TestIsDecisionNodeFollowsAppOpLease(t *testing.T) {
	tests := []struct {
		name        string
		statsLeader bool
		appOpLeader bool
		want        bool
	}{
		{name: "neither lease", want: false},
		{name: "stats lease only", statsLeader: true, want: false},
		{name: "app-op lease only", appOpLeader: true, want: true},
		{name: "both leases", statsLeader: true, appOpLeader: true, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := &zedkube{statsElection: &leaderElection{}, appOpElection: &leaderElection{}}
			z.statsElection.isLeader.Store(tt.statsLeader)
			z.appOpElection.isLeader.Store(tt.appOpLeader)
			if got := z.isDecisionNode(); got != tt.want {
				t.Errorf("isDecisionNode() = %v, want %v", got, tt.want)
			}
		})
	}
}
