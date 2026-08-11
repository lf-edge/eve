// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package clustermode

import (
	"reflect"
	"testing"
)

// TestStaleLeases pins the rule that decides which apiserver
// advertisements survive: membership, not subnet. The two events that
// strand a lease strand it on opposite sides of the cluster network, so
// a subnet test catches only one of them.
func TestStaleLeases(t *testing.T) {
	const p = masterLeasesPrefix
	cases := []struct {
		name    string
		leases  []string
		members map[string]bool
		want    []string
	}{
		{
			name:    "a live member keeps its lease",
			leases:  []string{p + "10.244.244.2"},
			members: map[string]bool{"10.244.244.2": true},
			want:    nil,
		},
		{
			name:   "the address left behind by single-to-cluster goes",
			leases: []string{p + "192.168.1.10", p + "10.244.244.2"},
			// Outside the cluster subnet, which the old rule also caught.
			members: map[string]bool{"10.244.244.2": true},
			want:    []string{p + "192.168.1.10"},
		},
		{
			name:   "the member a reset erased goes too",
			leases: []string{p + "10.244.244.2", p + "10.244.244.3"},
			// Inside the cluster subnet, which the old rule skipped: this
			// is the dead seed after --cluster-reset reduced membership.
			members: map[string]bool{"10.244.244.3": true},
			want:    []string{p + "10.244.244.2"},
		},
		{
			name:    "a member that is merely down is not stale",
			leases:  []string{p + "10.244.244.2"},
			members: map[string]bool{"10.244.244.2": true, "10.244.244.3": true},
			want:    nil,
		},
		{
			name:    "an unparsable key is left for a human",
			leases:  []string{p + "not-an-ip"},
			members: map[string]bool{"10.244.244.3": true},
			want:    nil,
		},
		{
			name:    "no members reported removes nothing by accident",
			leases:  []string{p + "10.244.244.2"},
			members: map[string]bool{},
			want:    []string{p + "10.244.244.2"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := staleLeases(c.leases, c.members)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("staleLeases() = %v, want %v", got, c.want)
			}
		})
	}
}
