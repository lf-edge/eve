// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"testing"

	eveconfig "github.com/lf-edge/eve-api/go/config"
)

func TestReusedClusterIdentity(t *testing.T) {
	const (
		cluster      = "6b2c7d3e-0f4a-4b5c-9d8e-1a2b3c4d5e6f"
		otherCluster = "0e9a8b7c-6d5e-4f3a-8b2c-1d0e9f8a7b6c"
	)
	dev := func(clusterID, token string) *deviceState {
		config := &EdgeDeviceConfig{EdgeDevConfig: &eveconfig.EdgeDevConfig{}}
		if clusterID != "" {
			config.Cluster = &eveconfig.EdgeNodeCluster{ClusterId: clusterID}
			config.clusterToken = token
		}
		return &deviceState{config: config}
	}
	twoNodes := []ClusterNode{{DevName: "edge-dev1"}, {DevName: "edge-dev2"}}
	threeNodes := append(twoNodes, ClusterNode{DevName: "edge-dev3"})
	tests := []struct {
		name    string
		nodes   []ClusterNode
		devices map[string]*deviceState
		wantOK  bool
	}{
		{"nodes form the cluster", twoNodes, map[string]*deviceState{
			"edge-dev1": dev(cluster, "token"),
			"edge-dev2": dev(cluster, "token"),
		}, true},
		{"fresh devices", twoNodes, map[string]*deviceState{
			"edge-dev1": {}, "edge-dev2": {},
		}, false},
		{"no node in a cluster", twoNodes, map[string]*deviceState{
			"edge-dev1": dev("", ""),
			"edge-dev2": dev("", ""),
		}, false},
		{"node taken out of the cluster rejoins", threeNodes, map[string]*deviceState{
			"edge-dev1": dev(cluster, "token"),
			"edge-dev2": dev(cluster, "token"),
			"edge-dev3": dev("", ""),
		}, true},
		{"member without a recorded token", twoNodes, map[string]*deviceState{
			"edge-dev1": dev(cluster, "token"),
			"edge-dev2": dev(cluster, ""),
		}, false},
		{"nodes in different clusters", twoNodes, map[string]*deviceState{
			"edge-dev1": dev(cluster, "token"),
			"edge-dev2": dev(otherCluster, "token"),
		}, false},
		{"different tokens", twoNodes, map[string]*deviceState{
			"edge-dev1": dev(cluster, "token"),
			"edge-dev2": dev(cluster, "other-token"),
		}, false},
		{"another device is in the cluster too", twoNodes, map[string]*deviceState{
			"edge-dev1": dev(cluster, "token"),
			"edge-dev2": dev(cluster, "token"),
			"edge-dev3": dev(cluster, "token"),
		}, false},
		{"another device is in another cluster", twoNodes, map[string]*deviceState{
			"edge-dev1": dev(cluster, "token"),
			"edge-dev2": dev(cluster, "token"),
			"edge-dev3": dev(otherCluster, "token"),
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			th := &TestHarness{devices: tt.devices}
			id, token, ok := th.reusedClusterIdentity(tt.nodes)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && (id.String() != cluster || token != "token") {
				t.Fatalf("got cluster %s with token %q, want %s with %q",
					id, token, cluster, "token")
			}
		})
	}
}
