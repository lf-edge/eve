// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"testing"
)

// TestComponentMarkerPaths spot-checks the marker constant values.
// The filenames are an external contract (debug tooling greps for
// these names), so a careless edit must show up as a test failure
// rather than a quiet user-visible regression.
func TestComponentMarkerPaths(t *testing.T) {
	cases := map[Marker]string{
		AllComponentsInitialized:     "/var/lib/all_components_initialized",
		K3sInstalledUnpacked:         "/var/lib/k3s_installed_unpacked",
		MultusInitialized:            "/var/lib/multus_initialized",
		KubevirtInitialized:          "/var/lib/kubevirt_initialized",
		KubevirtFeatureGatesMigrated: "/var/lib/kubevirt-feature-gates-migrated",
		LonghornInitialized:          "/var/lib/longhorn_initialized",
		DebugUserInitialized:         "/var/lib/debuguser-initialized",
		NodeLabelsInitialized:        "/var/lib/node-labels-initialized",
		EdgeNodeClusterMode:          "/var/lib/edge-node-cluster-mode",
		NativeKubernetesMode:         "/var/lib/native-kubernetes-mode",
		ConvertToSingleNode:          "/var/lib/convert-to-single-node",
		TransitionToCluster:          "/var/lib/transition-to-cluster",
		RequestRetouchMultus:         "/var/lib/request-retouch-multus",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("marker path = %q, want %q", string(got), want)
		}
	}
}
