// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestCopyKubeAppIdentityToStatus catches a missing copy or pointer aliasing in
// doCopyAppNetworkConfigToStatus. zedkube consumes the status asynchronously,
// so the published identity must be an independent snapshot of the config.
func TestCopyKubeAppIdentityToStatus(t *testing.T) {
	config := types.AppNetworkConfig{
		DisplayName: "local-switch-ni-dp",
		KubeApp: &types.KubeAppInfo{
			Namespace: "default",
			OwnerName: "native-ni-server",
		},
	}
	status := types.AppNetworkStatus{}

	(&zedrouter{}).doCopyAppNetworkConfigToStatus(config, &status)
	config.KubeApp.OwnerName = "mutated-after-copy"

	if status.KubeApp == nil {
		t.Fatal("KubeApp identity was not copied into AppNetworkStatus")
	}
	if status.KubeApp.Namespace != "default" || status.KubeApp.OwnerName != "native-ni-server" {
		t.Fatalf("copied KubeApp identity changed through config alias: %+v", status.KubeApp)
	}
	if status.DisplayName != "local-switch-ni-dp" {
		t.Fatalf("copied display name is %q, want %q",
			status.DisplayName, "local-switch-ni-dp")
	}
}
