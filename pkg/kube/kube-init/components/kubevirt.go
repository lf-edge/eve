// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// standardFeatureGates is the EVE-expected set of KubeVirt feature
// gates. Migration adds any gate missing from this list to the
// running CR.
var standardFeatureGates = []string{
	"HostDisk",
	"Snapshot",
	"HostDevices",
	"GPU",
	"VideoConfig",
}

// MigrateKubeVirtFeatureGates patches the running KubeVirt CR's
// featureGates list with the full standard set when the VideoConfig
// sentinel is missing. Idempotent via state.KubevirtFeatureGatesMigrated.
//
// VideoConfig is chosen as the sentinel because it is the newest
// gate; an older EVE release whose CR has the rest of the set will
// still need this migration on upgrade.
func MigrateKubeVirtFeatureGates(ctx context.Context) error {
	migrated, err := state.IsMarked(state.KubevirtFeatureGatesMigrated)
	if err != nil {
		return fmt.Errorf("check feature-gate migration marker: %w", err)
	}
	if migrated {
		return nil
	}

	obj, err := kubeclient.Default().Dynamic.Resource(kubectlx.KubeVirtGVR).
		Namespace(kubectlx.KubeVirtNamespace).Get(ctx, "kubevirt", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("query kubevirt feature gates: %w", err)
	}
	// spec.configuration.developerConfiguration.featureGates: []string
	spec, _ := obj.Object["spec"].(map[string]any)
	config, _ := spec["configuration"].(map[string]any)
	dev, _ := config["developerConfiguration"].(map[string]any)
	rawGates, _ := dev["featureGates"].([]any)
	for _, rg := range rawGates {
		if g, _ := rg.(string); g == "VideoConfig" {
			log.Printf("KubeVirt feature gates already up to date, skipping migration")
			if err := state.Mark(state.KubevirtFeatureGatesMigrated); err != nil {
				return fmt.Errorf("mark feature-gate migrated: %w", err)
			}
			return nil
		}
	}

	log.Printf("KubeVirt VideoConfig feature gate missing, patching CR")
	patch := buildFeatureGatesPatch(standardFeatureGates)
	if _, err := kubeclient.Default().Dynamic.Resource(kubectlx.KubeVirtGVR).
		Namespace(kubectlx.KubeVirtNamespace).Patch(ctx, "kubevirt",
		types.MergePatchType, []byte(patch), metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patch kubevirt feature gates: %w", err)
	}
	log.Printf("KubeVirt feature gates migrated")
	if err := state.Mark(state.KubevirtFeatureGatesMigrated); err != nil {
		return fmt.Errorf("mark feature-gate migrated: %w", err)
	}
	return nil
}

// buildFeatureGatesPatch produces the merge-patch JSON for the
// KubeVirt CR's developerConfiguration.featureGates field. A nil
// or empty gates list still emits an empty array (never null) so
// the merge patch clears the field instead of leaving it untouched.
func buildFeatureGatesPatch(gates []string) string {
	if gates == nil {
		gates = []string{}
	}
	patch, _ := json.Marshal(map[string]any{
		"spec": map[string]any{
			"configuration": map[string]any{
				"developerConfiguration": map[string]any{
					"featureGates": gates,
				},
			},
		},
	})
	return string(patch)
}
