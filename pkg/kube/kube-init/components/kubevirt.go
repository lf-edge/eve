// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
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

	out, err := kubectl("get", "kubevirt", "kubevirt", "-n", kubevirtNamespace,
		"-o", "jsonpath={.spec.configuration.developerConfiguration.featureGates[*]}")
	if err != nil {
		return fmt.Errorf("query kubevirt feature gates: %w", err)
	}
	for _, g := range strings.Fields(strings.TrimSpace(out)) {
		if g == "VideoConfig" {
			log.Printf("KubeVirt feature gates already up to date, skipping migration")
			if err := state.Mark(state.KubevirtFeatureGatesMigrated); err != nil {
				return fmt.Errorf("mark feature-gate migrated: %w", err)
			}
			return nil
		}
	}

	log.Printf("KubeVirt VideoConfig feature gate missing, patching CR")
	patch := buildFeatureGatesPatch(standardFeatureGates)
	if _, err := kubectl("patch", "kubevirt", "kubevirt", "-n", kubevirtNamespace,
		"--type=merge", "-p="+patch); err != nil {
		return fmt.Errorf("patch kubevirt feature gates: %w", err)
	}
	log.Printf("KubeVirt feature gates migrated")
	if err := state.Mark(state.KubevirtFeatureGatesMigrated); err != nil {
		return fmt.Errorf("mark feature-gate migrated: %w", err)
	}
	return nil
}

// buildFeatureGatesPatch produces the merge-patch JSON for the
// KubeVirt CR's developerConfiguration.featureGates field.
func buildFeatureGatesPatch(gates []string) string {
	quoted := make([]string, len(gates))
	for i, g := range gates {
		quoted[i] = `"` + g + `"`
	}
	return `{"spec":{"configuration":{"developerConfiguration":{"featureGates":[` +
		strings.Join(quoted, ",") + `]}}}}`
}
