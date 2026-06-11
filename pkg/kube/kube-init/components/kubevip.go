// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"context"
	"fmt"
	"log"
)

// Kube-VIP manifest paths (baked into the kube container image).
const (
	kubevipSA = "/etc/kubevip-sa.yaml"
	kubevipCM = "/etc/kubevip-cm.yaml"
	kubevipDS = "/etc/kubevip-ds.yaml"
)

// KubeVIPApply applies the Kube-VIP service account, configmap, and
// daemonset. Order matters: SA + CM before DS so pod startup finds
// its config.
func KubeVIPApply(ctx context.Context) error {
	log.Printf("applying Kube-VIP resources")
	for _, f := range []string{kubevipSA, kubevipCM, kubevipDS} {
		if err := kubectlApply(ctx, f); err != nil {
			return fmt.Errorf("apply %s: %w", f, err)
		}
	}
	log.Printf("Kube-VIP resources applied")
	return nil
}

// KubeVIPDelete removes Kube-VIP resources in reverse-apply order
// (daemonset first so pods drain before the SA/CM disappear).
// Per-file delete failures are warnings, not errors — uninstall
// proceeds across stale state.
func KubeVIPDelete(ctx context.Context) error {
	log.Printf("deleting Kube-VIP resources")
	for _, f := range []string{kubevipDS, kubevipCM, kubevipSA} {
		if _, err := kubectl("delete", "-f", f); err != nil {
			log.Printf("warning: delete %s: %v", f, err)
		}
	}
	log.Printf("Kube-VIP resources deleted")
	return nil
}
