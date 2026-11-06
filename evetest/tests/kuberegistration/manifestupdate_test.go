// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kuberegistration_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// TestKubeRegistrationManifestUpdate replaces the registration manifest of the
// running native-K8s cluster and verifies that Kubernetes applies the new one.
//
// This is what a controller does when it moves a cluster to another
// registration endpoint or re-registers it: the cluster config is unchanged
// except for the manifest. The setup test only covers the first delivery, when
// nothing is staged yet; a replacement goes through the same path but finds
// the previous manifest already in the k3s server-manifests dir, and kube-init
// must notice the content changed and re-stage it rather than treat "a copy is
// staged" as "this copy is staged". If it does not, the cluster stays registered with
// the old registration endpoint and the new one shows it Unprovisioned.
//
// Network model / device configuration
// ------------------------------------
//   - Unchanged from the rest of the suite (kubeRegRequirements, UseAsIs).
//   - The saved cluster config with SetRegistrationManifest swapped, which
//     re-encrypts every member's token+manifest block under the same join
//     token, so cluster membership does not change.
//
// Test parameters
// ---------------
//   - TPM and FILESYSTEM, which must resolve as in the earlier tests or the
//     devices are not reused.
//
// Phases
// ------
//  1. updated-manifest-config-applied: the cluster config, carrying a manifest
//     that sets the registration ConfigMap to a new value, is pushed to every
//     member.
//  2. source-manifest-updated: zedkube on the bootstrap node has rewritten
//     /persist/vault/manifests/registration.yaml with the new manifest. Checked
//     separately so a failure in the next phase is known to be kube-init's.
//  3. registration-manifest-reapplied: the ConfigMap carries the new value,
//     which only a re-staged manifest re-applied by k3s can produce.
//
// Suite placement
// ---------------
//   - Last: it replaces the manifest the earlier tests assume is applied.
func TestKubeRegistrationManifestUpdate(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)

	evetest.Setup(kubeRegRequirements(evetest.UseAsIs)...)
	evetest.Checkpoint("setup-done")

	log := evetest.Logger()
	state := requireKubeRegCluster(evetestT)
	// Only the bootstrap node writes and stages the manifest (see the setup
	// test, phase 4).
	bootstrap := evetest.GetEdgeDevice(state.members[0])

	// Start from the setup test's manifest so the new value is known to be a
	// change, not something already applied.
	expectRegistrationApplied(t, bootstrap, registrationValueInitial,
		5*time.Minute)

	updated := kubeRegManifest(registrationValueUpdated)
	log.Infof("Replacing the registration manifest of cluster %s (%s=%q)",
		state.config.ClusterID, registrationConfigMapKey, registrationValueUpdated)
	state.config.SetRegistrationManifest([]byte(updated))
	state.cluster.ApplyConfig(state.config, true, true)
	evetest.Checkpoint("updated-manifest-config-applied")

	// Phase 2. zedkube decrypts the new block and rewrites the source file.
	t.Eventually(func() (string, error) {
		stdout, _, err := bootstrap.RunShellScript(
			"cat "+sourceManifestPath, kubectlTimeout, 0)
		return stdout, err
	}, 5*time.Minute, kubePollInterval).Should(Equal(updated),
		"zedkube should rewrite %s with the updated manifest", sourceManifestPath)
	evetest.Checkpoint("source-manifest-updated")

	// Phase 3. kube-init's health tick (15 s) re-stages it and k3s re-applies
	// the AddOn; the budget covers a slow tick plus k3s's own reconcile.
	log.Infof("Waiting for k3s to re-apply the updated registration manifest...")
	expectRegistrationApplied(t, bootstrap, registrationValueUpdated,
		10*time.Minute)
	evetest.Checkpoint("registration-manifest-reapplied")
}
