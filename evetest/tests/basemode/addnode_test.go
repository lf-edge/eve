// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package basemode_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// TestBaseModeAddNode admits a fourth node into the running base-mode cluster
// and verifies that Kubernetes and the EVE API agree it joined.
//
// This is the single-to-cluster conversion on a node that has had time to
// settle: the setup test leaves the fourth device running a standalone EVE-K,
// so joining means kube-init stopping that K3s, dropping its server PKI and
// bringing the node back as a member (the step runner in
// pkg/kube/kube-init/clustermode/transition.go). Nodes that join seconds after
// boot, as in the setup test, never exercise that.
//
// Both vantage points are checked because they come from different code on
// possibly different nodes: only the elected kube-stats leader publishes
// cluster info, so a node can be a healthy member the controller never learns
// about.
//
// Network model
// -------------
//   - Unchanged from the setup test, and it must be: devices are reused only
//     when the network model and device set match the previous test exactly.
//
// Device configuration
// --------------------
//   - baseModeRequirements with UseAsIs. Any other policy breaks the cluster:
//     ResetDeviceConfig strips every cipher block from the retained config,
//     the join token included (clearCipherBlocks in evetest/cipherdata.go),
//     and the reboot policies restart nodes for no reason.
//   - AddNode gives the fourth device its own cluster IP (10.244.244.5) and
//     encrypted join token. It already has the cluster's networks and
//     adapters from the setup test, so only the cluster block changes -- as
//     when a controller adds an existing device to a cluster.
//
// Test parameters
// ---------------
//   - TPM and FILESYSTEM, which must resolve as in the setup test or the
//     devices are not reused.
//
// Phases
// ------
//  1. fourth-node-config-applied: AddNode, then re-apply to all four devices.
//  2. four-nodes-ready: WaitUntilNodesAreReady over all four, 30-min budget --
//     the joining node has a standalone K3s to tear down first.
//  3. four-nodes-in-kubectl: Kubernetes reports exactly the four as Ready.
//  4. four-nodes-in-cluster-info: ZInfoKubeCluster reports the same four under
//     the cluster UUID the setup test created.
//
// Suite placement
// ---------------
//   - After TestBaseModeClusterSetup, whose cluster it extends. It leaves the
//     four-node cluster running for the tests after it.
func TestBaseModeAddNode(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)

	evetest.Setup(baseModeRequirements(evetest.UseAsIs)...)
	evetest.Checkpoint("setup-done")

	log := evetest.Logger()
	state := requireBaseModeCluster(evetestT)

	// The node to admit is the first device the cluster does not yet hold.
	joiningIdx := len(state.members)
	t.Expect(joiningIdx).To(BeNumerically("<", baseModeDevices),
		"the suite has no spare device left to add to the cluster")
	joiningName := baseModeDevName(joiningIdx)

	log.Infof("Admitting %q into cluster %s (current members: %v)",
		joiningName, state.config.ClusterID, state.members)
	state.config.AddNode(baseModeClusterNode(joiningIdx))
	state.members = append(state.members, joiningName)

	// Applied to every device; the existing members just re-confirm what they
	// already run.
	state.cluster.ApplyConfig(state.config, true, true)
	evetest.Checkpoint("fourth-node-config-applied")

	// Phase 2. The joining node must discard its standalone K3s first, so this
	// is no quicker than the original formation.
	state.cluster.WaitUntilNodesAreReady(30 * time.Minute)
	evetest.Checkpoint("four-nodes-ready")

	// Phase 3. Asked through a node that was already a member, so the answer
	// cannot come from the joining node's leftover standalone K3s.
	expectReadyKubeNodes(t, evetest.GetEdgeDevice(state.members[0]),
		state.members, 15*time.Minute)
	evetest.Checkpoint("four-nodes-in-kubectl")

	// Phase 4. The same four as the controller sees them, under the cluster
	// UUID the setup test created.
	expectClusterInfoNodes(t, state.members, state.config.ClusterID.String(),
		state.members, 10*time.Minute)
	evetest.Checkpoint("four-nodes-in-cluster-info")
}
