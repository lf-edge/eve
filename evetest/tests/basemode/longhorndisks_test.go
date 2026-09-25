// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package basemode_test

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

// TestBaseModeLonghornDisks verifies that every node of the cluster offers
// /persist/vault/volumes to Longhorn as a disk.
//
// That path is EVE's vault, the encrypted store Longhorn is meant to keep
// replicas on. A node whose Longhorn disk is missing or points elsewhere still
// joins and still reports Ready, so nothing earlier in the suite catches it;
// what happens instead is that replicas land on the wrong filesystem, or the
// node holds none, and the cluster quietly loses its redundancy. A late-joining
// node is the interesting case, hence running after TestBaseModeAddNode: it
// runs kube-init's deploy in a different order from the founders.
//
// Longhorn is read through Kubernetes because there is no EVE API for it:
// ZInfoKubeCluster carries one cluster-wide storage health flag, which is
// healthy long before a misconfigured disk would show up in it.
//
// Network model / device configuration
// ------------------------------------
//   - Unchanged from the rest of the suite (baseModeRequirements, UseAsIs);
//     this test only reads, and changing either would cost the cluster.
//
// Test parameters
// ---------------
//   - TPM and FILESYSTEM, which must resolve as in the earlier tests or the
//     devices are not reused.
//
// Phases
// ------
//  1. longhorn-disks-verified: every cluster member has a nodes.longhorn.io
//     object, and each lists /persist/vault/volumes among its disk paths.
//
// Suite placement
// ---------------
//   - Last: it wants the largest cluster the suite builds, including the node
//     added by TestBaseModeAddNode.
func TestBaseModeLonghornDisks(test *testing.T) {
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
	device := evetest.GetEdgeDevice(state.members[0])

	// One wait, not two: Longhorn fills the disk list in as it registers a
	// node, so checking the node set first would race a just-appeared node
	// with an empty spec. The error still distinguishes the two cases.
	log.Infof("Verifying every node of %v offers %s to Longhorn",
		state.members, longhornDiskPath)
	t.Eventually(func() error {
		disks, err := longhornNodeDisks(device)
		if err != nil {
			return err
		}
		registered := make([]string, 0, len(disks))
		for nodeName := range disks {
			registered = append(registered, nodeName)
		}
		if !generics.EqualSets(registered, state.members) {
			return fmt.Errorf(
				"Longhorn knows nodes %v, want exactly the cluster members %v",
				registered, state.members)
		}
		for _, nodeName := range state.members {
			if !generics.ContainsItem(disks[nodeName], longhornDiskPath) {
				return fmt.Errorf(
					"Longhorn node %q has disks %v, none of them %s",
					nodeName, disks[nodeName], longhornDiskPath)
			}
		}
		log.Infof("All %d Longhorn nodes offer %s", len(disks), longhornDiskPath)
		return nil
	}, 15*time.Minute, kubePollInterval).Should(Succeed())
	evetest.Checkpoint("longhorn-disks-verified")
}
