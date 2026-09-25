// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package basemode_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
)

// TestBaseModeClusterSetup forms the base-mode EVE-K cluster the rest of
// TestBaseModeClusterSuite builds on, and verifies that the controller's
// registration manifest reaches Kubernetes.
//
// "Base mode" is CLUSTER_TYPE_REPLICATED_STORAGE plus
// EnableNativeK8SOrchestration: EVE serves EVE-API-scheduled and
// natively-applied workloads side by side. It is the opt-in that replaced
// CLUSTER_TYPE_K3S_BASE, and it changes when a registration manifest applies --
// on a legacy K3s-base cluster it waits for the replicated-storage uninstall,
// here it applies as soon as zedkube writes it (RegistrationApplyIfReady in
// pkg/kube/kube-init/components/registration.go).
//
// Network model
// -------------
//   - netmodels.SeparateClusterPortNodes(4) -- eight ports, two per device.
//     eth0 on a shared mgmt+app bridge with DHCP and controller access, eth1
//     on a cluster-only bridge (10.244.244.0/24, no Internet) for k3s traffic.
//
// Device configuration
// --------------------
//   - Four devices from baseModeRequirements: Kubevirt, ext4 by default
//     (FILESYSTEM), 4 vCPUs and 8 GiB each.
//   - A three-node cluster over the first three. The fourth is left out of the
//     cluster config and given a standalone one instead -- same networks and
//     adapters under the same UUIDs, no EdgeNodeCluster block -- so it runs a
//     single-node EVE-K until TestBaseModeAddNode admits it.
//   - It must be declared here regardless, since evetest cannot add a device
//     to a running environment (see baseModeDevices). Configuring it is a
//     choice: with no config kube-init blocks in WaitDeviceName and never
//     starts K3s, so joining later would skip the single-to-cluster conversion
//     the next test exists to cover.
//   - SystemAdapter on eth0 (DHCP, mgmt+app, V4Only) and eth1 (no IP, Shared);
//     the cluster interface is addressed from the cluster config.
//
// Test parameters
// ---------------
//   - TPM (bool) via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// Phases
// ------
//  1. cluster-config-applied: push the cluster config, with the
//     native-orchestration flag and the registration manifest, to the three
//     members in parallel.
//  2. nodes-are-ready: WaitUntilNodesAreReady, 30-min budget.
//  3. three-nodes-ready: Kubernetes and the EVE API both report exactly the
//     three members Ready -- no more, so the fourth device is known not to
//     have joined.
//  4. registration-manifest-applied: the manifest's ConfigMap exists, and k3s
//     recorded the staged file as the persist-registration AddOn.
//  5. spare-node-standalone: the fourth device reports itself a healthy
//     single-node cluster under a cluster UUID of its own -- so it is known
//     not to have joined, and the next test starts from a known state.
//
// Suite placement
// ---------------
//   - First in TestBaseModeClusterSuite. Every later test reuses the cluster
//     this one leaves running, via baseModeCluster.
func TestBaseModeClusterSetup(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)

	// ResetDeviceConfig, not a from-scratch policy: as the first test the
	// devices are built fresh anyway, and the cluster the later tests inherit
	// must survive between them.
	evetest.Setup(baseModeRequirements(evetest.ResetDeviceConfig)...)
	evetest.Checkpoint("setup-done")

	log := evetest.Logger()

	// Build the cluster over the first baseModeInitialNodes devices.
	members := make([]string, 0, baseModeInitialNodes)
	nodes := make([]evetest.ClusterNode, 0, baseModeInitialNodes)
	for i := 0; i < baseModeInitialNodes; i++ {
		nodes = append(nodes, baseModeClusterNode(i))
		members = append(members, baseModeDevName(i))
	}
	clusterConfig := evetest.NewEdgeClusterConfig(
		eveconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE, nodes...)
	clusterConfig.SetNativeK8SOrchestration(true)
	clusterConfig.SetRegistrationManifest([]byte(baseModeRegistrationManifest))

	// Configure networks and adapters (applied to all cluster members).
	dhcpNet := clusterConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	noIPNet := clusterConfig.AddNetwork(evetest.NoIPNetworkConfig{})
	clusterConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  mgmtInterface,
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	clusterConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  clusterInterface,
			PhysicalLabel: "eth1",
			InterfaceName: "eth1",
			NetworkUUID:   noIPNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		})

	cluster := evetest.NewEdgeCluster("base-mode-cluster")
	cluster.ApplyConfig(clusterConfig, true, true)
	log.Infof("Submitted base-mode cluster config (ID=%s) to nodes %v",
		clusterConfig.ClusterID, members)
	evetest.Checkpoint("cluster-config-applied")

	// Phase 2. K3s forms across the three nodes over the cluster network.
	cluster.WaitUntilNodesAreReady(30 * time.Minute)
	evetest.Checkpoint("nodes-are-ready")

	// Phase 3. Exactly three nodes, no more: a spare that joined by mistake
	// shows up here, which WaitUntilNodesAreReady alone would not catch --
	// it only checks that the named nodes are ready.
	bootstrap := evetest.GetEdgeDevice(members[0])
	expectReadyKubeNodes(t, bootstrap, members, 10*time.Minute)
	expectClusterInfoNodes(t, members, clusterConfig.ClusterID.String(),
		members, 10*time.Minute)
	evetest.Checkpoint("three-nodes-ready")

	// Phase 4. Only the bootstrap node writes the manifest out (zedkube's
	// publishKubeConfigStatus gates on BootstrapNode), so the staged AddOn is
	// recorded there. The ConfigMap it creates is visible from any node.
	log.Infof("Waiting for the registration manifest to be applied by k3s...")
	expectRegistrationApplied(t, bootstrap, 10*time.Minute)
	evetest.Checkpoint("registration-manifest-applied")

	// Phase 5. Configure the spare devices as standalone nodes, after the
	// cluster is up: a first EVE-K bring-up is heavy (Longhorn, CDI and
	// KubeVirt images at once) and should not compete with cluster formation.
	//
	// Cloned from a member so the two cannot drift -- joining with different
	// network UUIDs would have EVE rebuild its networks mid-join.
	for i := baseModeInitialNodes; i < baseModeDevices; i++ {
		spareName := baseModeDevName(i)
		spareConfig := clusterConfig.GetDeviceConfig(members[0]).Clone()
		spareConfig.DeviceName = spareName
		// A nil cluster block is what keeps the spare out: zedagent reads it
		// as "no cluster for this node", and the join token goes with it.
		spareConfig.Cluster = nil
		spareConfig.CipherContexts = nil // per device; ApplyConfig republishes
		log.Infof("Configuring %q as a standalone node, outside the cluster",
			spareName)
		spareDev := evetest.GetEdgeDevice(spareName)
		spareDev.ApplyConfig(spareConfig, true, true)
		spareDev.WaitForClusterNodeIsReady(30 * time.Minute)

		// Prove the masking rather than assume it: a spare that had silently
		// joined would still report Ready above, and the next test would then
		// be admitting a node that was already a member.
		spareInfo := spareDev.GetClusterInfo()
		t.Expect(readyClusterInfoNodes(spareInfo)).To(ConsistOf(spareName),
			"%s should be a cluster of its own, not a member of %v",
			spareName, members)
		t.Expect(spareInfo.GetClusterId()).NotTo(Equal(clusterConfig.ClusterID.String()),
			"%s should not report the cluster it was left out of", spareName)
	}
	evetest.Checkpoint("spare-node-standalone")

	// Hand the running cluster to the tests that follow in the suite.
	baseModeCluster = &baseModeClusterState{
		config:  clusterConfig,
		cluster: cluster,
		members: members,
	}
}
