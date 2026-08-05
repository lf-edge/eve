// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// nodeNamesReported returns the names of all nodes the given cluster info
// reports, regardless of their conditions.
func nodeNamesReported(info *eveinfo.ZInfoKubeCluster) []string {
	var names []string
	for _, node := range info.GetNodes() {
		names = append(names, node.GetName())
	}
	return names
}

// soleNodeReady reports whether info describes exactly one node, named
// devName, in Ready state — i.e. a standalone K3s rather than a cluster
// member.
func soleNodeReady(info *eveinfo.ZInfoKubeCluster, devName string) bool {
	const nodeReadyCond = eveinfo.KubeNodeConditionType_KUBE_NODE_CONDITION_TYPE_READY
	nodes := info.GetNodes()
	if len(nodes) != 1 || nodes[0].GetName() != devName {
		return false
	}
	for _, cond := range nodes[0].GetConditions() {
		if cond.GetType() == nodeReadyCond && cond.GetSet() {
			return true
		}
	}
	return false
}

// TestClusterToSingleConversion verifies that a node which has joined an
// HA cluster can be converted back to a standalone K3s node by the
// controller withdrawing its cluster configuration, and that it comes
// back healthy on its own.
//
// This is the rollback path behind the /var/lib snapshot. Each node takes
// that snapshot during its own first (standalone) boot, before any
// cluster config arrives. Joining the cluster then overwrites /var/lib
// with cluster-mode state — different certs, a different node identity,
// and a different datastore. Converting back is therefore not a
// reconfiguration but a restore: kube-init marks ConvertToSingleNode,
// reboots, and puts the pre-cluster tree back. Without a usable snapshot
// the node boots K3s against cluster-mode state and crash-loops in
// BACKOFF, which is exactly what this test is here to catch.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort -- same as TestThreeNodesCluster, so
//     the suite can reuse the three VMs instead of recreating them: eth0
//     on a shared management+app bridge with DHCP, eth1 on a cluster-only
//     bridge (10.244.244.0/24).
//
// Device configuration
// --------------------
//   - Three RequireEdgeDevice entries from clusterDeviceRequirements,
//     identical to TestThreeNodesCluster (Kubevirt, fresh image, 4 vCPUs,
//     vcpu-cap grub options, filesystem per FILESYSTEM).
//   - A REPLICATED_STORAGE ClusterConfig over all three nodes, node 1 the
//     bootstrap node, then the conversion is driven by clearing the
//     Cluster field of one device's config.
//
// Test parameters
// ---------------
//   - TPM via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// Phases
// ------
//  1. cluster-formed: all three nodes report Ready (30-min budget), so we
//     know each node took its standalone snapshot and then joined.
//  2. cluster-config-withdrawn: the last node's EdgeNodeCluster config is
//     cleared and the config re-applied. Only that node is converted, so
//     the remaining two stay a cluster and the test also covers the
//     "cluster survives a member leaving" side.
//  3. converted-node-standalone: the converted node reports exactly one
//     Ready node — itself. Reaching this state requires the restore to
//     have produced a bootable pre-cluster /var/lib; a bad snapshot
//     surfaces here as a timeout with K3s crash-looping.
//  4. remaining-cluster-healthy: the two surviving nodes still report each
//     other Ready, confirming the conversion did not take the cluster
//     down with it.
//
// Suite placement
// ---------------
//   - TestNodeClusterSuite, after TestThreeNodesCluster: same device and
//     network requirements, so the framework reuses the VMs.
func TestClusterToSingleConversion(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)

	// Get parameter values set for this test execution.
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	// Set up the test harness and specify the test prerequisites.
	var requiredDevices [3]evetest.Requirement
	var devName [3]string
	for i := 0; i < 3; i++ {
		devName[i] = fmt.Sprintf("edge-dev%d", i+1)
		requiredDevices[i] = clusterDeviceRequirements(devName[i], withTPM, filesystem)
	}
	requirements := append([]evetest.Requirement{},
		requiredDevices[:]...)
	requirements = append(requirements, evetest.RequireNetworkModel{
		NetworkModel: netmodels.SeparateClusterPort,
	})
	evetest.Setup(requirements...)
	evetest.Checkpoint("setup-done")

	log := evetest.Logger()

	// Build the cluster configuration: same shape as TestThreeNodesCluster.
	var nodes [3]evetest.ClusterNode
	for i := 0; i < 3; i++ {
		clusterIP := evetest.IPAddressWithPrefix(fmt.Sprintf("10.244.244.%d/24", i+2))
		nodes[i] = evetest.ClusterNode{
			DevName:          devName[i],
			ClusterIP:        clusterIP,
			ClusterInterface: "ethernet1",
			BootstrapNode:    i == 0,
		}
	}
	clusterConfig := evetest.NewEdgeClusterConfig(
		eveconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE,
		nodes[:]...,
	)

	dhcpNet := clusterConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	noIPNet := clusterConfig.AddNetwork(evetest.NoIPNetworkConfig{})
	clusterConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	clusterConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet1",
			PhysicalLabel: "eth1",
			InterfaceName: "eth1",
			NetworkUUID:   noIPNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		})

	cluster := evetest.NewEdgeCluster("test-cluster")
	cluster.ApplyConfig(clusterConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	// Phase 1. Every node must join before there is anything to roll back:
	// the cluster-mode state that the conversion undoes is only written
	// once the node is actually a member.
	cluster.WaitUntilNodesAreReady(30 * time.Minute)
	evetest.Checkpoint("cluster-formed")

	// Phase 2. Convert the last node back to standalone by withdrawing its
	// cluster configuration. kube-init sees EdgeNodeClusterConfig
	// disappear, marks ConvertToSingleNode and reboots; the next boot
	// restores the pre-cluster /var/lib.
	convertedName := devName[2]
	convertedDev := evetest.GetEdgeDevice(convertedName)
	remainingNames := []string{devName[0], devName[1]}

	convertedCfg := clusterConfig.GetDeviceConfig(convertedName)
	convertedCfg.Cluster = nil
	log.Infof("Withdrawing cluster config from %q to convert it back to "+
		"a single node", convertedName)

	convertedUpdates, stopConvertedWatch := convertedDev.WatchClusterInfo()
	defer stopConvertedWatch()

	// The conversion is carried out by rebooting: kube-init marks
	// ConvertToSingleNode and restarts, because the pre-cluster /var/lib
	// has to be put back before k3s starts, which cannot be done under a
	// running k3s. That reboot is required behaviour, not a crash, so
	// declare it — Close audits observed reboots against expected ones and
	// would otherwise report the conversion working as a failure.
	convertedDev.ExpectReboots(1)

	// Applied per-device: the other two keep their cluster config, so the
	// controller is removing one member rather than dissolving the cluster.
	convertedDev.ApplyConfig(convertedCfg, true, true)
	evetest.Checkpoint("cluster-config-withdrawn")

	// Phase 3. The conversion reboots the node, so the budget has to cover
	// a full EVE boot plus the K3s bring-up that follows the restore.
	conversionTimeout := 20 * time.Minute
	log.Infof("Waiting for %q to come back as a standalone node...", convertedName)
	t.Eventually(convertedUpdates, conversionTimeout).Should(Receive(
		matchers.SatisfyPredicate(
			fmt.Sprintf("Device %q reports itself as the only ready node",
				convertedName),
			func(info *eveinfo.ZInfoKubeCluster) bool {
				if soleNodeReady(info, convertedName) {
					return true
				}
				log.Debugf("%q still reports nodes %v",
					convertedName, nodeNamesReported(info))
				return false
			})))
	evetest.Checkpoint("converted-node-standalone")

	// Phase 4. Removing a member must not disturb the survivors. Checked
	// after the conversion so a cluster broken by the departure is
	// attributed to the conversion rather than to cluster formation.
	log.Infof("Verifying the remaining nodes %v still form a cluster",
		remainingNames)
	remainingTimeout := 10 * time.Minute

	// Cluster-wide info is published by one node only — whichever holds
	// the eve-kube-stats-leader lease — and the others actively unpublish
	// it (zedkube/kubestatscollect.go). So this cannot be asserted per
	// device: a non-leader survivor never reports a node list at all, and
	// waiting for one from it can only ever time out. Ask the survivors
	// collectively and assert on whichever is reporting.
	//
	// Polled rather than awaited as a fresh message, too. Info reaches
	// the controller only when its content changes, which is correct —
	// pubsub deduplicates identical publications — so the removal is
	// reported once, while the converted node is still rebooting, and
	// then the survivors fall silent because nothing more is changing. A
	// watch opened at this point waits for a message that is never sent.
	//
	// The old form passed only by accident: a departed node left behind
	// as NotReady keeps churning heartbeats, so messages kept flowing
	// exactly while the bug was present, and stopped once it was fixed.
	t.Eventually(func() bool {
		for _, name := range remainingNames {
			info := evetest.GetEdgeDevice(name).GetClusterInfo()
			if info == nil {
				continue // not the stats leader
			}
			reported := nodeNamesReported(info)
			if slices.Contains(reported, convertedName) {
				log.Debugf("%q still reports nodes %v", name, reported)
				return false
			}
			// The leader must still see every survivor, or the departure
			// broke the cluster it was supposed to leave intact.
			for _, want := range remainingNames {
				if !slices.Contains(reported, want) {
					log.Debugf("%q reports %v, missing survivor %q",
						name, reported, want)
					return false
				}
			}
			return true
		}
		log.Debugf("no survivor of %v is reporting cluster info yet",
			remainingNames)
		return false
	}, remainingTimeout, 10*time.Second).Should(BeTrue(),
		"No survivor of %v reports a cluster of exactly %v without %q",
		remainingNames, remainingNames, convertedName)
	evetest.Checkpoint("remaining-cluster-healthy")
}
